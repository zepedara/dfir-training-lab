# Research — YARA (Pattern-Matching for Malware Identification)

> **Status in `dfir-aio:v2`:** PRESENT. `yara` on `PATH` (`/usr/bin/yara`). Version **4.2.3** (verified on rick 2026-06-29). `yarac` (rule compiler) is part of the same package. **No rule sets are bundled** — you supply `.yar` files (e.g. clone Neo23x0/signature-base into the mounted `/data`).

---

## 1. What it is and the forensic question it answers

**YARA** (by Victor Alvarez, originally VirusTotal) is "the pattern-matching swiss-army knife for malware researchers." It answers: **"Does this file/process/memory match a known-bad pattern — and *which* one?"** You write **rules** describing strings and byte patterns that characterise a malware family, campaign, or technique, then scan files, directories, or even a **running process / memory image** against them. A match tells you *identity and attribution* in a way capa (capability) and FLOSS (strings) do not.

YARA is everywhere in DFIR: EDR/AV engines, sandboxes, Loki/Thor/Fenrir IOC scanners, `clamav`, Volatility (`yarascan`), and incident-response sweeps.

---

## 2. How it works under the hood (plain language)

A YARA rule is a small text recipe with three parts: **meta**, **strings**, and a **condition**. YARA compiles your strings (text, hex, or regex) into an efficient automaton and scans the target's bytes for them; the **condition** is boolean logic over which strings matched (and optional file/PE properties). If the condition is true, the rule "fires."

The engine is fast because:
- It compiles all rules into one optimised matcher (you can pre-compile with `yarac` to a `.yarc` for repeated sweeps).
- **Modules** (`pe`, `elf`, `math`, `hash`, `dotnet`, `magic`, `cuckoo`) expose structured fields so conditions can reference, e.g., the PE import table, entry point, section entropy, or a section's MD5 — far more precise than raw strings.

### Anatomy of a rule
```yara
import "pe"

rule Emotet_Loader_GenericA
{
    meta:
        author      = "DFIR-Lab"
        date        = "2026-06-29"
        description = "Generic Emotet loader markers"
        reference   = "https://example/report"
        hash        = "a1b2c3..."
        tlp         = "WHITE"

    strings:
        $s1 = "Mozilla/5.0 (compatible; MSIE" ascii
        $s2 = "/wp-content/" wide
        $hex = { 6A 40 68 00 30 00 00 6A 14 8D 91 }   // VirtualAlloc stub
        $re  = /[A-Za-z0-9+\/]{120,}={0,2}/            // long base64 blob

    condition:
        uint16(0) == 0x5A4D                // "MZ" — it's a PE
        and pe.number_of_sections < 6
        and 2 of ($s*)                      // any 2 text strings
        and ($hex or $re)
}
```

**Reading the building blocks:**
- **Strings** have modifiers: `ascii`, `wide` (UTF-16, common in Windows), `nocase`, `fullword`, `xor` (match XOR-encoded copies across a key range, e.g. `$s = "cmd.exe" xor`), `base64` (match base64-encoded forms). `wide ascii` matches both encodings.
- **Hex strings** support wildcards `??`, jumps `[4-6]`, and alternatives `( AA | BB )`.
- **Condition** primitives: `uint16(0)==0x5A4D` (magic bytes), `filesize`, counts (`#s1 > 3`), offsets (`$s1 at 0`, `$s2 in (0..1024)`), quantifiers (`2 of them`, `any of ($s*)`, `all of them`), and module fields (`pe.imphash()`, `pe.entry_point`, `math.entropy(0, filesize) > 7.0`).

> **The `condition` is what separates a good rule from a noisy one.** Anchor with a magic-byte/`filesize` gate, require *combinations* of strings, and prefer `fullword`/specific hex over short common strings.

---

## 3. Installation / availability

```bash
yara --version     # 4.2.3
yara -h
yarac -h           # rule compiler
```
Get rule sets (the container ships **none**, so add your own into the mounted folder):
```bash
git clone https://github.com/Neo23x0/signature-base   # Florian Roth (THOR/Loki) — high quality
git clone https://github.com/Yara-Rules/rules         # large community set (noisier)
```

---

## 4. The most useful commands + flags

### Scan a file or directory
```bash
yara rules.yar suspicious.exe              # single rule file, single target
yara -r rules.yar /evidence/extracted/     # -r = recurse into the directory tree
```

### Key flags
| Flag | Purpose |
|---|---|
| `-r` | **recursive** directory scan. |
| `-s` | print the **matched strings** and their **offsets** (essential to see *why* it matched). |
| `-m` | print the rule's **meta** (author/description/reference) with each hit. |
| `-g` | print the rule's **tags**. |
| `-w` | suppress **warnings** (slow-rule/deprecated noise). |
| `-f` | **fast** matching mode. |
| `-c` | print only the **count** of matches per rule. |
| `-d NAME=VALUE` | define an **external variable** a rule references (e.g. `-d filename="x.exe"`). |
| `-p N` | use **N threads**. |
| `-x MODULE=FILE` | feed a module's data (e.g. a cuckoo report). |
| `-a SECONDS` | **timeout** (abort on a pathological file). |
| `-n` | print rules that **did *not*** match (negation). |
| `-e` | print namespace with the rule name. |
| `--scan-list` | treat the target arg as a **file listing** of paths to scan. |

### Compile once, scan many (fast sweeps)
```bash
yarac rules/*.yar compiled.yarc            # compile all rules to one binary
yara -r -s -m -C compiled.yarc /evidence/  # -C = load a compiled ruleset
```

### Scan a live process (Linux/Windows) by PID
```bash
yara -s rules.yar 1337                      # last arg is a PID → scans that process's memory
```

### Realistic invocations
```bash
# Sweep an extraction folder with Florian Roth's set, show evidence + meta
yara -r -s -m signature-base/yara/*.yar /evidence/files/ | tee yara_hits.txt

# Hunt one family across a triage tree, count only
yara -r -c family_x.yar /triage/

# Validate a rule you just wrote
yara -s my_new_rule.yar known_sample.bin    # should fire; then test on clean files for FPs
```

---

## 5. Reading the output

Default output is one line per hit: `RuleName  /path/to/file`. With `-s` you also get, per matched string:
```
0x4a2:$s1: Mozilla/5.0 (compatible; MSIE
0x118c:$hex: 6A 40 68 00 30 00 00 ...
```
The **offset** + **string identifier** is your proof and your pivot into a hex editor/disassembler. With `-m` you get the `reference`/`description` so you know what the rule *claims* and can chase the report. **Multiple different rules firing on one file strengthens attribution; a single short-string rule on its own warrants scepticism (possible FP).**

---

## 6. Writing good rules + Volatility integration

- **Build rules from FLOSS output:** unique decoded strings/mutexes recovered by FLOSS make excellent, specific YARA strings.
- **Use `pe.imphash()`** to catch recompiled variants that share an import table.
- **Memory scanning:** Volatility 3's `windows.vadyarascan`/`yarascan` plugins run YARA rules **across a memory image**, finding matches inside injected/unpacked regions that never touch disk — combine with the YARA module here.
- **Test for false positives** against a clean goodware corpus before deploying a rule to a sweep.

---

## 7. Common pitfalls

- **Short/common strings = false-positive storms.** Require combinations and gate with magic bytes/`filesize`.
- **`ascii` vs `wide`:** Windows strings are frequently UTF-16; forgetting `wide` silently misses them. Use `wide ascii` when unsure.
- **Rule-set quality varies.** Yara-Rules/rules is broad but noisy; Neo23x0/signature-base is curated and FP-tested — prefer it for clean results.
- **Version/module mismatches:** a rule using a newer module field won't compile on an older YARA. The container is 4.2.3 — check rule headers' minimum version.
- **Performance:** huge regex or unanchored short hex slow scans dramatically; `-a` timeout and `yarac` pre-compilation help.
- **A match is a lead, not a verdict** — confirm with hashing, capa, and context.

---

## 8. Where it fits a DFIR investigation

YARA is the **identity/attribution and hunting** layer. After Volatility dumps a payload and capa/FLOSS characterise it, YARA tells you **which known family/campaign** it is and lets you **sweep the entire environment** (disk extractions, triage collections, live memory) for the same indicators. It's the connective tissue between single-sample analysis and enterprise-wide hunting, and the format most threat-intel IOCs ship in.

---

## 9. Sources
- YARA official docs — https://yara.readthedocs.io/ (rule syntax, modules, command-line reference).
- YARA repo — https://github.com/VirusTotal/yara (releases, `yarac`).
- Neo23x0 / signature-base — https://github.com/Neo23x0/signature-base (Florian Roth; THOR/Loki rules, the gold-standard curated set).
- Yara-Rules project — https://github.com/Yara-Rules/rules (large community ruleset).
- "How to write simple but sound YARA rules" — Florian Roth (Nextron) blog series (rule-quality methodology).
- Volatility 3 `yarascan`/`vadyarascan` plugin docs (memory scanning).
