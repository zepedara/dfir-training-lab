# Research — FLOSS (FLARE Obfuscated String Solver)

> **Status in `dfir-aio:v2`:** PRESENT. `floss` on `PATH` (`/opt/tools/bin/floss`). Version **3.1.1** (verified on rick 2026-06-29). Works fully offline.

---

## 1. What it is and the forensic question it answers

**FLOSS** (by Mandiant/Google FLARE) is "`strings` on steroids." The classic `strings` utility only finds **plaintext** ASCII/UTF-16 text in a file. Malware authors know that, so they **hide** their meaningful strings — C2 domains, file paths, registry keys, mutex names, ransom notes, decryption keys — by **encoding or building them at runtime**. FLOSS answers: **"What strings does this malware actually use, including the ones it hides?"**

It recovers four kinds of strings:
1. **Static strings** — the same ASCII/UTF-16 that `strings` finds (so FLOSS is a drop-in replacement).
2. **Stack strings** — strings the program **builds one character at a time onto the stack** at runtime (a common, cheap obfuscation; invisible to `strings`).
3. **Tight strings** — a variant built/decoded inside a tight loop and only briefly present in memory.
4. **Decoded strings** — strings produced by the malware's **own decoding routine** (XOR/RC4/base64/custom). FLOSS finds the decoder, **emulates** it, and captures what it would have produced.

---

## 2. How it works under the hood (plain language)

FLOSS combines static analysis with **lightweight CPU emulation**:

1. It disassembles the PE with **vivisect** and finds all functions.
2. For **static/stack/tight** strings it analyses instructions that move bytes onto the stack and reconstructs the resulting text.
3. For **decoded** strings it uses a heuristic to identify likely **decoding functions** (small functions that take a buffer and transform it — lots of XOR/arithmetic, called from many places). It then **emulates** those functions with an embedded x86/x64 emulator (vivisect/`viv-utils`), feeding them the program's data, and records the **output buffers** — i.e. the plaintext the malware would have decoded at runtime, **without ever executing the malware on the real CPU**.

This is why FLOSS is powerful *and* safe: emulation happens in a sandboxed userland CPU model, so you extract the secrets **without detonating** the sample. It also means FLOSS is **slower** than `strings` (it's doing real analysis and emulation) and is **PE-focused** (it shines on Windows malware).

---

## 3. Installation / availability

```bash
floss --version       # 3.1.1 in the container
floss -h
```
Outside the container: `pipx install flare-floss` (PyPI package **`flare-floss`**; command `floss`). Standalone binaries are on the GitHub releases page.

---

## 4. The most useful commands + flags

### Default scan (all string types)
```bash
floss suspicious.exe
```
Output is grouped into sections: **static strings**, **stack strings**, **tight strings**, **decoded strings**.

### Key flags
| Flag | Purpose |
|---|---|
| `--only static` / `--only stacked` / `--only tight` / `--only decoded` | run only selected analyses. `--only static` makes FLOSS behave like fast `strings`; `--only decoded` skips the cheap stuff when you just want the emulated secrets. |
| `-n N` / `--minimum-length N` | minimum string length (default 4). Raise it to cut noise. |
| `-j` / `--json` | JSON output for pipelines. |
| `-f {auto,pe,sc32,sc64}` / `--format` | force format; **`sc32`/`sc64` for raw shellcode** with no PE header. |
| `-l {default,verbose,…}` / `-q` | verbosity / quiet. |
| `--no static` (and friends) | disable a specific analysis you don't want. |
| `--functions 0x401000 …` | restrict decoded-string emulation to specific functions (speed). |
| `-L` / language packs | (string filtering / language hints depending on version). |

> Flag names have shifted slightly across major versions (FLOSS 2.x → 3.x). Always confirm with `floss -h` in the actual build; the container is 3.1.1.

### Realistic invocations
```bash
# Full run, save everything
floss suspicious.exe | tee floss_full.txt

# Just the high-value hidden strings (skip the plaintext noise)
floss --only stacked --only tight --only decoded suspicious.exe

# JSON → pull just the decoded strings for IOC extraction
floss -j suspicious.exe > floss.json
jq -r '.strings.decoded_strings[].string' floss.json

# Shellcode blob carved from a Volatility malfind dump
floss -f sc64 injected_region.bin
```

---

## 5. Reading the output + getting IOCs

- The **decoded strings** and **stack strings** sections are where the gold is: C2 URLs/domains, IPs, user-agents, mutex names, registry persistence paths, sandbox/AV evasion checks, ransom-note text, and sometimes hardcoded keys/passwords.
- Each decoded string is annotated with the **address of the decoding function** that produced it and the **call site** — that's your jump-off point for confirming behaviour in a disassembler.
- Pipe the output through IOC extraction: grep for `http(s)://`, IP-like patterns, `\\HKLM`, `.onion`, file extensions, etc.

```bash
floss suspicious.exe | grep -EioZ -e 'https?://[^ ]+' -e '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
```

---

## 6. Common pitfalls

- **Slow on big/packed files** because of emulation. If a sample is **packed**, unpack first — FLOSS will mostly emulate the unpacker. (Same caveat as capa.)
- **PE/Windows-centric.** For ELF or odd formats, results are limited; for raw memory blobs use `-f sc32/sc64`.
- **Not every "decoded string" is meaningful** — emulation can surface internal/garbage buffers. Sort by relevance (looks-like-an-IOC) rather than trusting all of them.
- **It is analysis, not detonation** — but still handle malware on an isolated, offline host (the lab container with `--network none`).
- **Version drift in flags** (2.x vs 3.x): always `floss -h`.

---

## 7. Where it fits a DFIR investigation

FLOSS is step two of unknown-binary triage, right after capa: **capa = what it can do, FLOSS = the concrete IOCs it hides.** Run it on any recovered/dumped binary to harvest C2 indicators that you then sweep across the environment (proxy/DNS logs, EDR, the EVTX modules in this lab). It pairs especially well with **Volatility** (`malfind`/`--dump` a region, then FLOSS it) and **YARA** (FLOSS-recovered unique strings become new YARA rules). Its output directly feeds detection engineering and threat-intel enrichment.

---

## 8. Sources
- FLOSS official repo + docs — https://github.com/mandiant/flare-floss (README, design docs explaining stack/tight/decoded string extraction, `floss -h`).
- Mandiant/FLARE blog — "Automatically Extracting Obfuscated Strings from Malware using FLOSS" (the emulation methodology).
- vivisect / viv-utils — https://github.com/vivisect/vivisect (the emulator FLOSS builds on).
- PyPI `flare-floss` — packaging/versioning.
