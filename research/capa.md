# Research — capa (Capability Detection in Executables)

> **Status in `dfir-aio:v2`:** PRESENT. `capa` on `PATH` (`/opt/tools/bin/capa`). Version **9.4.0** (verified on rick 2026-06-29). Embedded rules + signatures ship with the package, so it works **offline**.

---

## 1. What it is and the forensic question it answers

**capa** (by Mandiant/Google, FLARE team) answers: **"What can this program *do*?"** — without you reverse-engineering it by hand. You point capa at an unknown executable and it reports **capabilities** in human terms: *"communicate over HTTP", "encrypt data using RC4", "inject code into another process", "persist via Run key", "check for a debugger", "create a process"* — and maps each to **MITRE ATT&CK** and the **Malware Behavior Catalog (MBC)**.

It bridges the gap between "I have a suspicious binary" and "I know what it's built to do," in seconds, before deep RE. Where YARA tells you *who* a sample is (signature/family) and FLOSS tells you *what strings* it hides, **capa tells you what it is capable of doing.**

---

## 2. How it works under the hood (plain language)

capa is a **rule engine over static program analysis**:

1. It **loads the file** and picks a backend: for PE/ELF it disassembles with **vivisect** (default) or can use **IDA**/**Binary Ninja**/**Ghidra** backends; it can also run over a **dynamic** sandbox report (CAPE) for packed samples.
2. It extracts **features** at four scopes: **file** (strings, imports, exported names, embedded PE), **function**, **basic block**, and **instruction** (specific API calls, numbers/constants, byte sequences, mnemonics, characteristics like "calls an import indirectly").
3. It matches those features against a large, open, community-curated **rule set** (the `capa-rules` repo, bundled in the binary). Each rule is a logical tree (`and`/`or`/`N or more`) of features, scoped appropriately. A rule fires only when its logic is satisfied within the right scope.
4. It prints the matched **capabilities**, grouped by **ATT&CK tactic/technique** and **MBC**, plus a namespace like `host-interaction/process/inject`.

Because it reasons over **code features**, not just strings, it sees through trivial obfuscation that defeats `strings`/grep — e.g. it recognises an inlined RC4 key-scheduling loop even with no telltale string.

**Key limitation to internalise:** capa is primarily **static**. If a sample is **packed/encrypted**, the real code isn't visible until unpacked — capa will mostly report the *packer's* capabilities and warn you. Unpack first (or feed it a CAPE dynamic report, or a memory-dumped image from Volatility's `--dump`).

---

## 3. Installation / availability

```bash
capa --version          # 9.4.0 in the container
capa -h
```
Outside the container: `pipx install flare-capa` (the PyPI package is **`flare-capa`**, the command is `capa`). Standalone single-file binaries are published on the GitHub releases page.

---

## 4. The most useful commands + flags

### Basic scan
```bash
capa suspicious.exe
```
Prints an ATT&CK summary table, an MBC table, and a **capability list** grouped by namespace.

### Key flags
| Flag | Purpose |
|---|---|
| `-v` | **verbose** — show each matched rule and the address where it matched. |
| `-vv` | **very verbose** — also show the **feature-by-feature** evidence under each rule (why it matched). Essential for triage write-ups. |
| `-j` / `--json` | machine-readable JSON (pipe to `jq`, feed pipelines). |
| `-f {auto,pe,elf,dotnet,sc32,sc64,cape,…}` | force the **file format**. Use `-f sc32`/`sc64` for **raw shellcode** (a memory blob has no PE header); `-f cape` to consume a CAPE sandbox report. |
| `-r DIR` | use a custom/updated **rules** directory instead of the embedded set. |
| `-s DIR` | custom **signatures** (library-function FLIRT-style sigs used to ignore statically-linked library code). |
| `-t TAG` / `--tag` | only evaluate rules matching a tag (e.g. an ATT&CK ID) — faster, focused. |
| `--os {windows,linux,…}` | hint the OS for ambiguous inputs. |
| `-b {vivisect,binja,ida,…}` | choose the analysis backend. |
| `-q` | quiet. |

### Realistic invocations
```bash
# Triage write-up evidence: show WHY each capability matched
capa -vv suspicious.exe | less

# JSON for automation / enrichment
capa -j suspicious.exe > capa.json
jq -r '.rules | keys[]' capa.json          # list matched rule names

# Shellcode carved from a memory dump (no PE header)
capa -f sc64 injected_region.bin

# A binary you dumped from RAM with Volatility windows.pslist --dump
capa -vv ./dump/pid.4242.exe
```

---

## 5. Reading the output

Three sections:
1. **ATT&CK / MBC tables** — the high-level "so what": tactics like *Defense Evasion*, *Persistence*, *Command and Control*, each with techniques. This is what goes in the report's executive summary.
2. **CAPABILITY / NAMESPACE table** — the concrete list: e.g.
   - `communicate via HTTP` → `communication/http/client`
   - `encrypt data using RC4 PRGA` → `data-manipulation/encryption/rc4`
   - `inject APC` → `host-interaction/process/inject`
   - `check for debugger via API` → `anti-analysis/anti-debugging`
3. With `-vv`, under each rule, the **exact features and addresses** that triggered it — your proof, and your starting offsets for manual RE.

**Interpretation rules of thumb:**
- A cluster of *anti-debugging + anti-VM + obfuscated strings* = the sample is evasive; expect it to behave differently in a sandbox.
- *Persistence + process-injection + C2* together = classic implant; prioritise.
- **Few/no capabilities + a "this file may be packed" warning** = unpack before believing the result.

---

## 6. Common pitfalls

- **Packed samples mislead.** capa often prints a note that the file appears packed and capabilities are limited. Unpack (manually, via sandbox, or analyse a memory-resident copy) and re-run.
- **.NET / managed code:** use `-f dotnet`; vivisect's native disassembly isn't meant for IL.
- **Shellcode needs `-f sc32`/`sc64`** — without a PE header, auto-detection fails.
- **capa describes capability, not intent or maliciousness.** "Create a process" is also what benign software does. Read the *combination* of capabilities, in context.
- **Rules evolve.** The embedded rules are a snapshot at build time (here, capa 9.4.0). For the newest techniques, point `-r` at a fresh clone of `capa-rules`.
- **Big binaries are slow** (full disassembly). Be patient or scope with `-t`.

---

## 7. Where it fits a DFIR investigation

capa is the **fast first-pass triage** on any unknown binary you recover — from disk, from an email attachment, from a Prefetch-identified path, or **dumped out of memory by Volatility**. Workflow: hash + VT/YARA for *identity* → **capa for *capability*** → FLOSS for *hidden strings/IOCs* → manual RE only if it's worth it. Its ATT&CK mapping drops straight into the incident report and into detection-engineering (turn the observed techniques into Sigma/EDR rules). In this lab it pairs naturally with the YARA and FLOSS modules and with Volatility's `--dump` output.

---

## 8. Sources
- capa official repo + docs — https://github.com/mandiant/capa (README, usage, backends).
- capa rules repo — https://github.com/mandiant/capa-rules (rule format, scopes).
- Mandiant/Google FLARE blog — capa announcement and "capa Explorer" / capabilities-detection posts.
- MITRE ATT&CK — https://attack.mitre.org/ and Malware Behavior Catalog — https://github.com/MBCProject/mbc-markdown (the two taxonomies capa maps to).
- PyPI `flare-capa` — package/versioning.
