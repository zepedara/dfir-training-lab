# Research — Volatility 3 (Memory Forensics)

> **Status in `dfir-aio:v2`:** PRESENT. Invoked as `vol` (also `volatility3`). Package/framework version **2.28.0**. Windows symbol pack (`windows.zip`) is **bundled offline** at `…/volatility3/symbols/`, so Windows analysis works with **no network**. Verified on rick 2026-06-29.

---

## 1. What it is and the forensic question it answers

**Volatility 3** is the open-source framework for **memory forensics** — analysing a snapshot of a computer's RAM (a "memory image" or "memory dump"). It is maintained by the Volatility Foundation and is a complete rewrite of the older Volatility 2 (Python 2). The rewrite dropped the old "profile" system in favour of **symbol tables** and made plugin names fully namespaced (e.g. `windows.pslist.PsList`).

Memory forensics answers the questions that **disk forensics cannot**, because they only ever existed in RAM:

- **What was actually running** at the moment of capture (including processes hidden from Task Manager / hidden from the disk)?
- **What was injected** — code that lives only in memory (fileless malware, process hollowing, reflective DLL injection)?
- **What network connections** were open and to where (C2 beacons)?
- **What command lines** launched each process (attacker tradecraft)?
- **What was decrypted/unpacked** — malware that is encrypted on disk is plaintext in RAM.

The core forensic value: **disk lies, memory tells the truth at capture time.** A rootkit can hide a file on disk and unlink a process from the Task-Manager list, but the kernel objects backing that process are still in RAM and Volatility walks them directly.

### How you get a memory image (context)
Acquisition is a separate step (WinPMEM, DumpIt, Magnet RAM Capture, FTK Imager, or a VMware `.vmem`/`.vmsn`, Hyper-V `.bin`, VirtualBox `.sav`, or a raw `crashdump`/`hiberfil.sys`). Volatility consumes the resulting file. It auto-detects most raw and crash-dump formats.

---

## 2. How it works under the hood (plain language)

A memory dump is just a flat copy of physical RAM — billions of bytes with no labels. To make sense of it Volatility needs two things:

1. **A way to translate virtual addresses to physical addresses.** The OS uses page tables; Volatility finds the kernel's page-table directory (DTB) and reconstructs the same translation, so it can "see" memory the way the OS did.
2. **Symbols** — a map of where every field sits inside every kernel structure (e.g. "in an `_EPROCESS`, the process name is at offset 0x5a8, the PID at 0x440"). These offsets differ for **every Windows build**. Volatility 3 ships these as **Intermediate Symbol Format (ISF)** JSON files (the `windows.zip`/`linux.zip`/`mac.zip` symbol packs). For Windows it can also auto-download the exact PDB from Microsoft's symbol server — **but in our offline container the bundled pack is what matters**; if a brand-new Windows build isn't covered you'd need to add its ISF.

With those two pieces, plugins simply **walk the kernel's own data structures**:
- `pslist` walks the doubly-linked `ActiveProcessLinks` list of `_EPROCESS` objects (the same list Task Manager uses).
- `psscan` does **pool tag scanning** — it carves the entire dump for the memory-pool signature of an `_EPROCESS` (`Proc` tag), so it finds processes even if they've been **unlinked** from the list (rootkit hiding). **Diffing `pslist` vs `psscan` is a classic hidden-process hunt.**

---

## 3. Installation / availability

```bash
vol --help            # in the container
vol --info            # lists every available plugin + detected OS layers/symbols
```

In `dfir-aio:v2` it is already on `PATH` as **`vol`**. Outside the container:
```bash
pipx install volatility3          # or: pip install volatility3
git clone https://github.com/volatilityfoundation/volatility3
```

Symbols live under the package's `symbols/` directory; you can drop extra ISF JSONs (zipped) there. To point at a custom symbol dir use `-s /path/to/symbols`.

---

## 4. Universal flags (apply to every plugin)

| Flag | Meaning |
|---|---|
| `-f FILE` | the memory image to analyse (**required**). |
| `-o DIR` | output directory for dumped files (used by `-D`/dump options). |
| `-r {pretty,csv,json,jsonl}` | **renderer** — output format. `-r csv` is gold for grepping/timelines. |
| `-q` | quiet (suppress progress bars — cleaner for scripting). |
| `-s DIR` | extra **symbol** directory. |
| `-p DIR` | extra **plugin** directory. |
| `--parallelism {processes,threads,off}` | speed vs. determinism. |
| `-v` / `-vvv` | verbose / very verbose (debug a "symbol not found" problem). |
| `-l FILE` | write a log file. |

> **Volatility 3 auto-detects the OS and the correct symbols** — there is **no `--profile`** flag like Vol 2. You just give `-f` and the plugin.

The first run on a large image builds a **cache**; later plugins on the same image are faster.

---

## 5. The most useful Windows plugins (with what each proves)

> Full plugin names are namespaced; you can usually use the short form (`vol -f mem.raw windows.pslist`). Add `.PsList` etc. if there's ambiguity.

### 5.1 `windows.info` — sanity check first, always
```bash
vol -f mem.raw windows.info
```
Confirms the OS build, kernel base, DTB, number of processors, and **system time of the capture**. Run this first: if `windows.info` works, your symbols match the image. The reported time anchors every timeline you build afterwards.

### 5.2 `windows.pslist` — the process list
```bash
vol -f mem.raw windows.pslist
vol -f mem.raw -r csv windows.pslist > pslist.csv
```
Columns: **PID, PPID, ImageFileName, Offset, Threads, Handles, CreateTime, ExitTime**. This is the "Task Manager" view. Look for:
- Processes with **odd parent/child relationships** (e.g. `winword.exe` → `cmd.exe` → `powershell.exe`).
- **Misspelled / masquerading** system names (`svch0st.exe`, `scvhost.exe`, `lsasss.exe`).
- System processes running from the **wrong path** (real `svchost.exe` is always `C:\Windows\System32\`).
- Useful options: `--pid 1234` to focus; `--dump` to write each process's executable image to `-o` dir.

### 5.3 `windows.pstree` — parentage as a tree
```bash
vol -f mem.raw windows.pstree
```
Same data as `pslist` but **indented by parent→child**, so masquerading and suspicious ancestry jump out. Add `--pid` to root the tree at one process. **This is where you spot the Office→shell→LOLBin chain visually.**

### 5.4 `windows.psscan` — find hidden/terminated processes
```bash
vol -f mem.raw windows.psscan
```
Pool-tag scan that finds `_EPROCESS` objects **even if unlinked** or already exited. **Diff against `pslist`:**
```bash
vol -f mem.raw -r csv windows.pslist | cut -d, -f3 | sort -u > seen_list.txt
vol -f mem.raw -r csv windows.psscan | cut -d, -f3 | sort -u > seen_scan.txt
comm -13 seen_list.txt seen_scan.txt     # in scan but NOT in list = candidate hidden process
```

### 5.5 `windows.cmdline` — how each process was launched
```bash
vol -f mem.raw windows.cmdline
```
Pulls the **full command line** from each process's PEB. This is one of the highest-value plugins: it exposes encoded PowerShell (`-enc …`), `rundll32` exports, `regsvr32 /i:http…` (Squiblydoo), download cradles, and the actual path the binary ran from.

### 5.6 `windows.malfind` — injected / hidden code
```bash
vol -f mem.raw windows.malfind
vol -f mem.raw -o ./out windows.malfind --dump      # dump the suspicious regions
```
Scans every process's private memory for regions that are **committed, executable, and not backed by a file on disk**, with `PAGE_EXECUTE_READWRITE` protection — the signature of **code injection / process hollowing / reflective loading**. It prints a hex+disassembly preview; an `MZ` header (`4D 5A`) at the top of an RWX private region is a strong injected-PE indicator. **This is the #1 "is there injected malware?" plugin.** Pitfall: legitimate JIT engines (.NET, Java, browsers) also create RWX regions — corroborate, don't assume.

### 5.7 `windows.netscan` / `windows.netstat` — network artifacts
```bash
vol -f mem.raw windows.netscan
```
Pool-scans for `TCP`/`UDP` endpoint and listener objects: **local/remote IP:port, state, owning PID, process name, and creation time.** This is how you find **C2 connections and beaconing**. `netstat` is the linked-list equivalent (faster, but misses closed/hidden ones); `netscan` carves and finds more. Map any foreign IP back to a PID, then pivot to `cmdline`/`pstree` for that PID.

### 5.8 `windows.dlllist` — loaded modules per process
```bash
vol -f mem.raw windows.dlllist --pid 1234
```
Lists every DLL loaded into a process with its **load path and load time**. Use it to spot **DLL side-loading** (a trusted EXE loading a malicious DLL from an unusual directory) and unsigned/odd modules. Compare the load path against the expected System32 path.

### 5.9 `windows.handles` — what a process has open
```bash
vol -f mem.raw windows.handles --pid 1234
```
Every open **handle**: files, registry keys, mutexes/events, processes, tokens. Malware often creates a uniquely named **mutex** (single-instance marker) — grepping handles for it can fingerprint a family. Reveals files/keys a process touched that are invisible on disk.

### 5.10 Other high-value plugins (round out a case)
| Plugin | Proves |
|---|---|
| `windows.dlllist --pid N --dump` / `windows.pslist --pid N --dump` | extract the actual binary/DLL image from RAM for `capa`/`yara`/hashing. |
| `windows.cmdscan` / `windows.consoles` | recovers **typed console commands and screen buffers** (attacker's actual keystrokes). |
| `windows.malfind` + `windows.vadinfo` | the VAD tree — memory region map of a process. |
| `windows.svcscan` | services (persistence). |
| `windows.registry.hivelist` / `windows.registry.printkey` | read registry **out of memory** (Run keys, etc.). |
| `windows.filescan` + `windows.dumpfiles` | carve cached **files** straight out of RAM. |
| `windows.getsids` / `windows.privileges` | token/SID and privilege abuse. |
| `windows.ldrmodules` | DLL-hiding (compares 3 module lists; a missing entry = unlinked DLL). |

---

## 6. A realistic mini-workflow + reading the output

```bash
# 1. Identify the image
vol -f case.raw windows.info

# 2. Triage processes (save CSVs)
vol -f case.raw -r csv windows.pstree   > pstree.csv
vol -f case.raw -r csv windows.cmdline  > cmdline.csv

# 3. Hunt injection
vol -f case.raw -o ./malfind_out windows.malfind --dump

# 4. Hunt C2
vol -f case.raw -r csv windows.netscan  > net.csv

# 5. For each suspect PID, pull modules + dump the binary
vol -f case.raw windows.dlllist --pid 4242
vol -f case.raw -o ./dump windows.pslist --pid 4242 --dump
# then: capa ./dump/*.exe   and   yara rules.yar ./dump/*.exe
```

**How to read it:** start from `pstree` to find a suspicious ancestry, confirm the launch with `cmdline`, check `malfind` for an RWX/`MZ` region in that PID, confirm a beacon in `netscan` owned by that PID, then **dump the image and run it through capa/FLOSS/YARA** (see the other research docs). Each plugin corroborates the next — never conclude from one.

---

## 7. Common pitfalls

- **"Symbol table not found" / unsupported build.** The image's Windows build has no matching ISF in the bundled pack. Online you'd let Volatility fetch the PDB; **offline you must add the ISF**. Flag the build to the lab maintainers so the symbol can be added to the container.
- **Profiles are gone.** Don't look for `--profile`; Vol 3 auto-detects. Old Vol 2 command lines won't work verbatim.
- **`malfind` false positives** from JIT (.NET/Java/browsers). Corroborate with `cmdline`, `netscan`, and a `yara`/`capa` scan of the dumped region.
- **`pslist` can be fooled** by DKOM unlinking — always cross-check with `psscan`/`ldrmodules`.
- **Hibernation/crash dumps** are valid inputs but `hiberfil.sys` from Win8+ may need conversion; Vol 3 handles raw + windows crash dumps natively.
- **Time zone:** `CreateTime` is UTC. Normalise before merging into a super-timeline.
- **Plugin name typos:** use `vol --info` to list the exact, available plugin names in *this* build.

---

## 8. Where it fits a DFIR investigation

Memory forensics is the **first stop in live/triage IR** and the place you go when disk artifacts are suspiciously clean (fileless attacks). In this lab's Triad-and-hunt arc it complements the disk-based execution evidence: Prefetch/Amcache/ShimCache prove *a binary existed and ran*; Volatility shows *what it was doing and talking to at capture time*, and lets you **extract the live payload** for capability analysis (capa), string analysis (FLOSS), and signature matching (YARA). Typical pivot: `netscan` (beacon) → owning PID → `cmdline`/`pstree` (how it launched) → `malfind`/`dlllist --dump` (the payload) → capa/YARA (what it does / who it is).

---

## 9. Sources
- Volatility 3 official documentation — https://volatility3.readthedocs.io/ (plugin reference, symbol tables, ISF).
- Volatility Foundation GitHub — https://github.com/volatilityfoundation/volatility3 (README, symbol packs).
- The Art of Memory Forensics (Ligh, Case, Levy, Walters) — foundational text on the kernel structures the plugins walk.
- 13Cubed — "Investigating Windows Memory" / Volatility 3 walkthroughs (YouTube), practical malfind/netscan tradecraft.
- SANS FOR508 / DFIR memory-forensics posters — process-anomaly and injection-hunting methodology.
- Microsoft Learn — `_EPROCESS`, pool tags, and PDB/symbol-server background.
