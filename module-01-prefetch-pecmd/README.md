# Module 1 — Prefetch with PECmd (the Execution Gold Standard)

**Deck mapping:** *Windows Execution Forensics* → "Windows Prefetch: The Gold Standard" / "Parsing Prefetch with PECmd" / "The 10-Second Rule."
**Goal:** prove a program **ran**, **when**, **how many times**, and **what files it touched** — the single strongest piece of execution evidence on a Windows machine.

> **New to this?** Read the next two sections slowly. Every italic term is defined the first time it appears. By the end you'll be able to look at a folder of `.pf` files and tell a story about what happened on a computer.

---

## 1. Background — what Prefetch is and why Windows creates it

### The everyday purpose (why the file exists at all)
Windows wants apps to *start fast*. Every time you launch a program, Windows watches what that program does in its **first ~10 seconds of life** — which code pages it loads, which `.dll` helper files (*Dynamic-Link Libraries*: shared code files a program pulls in) and data files it opens, and in what order. It saves that "shopping list" to a small file so that **next time** you launch the same program it can pre-load those pieces from disk in advance ("pre-fetch" them). That makes the second and later launches noticeably quicker.

That speed-up file is a **Prefetch file**. It lives in `C:\Windows\Prefetch\` and is named like:

```
NOTEPAD.EXE-C5670914.pf
```

- `NOTEPAD.EXE` — the executable's name.
- `C5670914` — an **8-character hexadecimal hash** (a number that fingerprints *where the program was run from*). Windows computes it from the program's **full path**, and for some system programs (like `svchost.exe`) also from the **command-line arguments**. (*Hexadecimal* just means base-16: digits 0-9 plus A-F.)
- `.pf` — the file extension for Prefetch.

The hash is why the same program run from two different folders produces **two different `.pf` files**. That is a gift to investigators: a copy of `cmd.exe` run from `C:\Windows\System32` and a malicious copy run from `C:\Users\Public` leave *two separate* Prefetch files with *two different* hashes.

### Why investigators love it (what you can prove)
Although Windows built this purely for speed, it accidentally created one of the best **evidence-of-execution** artifacts in Windows forensics. An *artifact* is just any trace the operating system leaves behind that we can read later. From one `.pf` file you can prove:

- **That the program ran at all** (the file's mere existence is proof it executed at least once).
- **How many times** it ran — the **run count**.
- **When** it ran — up to the **last 8 run timestamps**.
- **What it loaded** — a list of every file and DLL the program touched in those first seconds (great for spotting a trusted program that was tricked into loading a malicious DLL — a technique called *DLL side-loading*).
- **Where it ran from** — recoverable from the loaded-files list and the path hash.

### How it works under the hood (simple version)
1. You launch `program.exe`.
2. A Windows service called the **Prefetcher** (part of the *SysMain*/Superfetch service) monitors the launch for about **10 seconds**.
3. About 10 seconds *after* the process starts, Windows writes (or updates) the `.pf` file on disk. **This is the famous "10-second rule":** the timestamp baked into the `.pf` is essentially when the program *started*, but the file's own creation/modify time on disk is ~10 seconds later. When you build a timeline, remember the recorded run is the real "go" moment.
4. Since Windows 8, the `.pf` file is **compressed** with an algorithm called **Xpress Huffman** (sometimes shown as `XPRESS10`/`MAM` format). This is why you need a real Prefetch parser to read it — you can't just open it in Notepad.
5. Inside, since Windows 8, Windows keeps the **last 8 run times** (older Windows kept only 1). It also keeps a running **run count**.

### Limits and gotchas (so you don't over-claim)
- **Prefetch can be turned off.** A registry value, `EnablePrefetcher` (under `...\Session Manager\Memory Management\PrefetchParameters`), controls it. On SSDs and Windows Servers it is sometimes disabled, so *no Prefetch file does NOT prove a program never ran.*
- **Capacity is capped.** Modern Windows 10/11 keeps up to **1024** Prefetch files (older Windows kept 128). When full, the oldest get deleted — so absence can simply mean "aged out."
- **Attackers delete Prefetch** to cover tracks. A *missing* `.pf` for a program you know ran is itself a finding.
- **Only the last 8 runs** are timestamped. A program run 50 times shows run count 50 but only 8 dates.

---

## 2. What the tool does — PECmd

The deck's tool is **PECmd** ("Prefetch Explorer Command-line") by Eric Zimmerman — the standard Windows-native Prefetch parser. It decompresses each `.pf`, decodes the binary structure, and prints (or exports to CSV) the executable name, run count, all 8 run times, the volume/device info, and the full list of loaded files and directories. PECmd is one of the **EZ Tools**; on the lab's Windows VM it is installed natively and already on your `PATH` (it lives under `C:\DFIR\tools`), so you call it directly as `PECmd.exe`.

PECmd has two modes you'll use constantly:

- **`PECmd.exe -f <file.pf>`** — parse **one** `.pf` file and print a rich, human-readable summary **to the console** (run count, all run times, volume info, and the full files-loaded list). Use this when you want to read everything one artifact holds.
- **`PECmd.exe -d <dir> --csv <outdir> --csvf <name.csv>`** — parse a whole **d**irectory of `.pf` files and write the results to a **CSV** (one row per `.pf`, plus a companion `*_Timeline.csv` with one row per individual run time). Use this for triage across a folder.

**Data for this module (multiple files):** **197 real `.pf` files** extracted from the **DFIR Madness "Case 001"** desktop, hostname `DESKTOP-SDN1RPT` — a documented intrusion, so the exercises have real answers. The whole point of having 197 of them is that real triage means processing a *folder*, not one file: most are an ordinary Windows **baseline** (svchost, explorer, runtimebroker…) and a few are leads (`COREUPDATER.EXE`, plus LOLBins). You'll batch-process the directory, then compare a benign file against the suspect. For convenience the folder also ships a pre-parsed **`pf.csv`** (the same fields PECmd exports, with simple column names) you can open directly if you just want to read, not parse. See `data/README.md` for provenance and licensing of these files.

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-01-prefetch-pecmd/data        # contains prefetch/*.pf  and  pf.csv
```

What each piece means:
- `cd module-01-prefetch-pecmd/data` — move into the folder holding this module's evidence. **Every command below is run from inside this folder**, so evidence files are named with simple relative paths (e.g. `prefetch/AM_DELTA.EXE-78CA83B0.pf`).

All forensic tools are installed **natively on the lab VM and already on your `PATH`**, so you call them directly by name in Git Bash — no container, no Docker. The VM is kept **offline** (no network) so evidence can never "phone home" and nothing can tamper with it.

---

## 4. Step-by-step walkthrough

### Step 1 — Parse a single Prefetch file
Start with one file so you can see the full detail Prefetch holds:

```bash
PECmd.exe -f prefetch/AM_DELTA.EXE-78CA83B0.pf
```

- `PECmd.exe` — Eric Zimmerman's native Prefetch parser, already on your `PATH`.
- `-f prefetch/AM_DELTA.EXE-78CA83B0.pf` — the `-f` (**f**ile) switch parses a **single** `.pf` and prints its full summary to the console. (Use `-d` for a whole directory; see Step 2.)

**Representative output (PECmd console, abbreviated):**
```
Source file: prefetch\AM_DELTA.EXE-78CA83B0.pf
  Source created:  ...
  Source modified: ...

  Executable name: AM_DELTA.EXE
  Hash: 78CA83B0
  Version: Windows 10 or Windows 11

  Run count: 1
  Last run: 2020-09-18 22:44:32

  Volume information:
  #0: Name: \VOLUME{...}  Serial: ...  Created: ...

  Directories referenced: ...

  Files referenced: 13
  00: \VOLUME{...}\WINDOWS\SOFTWAREDISTRIBUTION\DOWNLOAD\INSTALL\AM_DELTA.EXE
  ...
```
*(Exact spacing/field order varies by PECmd version; the fields themselves are what matter.)*

**Reading the key fields:**
- **Executable name** — the program this `.pf` belongs to.
- **Hash** — the 8-character path hash from the filename (it fingerprints *where* the program ran from). Two copies of a program in different folders get two different hashes.
- **Version** — PECmd reports the Prefetch format as an OS family in words: **`Windows 10 or Windows 11`** here. (Older formats show as Windows 8.x or Windows 7.) This confirms the OS family.
- **Run count** — how many times this program has executed. `1` = ran exactly once.
- **Last run** — the **most recent** execution time, in **UTC** (Coordinated Universal Time — the timezone forensics uses so everyone agrees on "when"). PECmd also lists the earlier run times (up to 8 total) on their own lines.
- **Files referenced** (and **Directories referenced**) — every file and DLL the program loaded in its first ~10 seconds. The `\VOLUME{...}` prefix is Windows' internal name for the disk volume. **This list is your DLL side-loading hunt** — `-f` always prints it in full.

### Step 2 — Parse ALL 197 files at once (directory → CSV)
Reading 197 files one at a time is impractical. PECmd's directory mode parses the whole folder and writes a single CSV you can triage:

```bash
PECmd.exe -d prefetch --csv . --csvf prefetch.csv
```

- `-d prefetch` — parse every `.pf` in the `prefetch/` sub-folder (the **d**irectory mode).
- `--csv .` — write the CSV report into the current folder (`.`).
- `--csvf prefetch.csv` — name the main CSV `prefetch.csv`. (PECmd also writes a companion `prefetch_Timeline.csv` — one row per individual run time, handy for timelining.)

PECmd processes all 197 files, printing a running tally to the console and noting any file it could **not** parse. The malformed `VSSVC.EXE-6C8F0C66.pf` is reported as a **parsing error** and flagged in the CSV's error column, while the other **196** parse cleanly — exactly how you handle a damaged artifact in a real case (document it, move on; see Exercise 3).

The resulting `prefetch.csv` carries PECmd's native columns — among them **`SourceFilename, ExecutableName, Hash, Size, Version, RunCount, LastRun, PreviousRun0`…`PreviousRun6` (the earlier 7 run times), Volume info, Directories, FilesLoaded** (count of files referenced), and a parsing-error column. Open it in a spreadsheet to browse everything PECmd captured.

**Quick scan without a spreadsheet.** For a fast read of the four facts that matter (name, run count, last run, files loaded), scan the committed **`pf.csv`** — a pre-parsed convenience copy whose columns are simple and stable: `SourceFile, Executable, RunCount, LastRun, AllRunTimes, FilesLoaded`. (It holds the same facts your fresh `prefetch.csv` does, just with friendlier column names.)

```bash
awk -F',' 'NR>1 {printf "%-28s runs=%-3s last=%s loaded=%s files\n", $2, $3, $4, $6}' pf.csv
```

**What each part does, in plain English:**
- `awk -F','` — process the file column-by-column, splitting on commas (`-F','` sets the comma as the field separator).
- `NR>1` — skip the header row (`NR` is the current line number; row 1 is the column titles).
- `$2, $3, $4, $6` — the `Executable`, `RunCount`, `LastRun`, and `FilesLoaded` columns of `pf.csv`.
- `printf "%-28s runs=%-3s ..."` — print the fields in neat aligned columns (`%-28s` = left-justified 28-character text field).

**Representative output:**
```
AM_DELTA.EXE                 runs=1   last=2020-09-18 22:44:32 loaded=13 files
APPLICATIONFRAMEHOST.EXE     runs=7   last=2020-09-19 01:07:38 loaded=77 files
AUDIODG.EXE                  runs=8   last=2020-09-19 05:18:45 loaded=79 files
...
COREUPDATER.EXE              runs=1   last=2020-09-19 03:40:49 loaded=51 files
...
```
196 of the 197 files summarise cleanly; the one corrupt file (`VSSVC.EXE-6C8F0C66.pf`) is the parsing error PECmd flagged above (Exercise 3).

### Step 3 — Put it in execution order (build a mini-timeline)
Sort the scan by run time so the activity lines up chronologically around the incident window. Because `LastRun` is in `YYYY-MM-DD HH:MM:SS` ISO order, a plain text sort on that column *is* a true chronological sort:

```bash
sort -t, -k4 pf.csv | awk -F',' 'NR>1 {printf "%-26s %-40s runs=%-3s\n", $4, $2, $3}' | less -S
```
- `sort -t, -k4 pf.csv` — sort the rows on **column 4** (`LastRun`); `-t,` tells `sort` the fields are comma-separated.
- `awk -F',' '...'` — pretty-print the run time, executable, and run count into aligned columns.
- `less -S` — scroll without wrapping long lines (`q` to quit).

**Even simpler:** PECmd already wrote `prefetch_Timeline.csv` in Step 2 — one row per individual run time, so a program that ran 8 times appears 8 times. Sort that file by its timestamp column to get a per-run timeline of the whole host without any extra work.

### Step 4 — Compare a benign baseline file against the suspect (multi-file reasoning)
A single file in isolation rarely looks "wrong." You judge it by comparison. Parse a known-good system binary and the suspect side by side and pull the same fields from each:

```bash
echo "===== BENIGN BASELINE: SVCHOST ====="; PECmd.exe -f prefetch/SVCHOST.EXE-12871F9D.pf | grep -iE "Executable name|Run count|Last run|referenced"
echo "===== SUSPECT: COREUPDATER ====="; PECmd.exe -f prefetch/COREUPDATER.EXE-157C54BB.pf | grep -iE "Executable name|Run count|Last run|referenced"
```
- `PECmd.exe -f <file>` — print each file's full console summary.
- `grep -iE "...|..."` — keep only the lines matching any of these labels (a quick way to line up the same few fields from two different files). `-E` enables the `|` ("or") syntax; `-i` makes it case-insensitive.

**Read the comparison:** `svchost.exe` is a high-frequency OS service — many runs, many DLLs loaded from System32, unremarkable timing. `coreupdater.exe` is the opposite: it runs a handful of times, in the incident window, with a name that *imitates* a system updater. The contrast — not either file alone — is what flags it. This "baseline vs. outlier" instinct is the heart of every later module.

---

## 5. Reading the output — benign vs suspicious

| Field | What it means | Benign looks like | Suspicious looks like |
|---|---|---|---|
| **Executable** | program name | `SVCHOST.EXE`, `EXPLORER.EXE` | a System32-sounding name in a weird place, a typo (`scvhost.exe`), or an unknown name |
| **RunCount** | times executed | high counts for OS tools | a normally-rare tool with `runs=1` at an odd hour |
| **LastRun (UTC)** | most recent execution | during business hours / patching windows | 2-5 AM, right inside the incident window |
| **FilesLoaded** | DLLs/paths touched | DLLs from `\Windows\System32\` | a DLL loaded from `\Temp\`, `\AppData\`, `\Users\Public\` (side-loading) |

**Rules of thumb:**
- A binary in Prefetch but **not** in ShimCache (Module 2) or Amcache (Module 3) — or vice-versa — is a gap worth explaining; the three artifacts cover each other's blind spots.
- LOLBins (*Living-Off-the-Land Binaries*: legit Windows tools attackers abuse — `powershell.exe`, `rundll32.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`) running at unusual times deserve a look at *what they loaded* and *what ran right after*.
- Always apply the **10-second rule** when timelining: the recorded run is the real start; the file's on-disk timestamp is ~10s later.

---

## 6. Investigative narrative (Case 001)

In Case 001, the desktop `DESKTOP-SDN1RPT` was compromised. Among the 197 Prefetch files sits **`COREUPDATER.EXE-157C54BB.pf`** — a name engineered to look like a legitimate updater. Prefetch proves it **executed** on this host on **2020-09-19**, in the small hours, and its loaded-files list shows where it ran from. That single fact — *it ran, here, at this time* — is the anchor. In Modules 2-4 you'll confirm the same binary's **identity** (its SHA1 fingerprint) and learn it's the malware at the center of the case. Prefetch is the corner of the **Triad** that answers **"did it run, and when?"**

---

## 7. Try-it-yourself exercises

1. **Find the LOLBins.** Run the Step-3 sorted scan. Which `POWERSHELL.EXE`, `RUNDLL32.EXE`, `CMD.EXE`, or `WSCRIPT.EXE` entries appear, and when did they last run? (All are present in this data.) Do any cluster around the `2020-09-19` early-morning window?
2. **Inspect the malware's loaded files.** `PECmd.exe -f prefetch/COREUPDATER.EXE-157C54BB.pf` — read its **Files referenced** section. What paths did it touch? Any in `\Temp\`, `\AppData\`, or `\Users\Public\`? (You'll cross-check this binary's identity in Modules 3-4.)
3. **Meet a real corrupt artifact.** Run `PECmd.exe -f prefetch/VSSVC.EXE-6C8F0C66.pf` on its own. Note that PECmd reports a **parsing error** — the file is genuinely corrupt. When you parsed the whole folder in Step 2 (`-d`), PECmd flagged that one file and kept going, so the other 196 still parsed — exactly how you handle a damaged artifact in a real case (document it, move on).
4. **Run-count reasoning.** Open `pf.csv` (or your `prefetch.csv`) and find a program with `RunCount` far higher than the number of distinct timestamps shown. Explain why (only the last 8 runs are timestamped).
5. **10-second rule.** Pick any entry's `LastRun`. If a teammate says "the file's creation time on disk is 10 seconds later — which is the real execution time?", what's your answer and why?

---

## 8. Key takeaways

- **Prefetch exists for speed, but it's execution gold:** name, **run count**, **last 8 run times**, and **files loaded** per program.
- The **filename hash** ties a run to a *path*, so the same program from two folders leaves two `.pf` files — great for spotting an out-of-place copy.
- **The 10-second rule:** the recorded run time is the real start; the file's on-disk time is ~10s later.
- **Absence isn't innocence:** Prefetch can be disabled, capped at 1024, aged out, or deleted by an attacker.
- In the **Triad**, Prefetch answers **"did it run, when, how often?"** — confirm **existence** in Module 2 (ShimCache) and **identity/SHA1** in Module 3 (Amcache).

## Sources & further reading
This module's structure follows the standard DFIR teaching of Prefetch. To go deeper:
- **PECmd / EZ Tools** (Eric Zimmerman's official tools + docs): https://ericzimmerman.github.io/ and the AboutDFIR EZ Tools manual: https://aboutdfir.com/toolsandartifacts/windows/eric-zimmermans-tools/
- **libscca — Windows Prefetch File (PF) format** (an open-source spec documenting the Prefetch binary format PECmd parses): https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
- **Yogesh Khatri — "Windows Prefetch (.PF) files"** (the classic deep-dive on the format, hash, and timestamps): http://www.swiftforensics.com/2013/10/windows-prefetch-pf-files.html
- **Magnet Forensics — "Forensic Analysis of Prefetch files in Windows"** (the 10-second rule, run counts, what you can prove): https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/
- **13Cubed — "Investigating Windows Prefetch"** (excellent free video walkthrough): https://www.youtube.com/c/13cubed
- **DFIR Madness — Case 001** (the dataset these `.pf` files come from): https://dfirmadness.com/the-stolen-szechuan-sauce/

## Pivot
- A binary of interest here → confirm it in **Module 2 (ShimCache)** and **Module 3 (Amcache)**, and grab its **SHA1** from Amcache to hunt the same file on other hosts in **Module 4**.

---
*Next: [Module 2 — ShimCache](../module-02-shimcache-appcompatcache).*
