# Module 1 — Prefetch with PECmd (the Execution Gold Standard)

**Deck mapping:** *Windows Execution Forensics* → "Windows Prefetch: The Gold Standard" / "Parsing Prefetch with PECmd" / "The 10-Second Rule."
**Goal:** prove a program **ran**, **when**, **how many times**, and **what it touched** — the strongest single execution artifact.

---

## Concept (from the deck)
Windows writes a **Prefetch** file (`C:\Windows\Prefetch\<NAME>-<HASH>.pf`) to speed up app launches. For us it's execution gold: each `.pf` records the executable name, **run count**, up to **8 last-run timestamps**, and the **files/DLLs it loaded**. The deck's **"10-second rule":** the recorded run time is ~10s *after* the process actually started — keep that offset in mind when timelining.

> **Tooling note:** the deck uses **PECmd** (Eric Zimmerman) on a **Windows** host. PECmd needs Windows-only decompression libraries, so inside this Linux container we use the equivalent **`prefetch`** command (libscca/pyscca) — same core output, fully offline. On a Windows box, `PECmd -d <dir> --csv .` gives you the richer CSV.

**Data:** 197 real `.pf` files extracted from the **DFIR Madness Case 001** desktop (`DESKTOP-SDN1RPT`).

---

## Setup
```bash
cd module-01-prefetch-pecmd/data        # contains prefetch/*.pf
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

## Step — Parse the Prefetch
The container's `prefetch` command is **libscca's `sccainfo`**: it parses **one `.pf` file at a time** and prints rich detail. Point it at a single file:
```bash
prefetch /data/prefetch/AM_DELTA.EXE-78CA83B0.pf
```
**Expected output (real, from Case 001):**
```
Windows Prefetch File (PF) information:
	Format version			: 30
	Executable filename		: AM_DELTA.EXE
	Run count			: 1
	Last run time: 1		: Sep 18, 2020 22:44:32.551352300 UTC
	...
	Number of filenames		: 13
	Filename: 2			: \VOLUME{...}\WINDOWS\SOFTWAREDISTRIBUTION\DOWNLOAD\INSTALL\AM_DELTA.EXE
	...
```
The **Filenames** section lists every DLL/file the executable loaded — that's your "side-loaded DLL" hunt (no special flag needed; it's always printed).

To summarise **all** the `.pf` at once (executable, run count, last run, files loaded), loop `prefetch` and pull the key fields:
```bash
for f in /data/prefetch/*.pf; do
  prefetch "$f" 2>/dev/null | awk '
    /Executable filename/    {n=$0; sub(/.*: /,"",n)}
    /Run count/              {r=$0; sub(/.*: /,"",r)}
    /Last run time: 1[^0-9]/ {l=$0; sub(/.*: /,"",l); sub(/\..*/,"",l)}
    /Number of filenames/    {c=$0; sub(/.*: /,"",c);
                              printf "%-28s runs=%-3s last=%s loaded=%s files\n", n, r, l, c}'
done
```
**Expected output (real, from Case 001):**
```
AM_DELTA.EXE                 runs=1   last=Sep 18, 2020 22:44:32 loaded=13 files
APPLICATIONFRAMEHOST.EXE     runs=7   last=Sep 19, 2020 01:07:38 loaded=77 files
AUDIODG.EXE                  runs=8   last=Sep 19, 2020 05:18:45 loaded=79 files
...
```
196 of the 197 `.pf` summarise cleanly; `VSSVC.EXE-6C8F0C66.pf` is a real corrupted artifact and is skipped (Exercise 3).

> **Richer CSV (on the Windows VM):** the container's `prefetch`/`sccainfo` has **no** CSV export. On the **Windows** host this lab pairs with, the deck's tool **PECmd** does: `PECmd.exe -d C:\path\to\prefetch --csv . --csvf prefetch.csv` produces a timeline-ready CSV (`ExecutableName, RunCount, LastRun, ...`). Use PECmd on the VM; use the loop above in the container.

## Read it
- **RunCount + LastRun** = execution proof and recency. A normally-rare binary with `runs=1` at an odd hour is a lead.
- **Files loaded** = the DLLs/paths the program touched (the **Filenames** section) — spot a legit-looking process loading a malicious DLL from a weird directory.
- Pipe the loop to `sort` by the last-run field to see the execution sequence around your incident window (apply the ~10s offset).

## Exercises
1. Pipe the summary loop to `sort -k3` (by last run) — what ran around `2020-09-19`? Any LOLBins? (`POWERSHELL.EXE`, `RUNDLL32.EXE`, `CMD.EXE`, and the Case-001 malware `COREUPDATER.EXE` are all present here.)
2. Inspect a single binary's **Filenames** section — `prefetch` parses **one** file, so name it exactly, e.g. `prefetch /data/prefetch/COREUPDATER.EXE-157C54BB.pf` (the Case-001 malware you'll meet in Module 4) or one of the `RUNDLL32.EXE-*.pf`. Note the paths it loaded; a binary loading from `\Temp\`, `\AppData\`, or `\Users\Public\` is a staging lead (cross-check in Modules 2–3).
3. One `.pf` fails to parse — `VSSVC.EXE-6C8F0C66.pf` (a real corrupted artifact). Run `prefetch` on it and note the `libscca` read error; in the loop, `2>/dev/null` skips it so the run keeps going. That's how a real corrupted artifact behaves.

## Pivot
- An executable of interest → confirm it in **Module 2 (ShimCache)** and **Module 3 (Amcache)** (and get its **SHA1** from Amcache to hunt elsewhere).

---
*Next: [Module 2 — ShimCache](../module-02-shimcache-appcompatcache).*
