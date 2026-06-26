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
```bash
prefetch /data/prefetch
```
**Expected output (real, from Case 001):**
```
AM_DELTA.EXE                  runs=1   last=2020-09-18 22:44:32  loaded=13 files
APPLICATIONFRAMEHOST.EXE      runs=7   last=2020-09-19 01:07:38  loaded=77 files
AUDIODG.EXE                   runs=8   last=2020-09-19 05:18:45  loaded=79 files
...
196 prefetch files parsed.
```
CSV for timelining:
```bash
prefetch /data/prefetch --csv /data/prefetch.csv      # columns: Executable, RunCount, LastRun, AllRunTimes, FilesLoaded
```
See what an executable loaded (great for finding side-loaded DLLs):
```bash
prefetch /data/prefetch/SVCHOST.EXE-*.pf --files
```

## Read it
- **RunCount + LastRun** = execution proof and recency. A normally-rare binary with `runs=1` at an odd hour is a lead.
- **FilesLoaded** = the DLLs/paths the program touched — spot a legit-looking process loading a malicious DLL from a weird directory.
- Sort the CSV by `LastRun` to see the execution sequence around your incident window (apply the ~10s offset).

## Exercises
1. Sort `prefetch.csv` by `LastRun` — what ran in the minutes around `2020-09-19`? Any LOLBins (`powershell`, `wmic`, `rundll32`, `mshta`)?
2. Find an executable that ran from a **non-standard path** (Temp, AppData) via `--files`.
3. One `.pf` here fails to parse (`VSSVC...`) — that's a real corrupted-artifact case. Note how the tool skips it and keeps going.

## Pivot
- An executable of interest → confirm it in **Module 2 (ShimCache)** and **Module 3 (Amcache)** (and get its **SHA1** from Amcache to hunt elsewhere).

---
*Next: [Module 2 — ShimCache](../module-02-shimcache-appcompatcache).*
