# Module 4 — Scaling the Hunt with AppCompatProcessor

**Deck mapping:** *Windows Execution Forensics* → "Scaling Execution Analysis" / "Stacking & Least-Frequency-of-Occurrence" · *Advanced Intrusion Forensic Hunting* → "Hunting at Enterprise Scale."
**Goal:** stop looking at **one** host. Take the Triad artifacts (Amcache/ShimCache) from **many** hosts, pile them together, and let the **rarest** thing float to the top — that single weird binary that exists on *one* box out of hundreds.

> **The shift in thinking:** Modules 1-3 taught you to *read* artifacts on a single machine. At enterprise scale you can't read 5,000 machines by hand. Instead you **count**. This module teaches the counting method on real data, then shows the tool that automates it.

---

## 1. Background — stacking and Least-Frequency-of-Occurrence (LFO)

### Why counting beats reading at scale
On one host you study each entry. Across an enterprise you **stack**: pick one attribute (filename, path, SHA1, parent directory…), group every host's entries by that attribute, and **count** how many times each value appears. Then you read the *counts*, not the rows.

**Least-Frequency-of-Occurrence (LFO)** is the hunting principle that makes stacking pay off:

> Attacker tooling is, by definition, **rare** — it lives only on the few machines the attacker touched. Microsoft-signed binaries that exist on 5,000 hosts are **noise**. The unsigned 7 KB `coreupdater.exe` that exists on **one** host is the **hunt**.

So you sort the stack **ascending by count** and look at the top: the `Count = 1` and `Count = 2` rows are your leads.

### The honest caveat (so you don't over-trust LFO)
Rarity is a *lead generator*, not a verdict. Plenty of perfectly benign things are also rare — a developer's `code.exe`, one user's `firefox.exe`, an admin tool on a single workstation. **LFO narrows thousands of rows to a handful; you still apply the single-host skills (metadata, path, signing, SHA1 reputation) to each survivor.** You'll see exactly this in the data: `coreupdater.exe` *and* several benign apps all come back with Count = 1, and it's the metadata that separates them.

---

## 2. What the tool does — AppCompatProcessor (ACP)

**AppCompatProcessor** (Matías Bevilacqua) is the purpose-built scaling tool. It ingests AppCompat/Amcache from a folder of hosts into **one SQLite database**, then runs analytics across the whole set:

- **`stack`** — the LFO engine: count any attribute, sorted rarest-first.
- **`search`** — a known-bad regex sweep (130+ methodology terms) with a hit histogram.
- **`leven`** — typosquat/masquerade finder using **Levenshtein distance** (how many single-character edits separate two strings) — catches `svch0st.exe`, `lssas.exe`.
- **`tstomp`** — timestomp candidates (files wearing a timestamp that doesn't fit their location).
- **`tcorr`** — temporal correlation (dropper → payload sequences).

**Data for this module (multiple hosts):**
- **`amcache_host-DESKTOP_*.csv`** + **`shimcache_host-DESKTOP.csv`** — the **real** parsed Triad for `DESKTOP-SDN1RPT` (DFIR Madness Case 001), the same host you worked in Modules 1-3. This is the host that has the malware.
- **`amcache_host-WORKSTATION07_*.csv`** / **`shimcache_host-WORKSTATION07.csv`** and **`...WORKSTATION12...`** — **two synthetic benign peer workstations** added so stacking has something to count against. They share the real host's common Microsoft System32 binaries (same names, same SHA1s — because identical files really do share a hash) and each has a few unique benign apps (Chrome, Firefox, Teams, VS Code…). **They contain no malware.** Their purpose is to make the `Count` column meaningful so LFO actually demonstrates. See `data/README.md` for exactly how they were generated and labelled synthetic.

> **Why mix real + synthetic?** Stacking's payoff *requires* multiple hosts, but there is no clean, license-clear public "multi-host Amcache" set, and the lab's one fully-documented intrusion is a single host. So we keep the **real** host for verifiable answers and add two **synthetic benign** peers purely as a counting baseline — clearly labelled so no one mistakes them for evidence.

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-04-scaling-appcompatprocessor/data
```
(Every command in this module is run **from inside this `data/` folder**; all forensic tools are installed natively and already on your `PATH`, so you call them directly by name — no container, no Docker. See Module 1 §3.)

---

## 4. Part 1 — Stacking by hand across multiple hosts (works today, real data)

Stacking is just **group-and-count**. You already have parsed CSVs for three hosts, so Git Bash's shell tools *are* a stacking engine. Doing it by hand once makes the tool obvious.

### Stack 1 — count filenames across ALL hosts (the core LFO move)
```bash
awk -F, 'FNR>1{print tolower($7)}' amcache_host-*_UnassociatedFileEntries.csv \
  | sort | uniq -c | sort -n
```
- `awk -F, 'FNR>1{print tolower($7)}'` — for **every** host file matched by the wildcard, print column 7 (`Name`) in lowercase. `FNR>1` skips each file's header (FNR = line number *within the current file*, so it resets per file — important when reading many files).
- `amcache_host-*_UnassociatedFileEntries.csv` — the shell expands the `*` to all three hosts' files, so we count across the whole "enterprise."
- `sort | uniq -c` — sort the names, then `uniq -c` collapses duplicates and **prefixes each with its count**.
- `sort -n` — sort **n**umerically by that count, so the **rarest float to the top**.

**Expected output (real + synthetic peers):**
```
      1 7zfm.exe
      1 chrome.exe
      1 code.exe
      1 coreupdater.exe        <-- the malware: rare AND on the real host
      1 firefox.exe
      1 ftk imager.exe
      1 msiexec.exe
      1 outlook.exe
      1 teams.exe
      3 compattelrunner.exe
      3 csrss.exe
      3 devicecensus.exe
      3 drvinst.exe
      3 mousocoreworker.exe
      3 msmpeng.exe
      3 sihclient.exe
      3 svchost.exe
      3 tiworker.exe
      3 winlogon.exe
      4 onedrivesetup.exe
```
**Read it:** ubiquitous Microsoft binaries (`csrss`, `svchost`, `winlogon`) show **Count = 3** — present on all three hosts → noise. The **Count = 1** band is your lead list. Note the honest lesson from §1: `coreupdater.exe` is there, but so are benign `chrome.exe`, `firefox.exe`, `code.exe`. **LFO surfaced the candidates; now you triage them.**

### Stack 2 — stack on SHA1 (the strongest pivot)
Filenames can be reused; the **SHA1 hash is exact**. Stack on it:
```bash
awk -F, 'FNR>1 && $4!=""{print $4}' amcache_host-*_UnassociatedFileEntries.csv \
  | sort | uniq -c | sort -n
```
- Same idea, but printing column 4 (`SHA1`) and skipping blanks. (We drop the `| head` here: with only 21 distinct hashes the whole list is short, and dropping it keeps the **Count = 3** band visible instead of only the rarest rows.)

**Expected:**
```
      1 32756b3a319340c4b7fead410d3f36e503b30da2
      1 5d6102f5a170e982c7735bfc2b9c1a0a0d435fd1
      ...
      1 fd153c66386ca93ec9993d66a84d6f0d129a3a5c   <-- coreupdater, on ONE host
      1 fe0affa6c25ae39d12f2e59c14f65b8957168953
      3 2b0390dd4520dd77258bf52ad96692538c4de6d3
      3 53e696941b2a5fa304100cd0011f9478f282dab7
      ...
      3 66f5e6dade65d7dba979602830d58e53e60fdffb   <-- svchost, on all three
      3 69a1dcf6a41bc750cacec3185c99839c079275bd   <-- csrss, on all three
      ...
```
**Read it:** because identical files share a hash, genuine OS binaries collapse to **Count = 3**; the malware's hash `fd153c66…` is **Count = 1**. **This is LFO at its purest** — in a real 500-host hunt, this exact query names every infected box.

> **Instructor note — where the `Count = 3` band comes from.** Only **one** of these three hosts is real (the Case-001 `DESKTOP` host); the other two are the **lab-generated synthetic peers** (`WORKSTATION-07/12`) described in §1 and `data/README.md`. They were deliberately **seeded with the real host's Microsoft System32 SHA1s** so that ubiquitous OS binaries land on `Count = 3` and the malware stands out at `Count = 1`. The *mechanism* (rarity surfaces the outlier) is exactly what a real fleet shows — but the clean `3`-vs-`1` separation here is a **constructed teaching baseline**, not three independently collected machines. On real data the "noise" band is fuzzier; you still convict on metadata, never on the count alone.

### Stack 3 — triage the survivors: "which System32 exe has NO Microsoft metadata?"
Now apply single-host skill to the Count=1 band. Every genuine `C:\Windows\System32\*.exe` carries a Microsoft `ProductName`. Attacker drops usually don't:
```bash
awk -F, 'FNR>1 && tolower($6) ~ /system32/ && tolower($6) ~ /\.exe/ \
  {print $7"  | prod="$10" | size="$11" | host="FILENAME}' \
  amcache_host-*_UnassociatedFileEntries.csv | sort
```
- `tolower($6) ~ /system32/` — keep only rows whose `FullPath` (col 6) is in System32.
- `host="FILENAME` — `FILENAME` is an awk built-in holding the current input file, so each row is tagged with which host it came from.

**Expected (real, Case 001):**
```
coreupdater.exe  | prod=                                     | size=7168   | host=amcache_host-DESKTOP_...
csrss.exe        | prod=microsoft® windows® operating system | size=17592  | host=amcache_host-DESKTOP_...
svchost.exe      | prod=microsoft® windows® operating system | size=57368  | host=amcache_host-DESKTOP_...
winlogon.exe     | prod=microsoft® windows® operating system | size=907776 | host=amcache_host-DESKTOP_...
...
```
**Read it:** one row is naked — **`coreupdater.exe`**: empty `ProductName`, **7,168 bytes** (every real System32 binary is bigger and signed), on the real host. That's the LFO outlier *confirmed by metadata*.

### Stack 4 — pull its identity for the cross-host hunt
```bash
grep -i coreupdater amcache_host-DESKTOP_UnassociatedFileEntries.csv | cut -d, -f4,6,9,11
```
- `cut -d, -f4,6,9,11` — print just columns 4,6,9,11 = `SHA1, FullPath, LinkDate, Size`.
```
fd153c66386ca93ec9993d66a84d6f0d129a3a5c,c:\windows\system32\coreupdater.exe,2010-04-14 22:06:53,7168
```
**SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`** is your hunt key. Across a real enterprise you'd stack *every* host's Amcache on `SHA1` (Stack 2) and the handful of hosts holding this hash are your victim list.

> **A correction worth internalising:** an earlier telling of this case flagged `coreupdater.exe`'s **2010 LinkDate** as the tell. Don't lean on that. In this very dataset, genuine Microsoft binaries carry absurd LinkDates too (`MoUsoCoreWorker.exe` → 2049, `winlogon.exe` → 2077, `OneDriveSetup.exe` → 2090). **LinkDate alone proves nothing.** The real signal is the *convergence*: System32 path + empty ProductName/Version + 7 KB size + `IsOsComponent=False` + Count=1 across hosts.

### Stack 5 — where do executables live? (path stacking)
```bash
awk -F, 'FNR>1{n=split($6,a,"\\"); p=""; for(i=1;i<n;i++)p=p a[i]"\\"; print p}' \
  amcache_host-*_UnassociatedFileEntries.csv | sort | uniq -c | sort -n
```
- `split($6,a,"\\")` — split the full path on backslashes into array `a`; rebuild everything *except* the filename to get the **directory**, then count directories across hosts.

**Read it:** most executables sit in `System32` or `Program Files`. A directory like `Users\Public`, `ProgramData`, `Temp`, or `AppData` with a low count is a staging-location lead — the same instinct from Modules 2-3, now mechanised across hosts.

---

## 5. Part 2 — AppCompatProcessor (the at-scale tool)

With many hosts you don't `awk` by hand — you load everything into ACP once and query. The real commands:

```bash
# Load a folder of hosts (raw SYSTEM/Amcache hives, ShimCacheParser CSVs, or zips) into one DB:
python2 /opt/appcompatprocessor/AppCompatProcessor.py hosts.db load .

python2 /opt/appcompatprocessor/AppCompatProcessor.py hosts.db status   # host / entry counts
python2 /opt/appcompatprocessor/AppCompatProcessor.py hosts.db list     # hosts + recon scoring

# Stacking — the LFO engine. 'what' to count, 'from' = SQL filter:
python2 .../AppCompatProcessor.py hosts.db stack "FileName" "FilePath LIKE '%System32'"
python2 .../AppCompatProcessor.py hosts.db stack "FileName,Sha1" "FilePath LIKE '%System32' AND length(FileName) < 10"

# Known-bad regex sweep (130+ methodology terms, with a hit histogram):
python2 .../AppCompatProcessor.py hosts.db search

# Typosquat / masquerade finder (Levenshtein distance 1 from real System32 names: svch0st.exe, lssas.exe):
python2 .../AppCompatProcessor.py hosts.db leven

# Timestomp candidates (entries outside System32 wearing a System32 timestamp; AmCache 0-microsecond entries):
python2 .../AppCompatProcessor.py hosts.db tstomp
```
The `stack` sort is ascending-by-count, so **the top rows are the rarest** — LFO, automated. `search` prints a histogram so you triage the loudest known-bad hits first; `leven` and `tstomp` are zero-knowledge anomaly finders that need no prior IOCs.

> **ACP loader note:** ACP is a **Python 2** tool, and its hive/Amcache ingest depends on `libregf`/`pyregf` + `Registry.py`, with `load` computing per-file MD5 instance IDs (so it also needs a working py2 `hashlib` `md5`). The `load` step is historically the fragile part: where those native bits are missing, `load` registers a host but ingests **0 entries**. That's why **Part 1 above is the hands-on path** — and it now runs across **three** hosts so you feel the `Count` column work. The Part 2 commands are the correct production workflow; run them once you've confirmed ACP's loader (Python 2 + `libregf`/`pyregf` + working py2 `hashlib`) on your VM. **Adjust the `AppCompatProcessor.py` path** below to wherever ACP is installed on your lab VM.

---

## 6. Investigative narrative

In Modules 1-3 you proved, on a single host, that `coreupdater.exe` ran (Prefetch), was inventoried with SHA1 `fd153c66…` (Amcache), and slipped past ShimCache (the gap). Module 4 changes the question from *"is this host compromised?"* to *"which hosts in my fleet are?"* Stacked across three machines, the malware's **name and hash both come back Count = 1** while every Microsoft binary is Count = 3 — and that single fact, run across 500 real hosts, is how a responder turns one confirmed infection into a complete victim list in seconds.

---

## 7. Try-it-yourself exercises

1. **Find the outlier, the right way.** Run Stack 1 then Stack 3. List *every* reason `coreupdater.exe` is suspicious (metadata, size, path, `IsOsComponent`, rarity) — and explain why its **LinkDate is *not* on that list**. Confirm its SHA1.
2. **Hash beats name.** Run Stack 2. Why is stacking on SHA1 stronger than stacking on filename? Give one way an attacker could beat a *name* stack that a *hash* stack would still catch.
3. **The benign Count=1 trap.** Stack 1 returns `chrome.exe`, `firefox.exe`, `code.exe`, and `coreupdater.exe` all at Count = 1. Explain, in two sentences, why rarity alone didn't solve the case and what *did*.
4. **Triad gap, mechanised.** `grep -i coreupdater shimcache_host-DESKTOP.csv` — is it in ShimCache? (It isn't.) Using the Module 3 Triad table, explain what "in Amcache, not in ShimCache" tells you.
5. **Plan the fleet hunt.** You hold SHA1 `fd153c66…`. Write the one-sentence LFO hypothesis and the ACP `stack "FileName,Sha1" ...` command you'd run across 500 hosts to surface every infected box.
6. **(Stretch) Add a host, watch Count move.** Use `get-data.sh` (or copy a `WORKSTATION` CSV under a new name) to add a fourth host, re-run Stack 1, and watch a `Count` change. That's stacking earning its keep.

## Answers / what to find
- The outlier is **`coreupdater.exe`** in `C:\Windows\System32\`: empty `ProductName`/`Version`, **7,168 bytes**, `IsOsComponent=False`, **SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`**, and **Count = 1** across hosts — the Case 001 malware. Its 2010 LinkDate is **not** a reliable indicator (genuine MS files here have wilder dates).
- It appears in **Amcache** (Module 3) and **Prefetch** (Module 1) but **not ShimCache** (Module 2): identity + execution without a "seen-by-shim" record.
- The LFO principle: across hosts you `stack` on `SHA1`; a hash on a tiny number of hosts is the lead list. Microsoft-signed System32 binaries with high counts are noise. Rarity finds candidates; metadata convicts.

## Sources & further reading
- **AppCompatProcessor** (the tool, by Matías Bevilacqua / formerly Mandiant): https://github.com/mbevilacqua/appcompatprocessor
- **Mandiant — "Caching Out: The Value of Shimcache for Investigators"** (the stacking/LFO mindset for AppCompat data): https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-value-of-shimcache-for-investigators/
- **SANS DFIR — frequency analysis / stacking** (the least-frequency-of-occurrence method) and the FOR508 curriculum: https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
- **Eric Zimmerman EZ Tools** (AppCompatCacheParser/AmcacheParser that produce ACP's input): https://ericzimmerman.github.io/
- **DFIR Madness — Case 001** (the real host's data): https://dfirmadness.com/the-stolen-szechuan-sauce/

## Pivot
- The SHA1 → drop into threat-intel / hunt every host's Amcache.
- The execution proof for this binary → **Module 1 (Prefetch)** shows `COREUPDATER.EXE` ran on this host.
- From "what ran" to "what the attacker *did*" → **Part B (Modules 5-10)**, the event logs.

---
*Next: [Module 5 — Event Logs](../module-05-evtx-evtxecmd).*
