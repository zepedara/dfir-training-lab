# Module 4 — Scaling the Hunt with AppCompatProcessor

**Deck mapping:** *Windows Execution Forensics* → "Scaling Execution Analysis" / "Stacking & Least-Frequency-of-Occurrence" · *Advanced Intrusion Forensic Hunting* → "Hunting at Enterprise Scale."
**Goal:** stop looking at **one** host. Take the **Triad artifacts (Amcache/ShimCache) from many hosts**, pile them together, and let the **rarest** thing float to the top — that single weird binary that exists on *one* box out of hundreds.

---

## Concept (from the deck)
On a single host you *read* artifacts. Across an enterprise you **stack** them. Two ideas:

- **Stacking:** group an attribute (filename, path, SHA1, parent directory…) across every host and **count** how often each value occurs.
- **Least-Frequency-of-Occurrence (LFO):** attacker tooling is, by definition, **rare** — it lives on the few boxes they touched. Sort the stack ascending and the **Count = 1** rows are your leads. Microsoft-signed binaries that exist on 5,000 hosts are noise; the unsigned 7 KB `coreupdater.exe` that exists on **one** host is the hunt.

**AppCompatProcessor (ACP)** (Matías Bevilacqua) is the purpose-built tool: it ingests AppCompat/Amcache from a folder of hosts into one SQLite DB, then runs `stack`, `search` (known-bad regex sweep), `leven` (typosquat detection like `svch0st.exe`), `tstomp` (timestomp candidates) and `tcorr` (temporal correlation: dropper → payload) across the whole set.

**Data (real, Case 001):** the parsed Triad output for one host — `DESKTOP-SDN1RPT` (the same host you worked in Modules 1–3):
- `shimcache_host-DESKTOP.csv` — 266 ShimCache entries (`AppCompatCacheParser` output).
- `amcache_host-DESKTOP_*.csv` — the full `AmcacheParser` set; the one you'll live in is `..._UnassociatedFileEntries.csv` (the file entries **with SHA1, Size, ProductName, Version, LinkDate**).

> **Why one host here?** The lab ships the one fully-documented intrusion (Case 001) so the exercise has *answers*. Stacking's payoff scales with host count — so this module teaches the **method** on real data you can verify, then shows the exact ACP commands you'd run when you have 50 or 5,000 hosts. `get-data.sh` documents how to add more hosts.

---

## Setup
```bash
cd module-04-scaling-appcompatprocessor/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

---

## Part 1 — Stacking by hand (works today, real data)
Stacking is just **group-and-count**. You already have the parsed CSVs, so the container's shell tools *are* a stacking engine. This is exactly what ACP automates — doing it by hand once makes the tool obvious.

### Stack 1 — "Which System32 executables have NO Microsoft metadata?"
Every genuine `C:\Windows\System32\*.exe` carries a `ProductName` (*"Microsoft® Windows® Operating System"*) and a `Version` (`10.0.19041.x`). Attacker binaries dropped into System32 usually don't. Stack the file entries and look at columns `FullPath` (6), `ProductName` (10), `Size` (11), `Version` (12):

```bash
cd /data
awk -F, 'NR>1 && tolower($6) ~ /system32/ && tolower($6) ~ /\.exe/ \
  {print $7"  | prod="$10" | size="$11" | ver="$12}' \
  amcache_host-DESKTOP_UnassociatedFileEntries.csv
```
**Expected output (real, Case 001):**
```
CompatTelRunner.exe  | prod=microsoft® windows® operating system | size=172184 | ver=10.0.19041.1
coreupdater.exe      | prod=                                     | size=7168   | ver=
csrss.exe            | prod=microsoft® windows® operating system | size=17592  | ver=10.0.19041.1
DeviceCensus.exe     | prod=microsoft® windows® operating system | size=37688  | ver=10.0.19041.1
svchost.exe          | prod=microsoft® windows® operating system | size=57368  | ver=10.0.19041.1
winlogon.exe         | prod=microsoft® windows® operating system | size=907776 | ver=10.0.19041.1
...
```
**Read it:** one row is naked — **`coreupdater.exe`**: empty `ProductName`, empty `Version`, **7,168 bytes** (every real System32 binary is bigger and signed), with a fake **2010-04-14** LinkDate. That's the **LFO outlier**. It is the Case 001 malware.

### Stack 2 — pull its identity (SHA1) for the cross-host hunt
```bash
grep -i coreupdater amcache_host-DESKTOP_UnassociatedFileEntries.csv | cut -d, -f4,6,9,11
```
```
fd153c66386ca93ec9993d66a84d6f0d129a3a5c,c:\windows\system32\coreupdater.exe,2010-04-14 22:06:53,7168
```
**SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`** is now your hunt key. In a real enterprise you'd stack *every host's* Amcache on `SHA1` and ask "how many hosts have this hash?" — LFO says the answer (a handful) names your victims.

### Stack 3 — where do executables live? (path stacking)
```bash
awk -F, 'NR>1{n=split($6,a,"\\"); $0=""; p=""; for(i=1;i<n;i++)p=p a[i]"\\"; print p}' \
  amcache_host-DESKTOP_UnassociatedFileEntries.csv | sort | uniq -c | sort -n
```
**Read it:** most executables sit in `C:\Windows\System32\` or `Program Files`. Anything in `Users\Public`, `ProgramData`, `Temp`, `AppData` with a **Count of 1** is a staging-location lead — the same instinct from Modules 2–3, now mechanised.

---

## Part 2 — AppCompatProcessor (the at-scale tool)
With many hosts you don't `awk` — you load everything into ACP once and query. The real commands:

```bash
# Load a folder of hosts (raw SYSTEM/Amcache hives, ShimCacheParser CSVs, or zips) into one DB:
python2 /opt/appcompatprocessor/AppCompatProcessor.py hosts.db load /data

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
The `stack` sort is ascending-by-count, so **the top rows are the rarest** — LFO, automated. `search` prints a histogram so you triage the loudest known-bad hits first; `leven` and `tstomp` are zero-knowledge anomaly finders that need no IOCs.

> **Container note (dfir-aio:v2):** ACP is Python 2 and its hive/Amcache ingest depends on `libregf`/`pyregf` + `Registry.py`, and `load` computes per-file MD5 instance IDs. The current `dfir-aio:v2` build is missing those native bits (and its py2 `hashlib` has no working `md5`), so `load` registers a host but ingests **0 entries** — i.e. ACP's loader is **not yet functional in this image**. That's why Part 1 above is the hands-on path. The commands in Part 2 are the correct production workflow; they run once the container ships `libregf`/`pyregf` + a working py2 `hashlib`. This is tracked against the **[dfir-aio container](https://github.com/zepedara/dfir-drop)**, not this lab. Until then, do your stacking with Part 1's shell recipes (or load the data on a host with a working ACP install).

---

## Exercises
1. **Find the outlier** with Stack 1 and explain *every* reason `coreupdater.exe` is suspicious (metadata, size, path, LinkDate). Confirm its SHA1.
2. **Triad gap:** `grep -i coreupdater shimcache_host-DESKTOP.csv` — is it in ShimCache? (It isn't.) It's in **Amcache (identity) but not ShimCache (seen)**. Explain what that tells you about how it got there, using the Module 3 triad table.
3. **Plan the cross-host hunt:** you now have SHA1 `fd153c66…`. Write the one-sentence LFO hypothesis and the ACP `stack "FileName,Sha1" ...` command you'd run across 500 hosts to surface every infected box.
4. **(Stretch)** Use `get-data.sh` to add a second host's Amcache CSV, re-run Stack 1/3, and watch a `Count` column become meaningful — that's stacking earning its keep.

## Answers / what to find
- The outlier is **`coreupdater.exe`** in `C:\Windows\System32\`: empty `ProductName`/`Version`, **7,168 bytes**, fake **2010-04-14** LinkDate, **SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`** — the Case 001 malware.
- It appears in **Amcache** (Module 3) but **not ShimCache** (Module 2): identity without a "seen-by-shim" record — consistent with a dropped/executed binary the OS inventoried but never shimmed.
- The LFO principle: across hosts you'd `stack` on `SHA1`; this hash on a tiny number of hosts is the lead list. Microsoft-signed System32 binaries with thousands of hits are noise.

## Pivot
- The SHA1 → drop into threat-intel / hunt every host's Amcache.
- The execution proof for this binary → **Module 1 (Prefetch)** shows `COREUPDATER.EXE` ran on this host.
- From "what ran" to "what the attacker *did*" → **Part B (Modules 5–10)**, the event logs.

---
*Next: [Module 5 — Event Logs](../module-05-evtx-evtxecmd).*
