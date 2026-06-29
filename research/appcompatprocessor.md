# Research — AppCompatProcessor (Scaling ShimCache/Amcache Across Many Hosts)

> **Status in `dfir-aio:v2`:** PRESENT BUT NOT ON `PATH`, and **PYTHON 2 ONLY** — important caveat. The code is at `/opt/appcompatprocessor/AppCompatProcessor.py`. It is **Python 2** (`print "…"` statements), so it **fails under the default `python3`**. The container *does* ship a Python 2 at `/usr/local/bin/python2`, and the tool **runs correctly there**: `python2 /opt/appcompatprocessor/AppCompatProcessor.py -h` works (reports **Beta 0.9.1 [2020-05-11]**). **Recommended container fix:** add a `PATH` wrapper (`#!/usr/bin/env bash; exec python2 /opt/appcompatprocessor/AppCompatProcessor.py "$@"`) and `pip2 install termcolor python-Levenshtein psutil` so the `tstomp`/`leven` features and colour output work. Verified on rick 2026-06-29.

---

## 1. What it is and the forensic question it answers

**AppCompatProcessor** (by Matías Bevilacqua / Mandiant) takes the single-host execution-evidence artifacts — **AppCompatCache (ShimCache)** and **Amcache** — from **many hosts at once** and lets you **hunt across the whole fleet**. It answers the enterprise-scale question the per-host tools (AppCompatCacheParser, AmcacheParser, RegRipper) cannot: **"Across hundreds of machines, which executable is the anomaly — the one weird binary that appears on only one or two hosts, runs from a suspicious path, or stands out statistically?"**

It is purpose-built for the IR reality that an attacker's tool is *rare* in a large environment, while legitimate software is *common everywhere*. By loading every host's ShimCache/Amcache into one database, AppCompatProcessor surfaces rarity, suspicious paths, anti-forensic timestamps, and reconnaissance/lateral-movement tooling at scale.

---

## 2. How it works under the hood (plain language)

1. **Ingest:** it reads ShimCache (from `SYSTEM` hives) and Amcache (`Amcache.hve`) — and can also ingest pre-parsed CSV/text — from a directory tree of per-host artifacts, and **loads them all into a single SQLite database** (one `database_file` you create with `load`).
2. **Normalise:** every entry becomes a row keyed by **host + full path + timestamps + (Amcache) SHA1**, so the same binary across hosts is comparable.
3. **Analytics modules** then run *across all hosts* in that DB:
   - **Stacking / frequency** — count how many hosts each path/filename appears on. **Least-frequent = most suspicious** (the "stack the data, look at the bottom" technique).
   - **Search / fsearch** — regex/keyword hunt for known-bad names, paths (e.g. `\\Temp\\`, `\\PerfLogs\\`, `\\$Recycle`), or LOLBins across the fleet.
   - **`tstomp`** — flag **timestomping**: ShimCache/Amcache entries whose timestamps are inconsistent (e.g. impossible ordering), catching attackers who backdate binaries.
   - **`tcorr` / `ptcorr`** — **temporal correlation**: find files that appear *around the same time* across hosts (a tool pushed during lateral movement leaves correlated entries).
   - **`reconscan` / `fevil` / `precon`** — built-in knowledge bases of **recon commands** and known-evil patterns to auto-flag attacker reconnaissance (`whoami`, `net group "domain admins"`, `nltest`, `tasklist`, etc.) and malicious indicators.
   - **`leven`** — **Levenshtein** edit-distance to catch **masquerading/typosquatting** filenames (`svch0st.exe` vs `svchost.exe`).
   - **`filehitcount` / `stack` / `tstack`** — frequency tables for paths/timestamps.

Because the heavy lifting is a SQLite DB, you `load` once and run many fast queries.

---

## 3. The CLI (run via `python2`)

```bash
python2 /opt/appcompatprocessor/AppCompatProcessor.py -h
```
General form:
```bash
python2 AppCompatProcessor.py [global-opts] <database_file> <command> [command-opts]
```
| Global flag | Purpose |
|---|---|
| `--maxCores N` | parallel worker count (it has a multiprocessing engine). |
| `-o OUTPUTFILE` | write results to a file. |
| `-r` | (reload/append behaviour depending on command). |
| `-v` / `--version` | verbose / version. |

### Commands (the `{…}` subcommands)
`load, status, list, dump, search, fsearch, filehitcount, tcorr, ptcorr, tstomp, tstack, stack, leven, reconscan, precon, fevil, hashsearch, testset`

### Realistic workflow
```bash
cd /opt/appcompatprocessor

# 1. Build the database from a tree of per-host artifacts
#    (e.g. ./hosts/<HOSTNAME>/SYSTEM  and  Amcache.hve, or pre-parsed outputs)
python2 AppCompatProcessor.py case.db load ./hosts/

# 2. Sanity check what loaded
python2 AppCompatProcessor.py case.db status
python2 AppCompatProcessor.py case.db list Hosts        # hosts ingested

# 3. Stack filenames — rarest at the bottom = leads
python2 AppCompatProcessor.py case.db stack FilePath
python2 AppCompatProcessor.py case.db filehitcount      # per-file host counts

# 4. Hunt suspicious paths/names across the fleet
python2 AppCompatProcessor.py case.db search "\\\\Temp\\\\|\\\\PerfLogs\\\\|\\\\Public\\\\"
python2 AppCompatProcessor.py case.db fsearch "psexec|mimikatz|cobalt|rclone"

# 5. Auto-hunt attacker behaviour with the built-in knowledge bases
python2 AppCompatProcessor.py case.db reconscan          # recon-command indicators
python2 AppCompatProcessor.py case.db fevil              # known-evil patterns
python2 AppCompatProcessor.py case.db precon             # pre-defined recon set

# 6. Anti-forensics + masquerading
python2 AppCompatProcessor.py case.db tstomp            # timestomped entries
python2 AppCompatProcessor.py case.db leven svchost.exe # near-miss masquerades

# 7. Correlate timing across hosts (lateral movement)
python2 AppCompatProcessor.py case.db tcorr <reference>
```

---

## 4. Reading the output

- **`stack`/`filehitcount`**: a path present on **1–2 of 300 hosts** is a prime lead; ubiquitous Microsoft paths are noise. This is the core "rare = suspicious" output.
- **`reconscan`/`fevil`**: each hit is a host+entry matching an attacker-behaviour signature — e.g. a host where `net.exe`/`whoami.exe`/`nltest.exe` recon clustered, or a known tool name. These are starting points, not verdicts.
- **`tstomp`**: lists entries with impossible/inconsistent timestamps — strong anti-forensic indicators; pivot to that host's full timeline.
- **`leven`**: returns filenames within a small edit distance of a legit binary — classic masquerading.
- Pivot any lead back to the **single-host** tools (this lab's modules 1–3: Prefetch, ShimCache, Amcache) and the host's EVTX for confirmation.

---

## 5. Common pitfalls

- **Python 2 only (the big one).** Under `python3` it dies with a `SyntaxError` on `print`. Use `python2`. (Flag to container maintainers: add a `python2` wrapper on PATH.)
- **Optional modules disabled by default in the container:** `termcolor` (colour), `python-Levenshtein` (the `leven` command's speed), `psutil` (memory governor), `faker` (unit tests) are reported missing. `pip2 install` them for full functionality; core hunting still works without.
- **Input layout matters:** `load` expects artifacts arranged so it can attribute each to a host. Get the directory/host structure right or hosts collapse together. Check with `status`/`list Hosts`.
- **ShimCache caveat carries over:** ShimCache proves the OS *saw* a binary, **not** that it executed (order ≠ execution on all OS versions). Interpret accordingly; corroborate with Prefetch/Amcache/EVTX.
- **Beta software (0.9.1, 2020):** unmaintained-ish; expect rough edges. Validate surprising results against the raw artifacts.
- **Scale = noise.** Tune searches; start from rarity/known-evil, not broad dumps.

---

## 6. Where it fits a DFIR investigation

AppCompatProcessor is the **"scale the hunt" stage** — exactly the role of the lab's module 4. After you understand the single-host execution Triad (Prefetch/ShimCache/Amcache, modules 1–3), this tool applies the **same artifacts across an entire environment** to find patient-zero and the spread: the rare binary, the masqueraded name, the timestomped dropper, the recon burst, the temporally-correlated tool push of lateral movement. It turns per-host evidence into enterprise-wide attacker tracking and is a natural lead-generator for which hosts deserve deep, single-host analysis next.

---

## 7. Sources
- AppCompatProcessor repo (Matías Bevilacqua / Mandiant) — https://github.com/mbevilacqua/appcompatprocessor (README, command reference, knowledge-base files `reconFiles.txt`/`AppCompatSearch.txt`).
- Mandiant/FireEye blog — "AppCompatProcessor" release post (rarity-stacking, recon detection methodology).
- Mandiant ShimCache/Amcache white papers (Mandiant "Caching Out: The Value of Shimcache") — the artifacts AppCompatProcessor scales.
- SANS FOR508 — ShimCache/Amcache at scale and frequency-of-occurrence (stacking) hunting.
- This lab modules 02 (ShimCache) and 03 (Amcache) for the single-host artifact background.
