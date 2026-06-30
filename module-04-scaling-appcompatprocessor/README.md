# Module 04 — Scaling the Hunt with AppCompatProcessor

> **Tool spotlight.** This is the lab's deep-dive on **AppCompatProcessor (ACP)** by Matías Bevilacqua /
> Mandiant — the single most powerful way to turn *Application Compatibility* evidence (ShimCache +
> Amcache) from one box into a **fleet-wide hunt**. Earlier modules taught you to read ShimCache on one
> host (Module 02) and Amcache on one host (Module 03). Here you scale that to the whole enterprise and
> let the *frequency of execution across hosts* surface the intruder for you.
>
> **Scenario:** the realm of **Middle-earth Holdings** has been breached by **SAURON (APT-MORDOR)**. You
> have AppCompat collections from eight hosts. You do not yet know which are compromised. ACP will tell
> you. (Theme reference: [`THEME-MIDDLE-EARTH.md`](../THEME-MIDDLE-EARTH.md).)

---

## 1. Why this artifact, and why stacking

**Application Compatibility Cache (ShimCache / AppCompatCache)** and **Amcache** are two registry-borne
records of *programs that were present and/or executed* on a Windows host. They are gold for DFIR because
they survive deletion of the binary, and they record things attackers run. Their weakness on a *single*
host is noise: hundreds of legitimate entries surround the few malicious ones.

**The core idea ACP industrializes is frequency analysis ("stacking").** Across an enterprise, the same
software is everywhere — `explorer.exe`, `svchost.exe`, your EDR, Office — so it **stacks high**. An
intruder's tooling runs on one or a few hosts, so it **stacks low**. Sort the fleet's execution evidence
by how many hosts each program appears on, and the **rare tail is where the evil lives**. ACP adds the
plumbing to do this at scale: ingest many hosts, normalize, and run stacking, temporal correlation,
known-bad search, recon scoring, and timestomp detection on top.

> **Teaching caveat baked into this module:** *rare is not automatically evil.* A domain controller's
> `ntdsutil.exe` is rare across a workstation fleet but perfectly legitimate. Stacking **focuses** your
> attention; it does not make the judgement for you. You will see both legitimate-rare and malicious-rare
> in the same Count=1 band below, on purpose.

---

## 2. A note on running ACP on Windows (important)

ACP is written for Python 2 and was authored on Linux; upstream explicitly disabled Windows support
because its parallel loader and bundled multiprocessing logging **deadlock under Windows' `spawn`
process model**. This lab ships a **Windows-native build of ACP** so you can run the entire showcase in
the VM with no container and no Linux box. Two minimal, well-contained changes make it work (both applied
by [`tools/setup-acp-windows.ps1`](./tools/setup-acp-windows.ps1), and both leave the Linux behavior
untouched):

1. **Serial loader (`appLoadSerial`).** On Windows the loader runs its producer (parse) and consumer
   (DB insert) **inline in one process** instead of via the fork-based `mpEngineProdCons` engine. Same
   parsing, same SQL — no `spawn`/pickle deadlock.
2. **In-process search.** `appSearch`'s `Producer`/`Consumer` are `multiprocessing.Process` subclasses;
   on Windows we invoke their `.run()` **directly** (no child spawn, no cross-process pickling) — their
   queues all live in one process, so it just works.

It also needs the pure-Python **`python-registry`** package (the hive parser ACP's ShimCache/Amcache
readers rely on): `pip install python-registry`. The setup script installs it. In the prebuilt VM this is
already done; the commands below run as-is.

---

## 3. The data: an eight-host fleet

`data/fleet/` holds one ShimCacheParser-style CSV per host (the format ACP's `appcompat_csv` ingest
plugin reads; **the filename is the hostname**). The fleet:

| Host | Role | State |
|---|---|---|
| `RIVENDELL-WS01`, `GONDOR-WS02`, `ROHAN-WS03` | Workstations | clean baseline |
| `LOTHLORIEN-FS01` | File server | clean baseline |
| `EREBOR-SQL01` | SQL server | clean baseline |
| `ISENGARD-WS04` | Workstation | **compromised** — the insider `saruman.white`; lateral-movement launch point |
| `BAG-END-LT01` | Laptop | **compromised** — patient zero (`frodo.baggins`, phished) |
| `MINAS-TIRITH-DC01` | Domain controller | **compromised** — the crown jewel |

> **Instructor disclosure:** this fleet is a **synthetic teaching construct**. The benign baseline is a
> realistic common-software set; the SAURON toolkit is planted with a clear 2024-09-13/14 incident-window
> timestamp. It is generated reproducibly by [`tools/build_fleet_csvs.py`](./tools/build_fleet_csvs.py) —
> read it; it is documented and is itself part of the lesson (it shows exactly what "normal vs intrusion"
> looks like in this artifact). It is **not** the real case evidence used elsewhere in the lab.

---

## 4. Walkthrough

All commands run from the lab VM (Git Bash or PowerShell) in this module's folder. `vol`-style, ACP takes
a **database file** argument first, then a subcommand. We build a fresh DB from the fleet:

```
cd module-04-scaling-appcompatprocessor
python C:\DFIR\tools\appcompatprocessor\AppCompatProcessor.py acp.db load data/fleet
```

> On the VM a convenience wrapper `acp` is on PATH, so you can also just run `acp acp.db load data/fleet`.

### 4.1 Status — what did we ingest?

```
acp acp.db status
```
```
DB version: 0.9.1
Total hosts: 8
Total instances: 8
Total entries: 352
```
Eight hosts ingested. Now make the data work for you.

### 4.2 `stack` — the headline technique

```
acp acp.db stack FileName
```
Output (trimmed — read it bottom-up and top-down):
```
Count  What
1      netdom.exe            <- legit (DC tooling)        \
1      repadmin.exe          <- legit (DC replication)     |  the RARE TAIL:
1      ntdsutil.exe          <- legit (DC AD database)     |  legitimate-rare
1      dns.exe / dsac.exe / ismserv.exe / srmhost.exe ...  |  AND malicious-rare
1      sqlservr.exe / SQLCMD.EXE / Ssms.exe  <- legit (SQL)|  share this band --
1      putty.exe             <- legit-ish                  |  you must triage it
1      balrog.exe            <- EVIL (DC payload)          |
1      morgul.dll            <- EVIL (NTDS theft)          |
1      mordor-update.exe     <- EVIL (fake updater)        |
1      theonering.exe        <- EVIL (dropper)             |
1      gollum.exe            <- EVIL (temp stager)        /
2      dfsrs.exe             <- legit (DC + file server)
2      nazgul.exe            <- EVIL, on TWO hosts  ... lateral movement
2      palantir.exe          <- EVIL, on TWO hosts  ... C2 spread ISENGARD -> MINAS-TIRITH
4      Acrobat.exe
5      Teams.exe
8      explorer.exe / svchost.exe / kernel32.dll / msedge.exe / ...  <- the benign WALL
9      lsass.exe
```
**Read this like an analyst:**
- The **Count=8 wall** is your enterprise baseline — present everywhere, almost certainly fine.
- The **Count=1/2 tail** is your worklist. Here it contains both legitimate role-specific tools (the DC
  and SQL utilities) **and** the entire SAURON toolkit. You triage the tail; you don't trust it.
- **`palantir.exe` and `nazgul.exe` at Count=2 are a gift:** a non-baseline binary on *exactly two* hosts
  is the classic signature of **lateral movement** — something spread from one box to another. That is
  your thread to pull.

### 4.3 `search` — ACP's built-in known-bad intel

ACP ships a curated known-bad signature set (`AppCompatSearch.txt`, ~98 patterns: staging dirs, LOLBins
in odd places, recon tools, etc.). Run it with no regex:

```
acp acp.db search
```
```
Searching for known bad list: AppCompatSearch.txt (98 search terms)
Search hits: 1
[Staging perf.] MINAS-TIRITH-DC01  2024-09-14 02:09:48  C:\PerfLogs\balrog.exe  1340416  True
```
With **zero IOCs from you**, ACP flagged `C:\PerfLogs\balrog.exe` on the DC — its rule for *executables
staged in `C:\PerfLogs\`* (a well-known attacker drop spot) fired. This is the "free win" of the bundled
intel.

### 4.4 `search -f` — hunt your own IOCs

Once you have a lead (the Count=2 outliers, the PerfLogs hit), sweep the fleet for the whole toolkit:

```
acp acp.db search -f "palantir|nazgul|theonering|gollum|balrog|morgul|mordor-update"
```
```
Search hits: 18
BAG-END-LT01      ... C:\Users\frodo.baggins\Downloads\theonering.exe
BAG-END-LT01      ... C:\Users\frodo.baggins\AppData\Local\Temp\gollum.exe
ISENGARD-WS04     ... C:\ProgramData\palantir.exe
ISENGARD-WS04     ... C:\Windows\Temp\nazgul.exe
ISENGARD-WS04     ... C:\Users\saruman.white\AppData\Roaming\mordor-update.exe
MINAS-TIRITH-DC01 ... C:\Windows\Temp\palantir.exe / nazgul.exe / NTDS\morgul.dll / PerfLogs\balrog.exe
```
Now the **scope of compromise** is concrete: three hosts, with paths that tell the story (Downloads →
Temp on patient zero; ProgramData/AppData on the insider; Temp/NTDS/PerfLogs on the DC).

### 4.5 `filehitcount` — how widespread is one file?

```
acp acp.db filehitcount evilnames.txt    # evilnames.txt contains: palantir.exe
```
```
FileName      HitCount
palantir.exe  4
```
Four execution records of the C2 beacon across the fleet — a quick prevalence check for any indicator.

### 4.6 `tcorr` — temporal correlation (the pivot that finds what you missed)

Given one known-bad file, **what else executed around the same time on the same hosts?** This is how you
discover tooling you didn't have an IOC for.

```
acp acp.db tcorr palantir.exe
```
```
AppCompat temporal execution correlation candidates for palantir.exe:
nazgul.exe          Before:4  ...  <- the rest of the toolkit
morgul.dll          Before:2
balrog.exe          Before:2
mordor-update.exe   Before:2
repadmin.exe        After:2   ...  <- DC recon/replication abused right after
dsac.exe            After:2
netdom.exe          After:2
```
Pivoting from one beacon, ACP surfaces the **entire kill chain clustered in time**: the other implants
*and* the legitimate DC tools (`repadmin`, `dsac`, `netdom`) the attacker abused for recon/DCSync right
after landing. That `repadmin`/`netdom` burst immediately after `palantir` is your DCSync story.

### 4.7 `tstack` — stack a time window (the intrusion timeline)

Stack only what executed inside the incident window:

```
acp acp.db tstack 2024-09-13 2024-09-15
```
```
FullPath          Hits In  Hits Out  Ratio
nazgul.exe        4        0         40.000
palantir.exe      4        0         40.000
balrog.exe        2        0         20.000
gollum.exe        2        0         20.000
mordor-update.exe 2        0         20.000
morgul.dll        2        0         20.000
theonering.exe    2        0         20.000
```
Every binary whose execution is **entirely inside** the window (Hits Out = 0) is, by construction,
incident-relevant. The SAURON toolkit pops out cleanly; baseline software (which also ran on other days)
does not. This is time-boxing the hunt.

### 4.8 `reconscan` — which hosts did the most looking-around?

```
acp acp.db reconscan
```
```
Total number of potential recon commands detected: 122
Total number of hosts with potential recon activity: ... scored per host
```
`reconscan` tallies execution of reconnaissance-associated tools (`whoami`, `net`, `ipconfig`,
`tasklist`, `nltest`, `dsquery`, …) and scores hosts so you can rank where an operator was actively
enumerating. Combined with the stack, it points you at the hosts that had hands-on-keyboard.

---

## 5. The SAURON toolkit — what each file is and does

| File | What it actually is | Where it landed | LOTR rationale |
|---|---|---|---|
| `theonering.exe` | First-stage **dropper / persistence** ("always comes back") | `BAG-END-LT01` `\Downloads\` | The One Ring — the seed of it all |
| `gollum.exe` | Stealthy **%TEMP% stager** | `BAG-END-LT01` `\AppData\Local\Temp\` | Gollum — creeps unseen, "my precious" |
| `palantir.exe` | **Recon + C2 beacon** | `ISENGARD-WS04` → `MINAS-TIRITH-DC01` | The seeing-stone — see far, be tasked from afar |
| `nazgul.exe` | **Lateral-movement / remote-exec** | `ISENGARD-WS04`, `MINAS-TIRITH-DC01` | The Nine — hunt host to host |
| `mordor-update.exe` | Fake **"software updater" persistence** | `ISENGARD-WS04` `\AppData\Roaming\` | Mordor disguised as benign |
| `morgul.dll` | **Credential / NTDS theft** (DCSync) | `MINAS-TIRITH-DC01` `\Windows\NTDS\` | The Morgul-blade — poisons the realm's keys |
| `balrog.exe` | **Heavy end-objective payload** | `MINAS-TIRITH-DC01` `\PerfLogs\` | The Balrog — deep and powerful; "you shall not pass" (it did) |

---

## 6. How/why the techniques work (deeper)

- **ShimCache stores a path, a last-modified time, and an "executed" flag** (and on older Windows, an
  update time). It is written at shutdown, which is why it is a *presence* record more than a precise
  execution clock. ACP's `stack`/`search` lean on the path+name; `tcorr`/`tstack`/`tstomp` lean on the
  timestamps.
- **Stacking works because attacker tooling is, by definition, not enterprise-standard software.** The
  math is just "count of distinct hosts per program." Its power is entirely in having *many* hosts —
  hence a *fleet* tool. One host can't stack.
- **`tcorr` works because operators move fast:** the implants and the abused LOLBins execute within a
  tight window, so "what ran near my known-bad" reconstructs the kill chain even for components you had
  no signature for.
- **`tstack` works because incidents are time-bounded:** restricting the stack to the window removes
  years of benign history and leaves the intrusion.
- **`tstomp`** (run `acp acp.db tstomp`) hunts **timestomping**: files *outside* `System32` whose
  modified time matches a real `System32` binary on the same host — a classic evasion where malware
  copies a system file's timestamps. It is validated and runs cleanly; on this CSV fleet it reports no
  hits (ShimCache CSVs don't carry the secondary timestamps it keys on — feed it raw hives, e.g. the
  Module 02 SYSTEM hive, to see it flag a planted timestomp).

---

## 7. Try it yourself

1. `acp acp.db load data/fleet` then `acp acp.db stack FileName` — find the Count=1/2 tail.
2. Without peeking at Section 5, decide which Count=1 entries are *legitimate-rare* (role tools) vs
   *malicious-rare*. Justify each by **path** (`\PerfLogs\`, `\Temp\`, `\Downloads\` vs `\System32\`).
3. `tcorr palantir.exe` — list every file that correlates and label it implant vs abused-LOLBin.
4. `tstack 2024-09-13 2024-09-15` — write the one-paragraph intrusion timeline.
5. Bonus: regenerate the fleet with your own planted tool in `tools/build_fleet_csvs.py` and confirm it
   falls into the rare tail.

---

## 8. Sources & further reading

- AppCompatProcessor — Bevilacqua / Mandiant: https://github.com/mbevilacqua/appcompatprocessor
- Mandiant, *Leveraging the Application Compatibility Cache in Forensic Investigations* (ShimCache).
- Microsoft / Eric Zimmerman, AppCompatCacheParser & AmcacheParser (single-host parsers, Modules 02–03).
- MITRE ATT&CK: T1055-adjacent staging, **T1003.006** (DCSync), **T1070.006** (Timestomp), **T1021**
  (Lateral Movement), **T1057/T1018** (Recon).

> **Honesty note:** the Count=3-style baseline bands and the planted SAURON toolkit are a constructed
> teaching dataset (Section 3). The ACP tool, its commands, and its outputs are **real** — everything
> above was produced by running this exact build of ACP on this exact fleet in the lab VM.
