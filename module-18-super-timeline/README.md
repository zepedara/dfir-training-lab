# Module 18 — The Super Timeline: correlating filesystem + event-log activity in one view

**Deck mapping:** *Intrusion Hunting Playbook* → "The super-timeline: one clock for every artifact" (the capstone timelining technique that sits above every single-artifact module).
**Goal:** take two artifacts you already parsed in earlier modules — the **`$MFT`** filesystem table (Module 15) and a folder of **Windows event logs** (Module 05) — normalize each source's timestamps to a common column, **merge them into one time-sorted CSV**, and then *read across sources*: pivot on a single keyword and watch filesystem events and event-log events line up on the same clock. This is the backbone of the FOR508 timeline methodology, built here from scratch so you can see exactly what a super-timeline *is*.

> **Evidence note.** This module creates **no new evidence and runs nothing dangerous.** It *reuses inert artifacts already in the lab*: the `$MFT` carved in [Module 15](../module-15-filesystem-timeline) and the `.evtx` logs parsed in [Module 05](../module-05-evtx-evtxecmd). A one-time helper (`data/get-data.sh`) copies those two sets into this module's `evidence/` folder — that copy is **already staged for you**, so every runnable command below works out of the box. Because the two artifact sets come from **two different lab scenarios** (the Case-001 disk and the MSEDGEWIN10 log set), the merged result here demonstrates the *technique*, not a single unified host story — knowing that about your own evidence is itself the DFIR discipline this lab keeps drilling.

---

## 1. Background — what a "super timeline" is, and why it wins

Every artifact a Windows machine leaves behind carries **timestamps**: a file's `$MFT` record has its MACB times, an event-log record has its `TimeCreated`, a registry key has its `LastWrite`, a Prefetch file has its last-run times. In the earlier modules you read each of those artifacts **one at a time**, in its own tool, in its own CSV. That answers "what does *this* artifact say?" — but an intrusion is never confined to one artifact. The real questions are cross-artifact:

> *A suspicious executable was created on disk at 09:12:33. What event-log activity happened in the sixty seconds around it? Did a process start? A service install? A logon? A PowerShell script block?*

You cannot answer that by flipping between six spreadsheets that each sort on their own clock. A **super timeline** answers it by putting **every artifact's events onto one shared clock** — one file, one `Time` column, sorted ascending — so that filesystem activity and event-log activity **interleave in true chronological order**. Now a single scroll (or a single keyword filter) shows you the file creation *and* the process launch *and* the logon that all belong to the same moment. Correlation stops being detective work you do in your head and becomes something you can *see*.

That merged, cross-source, time-sorted view is the **super timeline**, and building/reading it is the core skill of SANS FOR508's timeline methodology.

### How this differs from Module 15
[Module 15](../module-15-filesystem-timeline) also built a "timeline," but a **single-source** one: it dumped the `$MFT`/`$UsnJrnl` to a filesystem timeline and read *that* in isolation. Powerful — it caught a timestomp — but it only ever saw the **filesystem**. This module takes the **next step up**: it keeps that filesystem timeline as *one input* and **combines** it with a second, completely different source (the event logs), so you can pivot across layers. Module 15 = the spine; Module 18 = the whole skeleton on one clock.

---

## 2. The approach — parse each source to CSV, then normalize + merge on time

A super timeline is built in two conceptual moves, and they map one-to-one to the tools here:

1. **Parse each artifact source into a flat CSV** with its native tool. Each tool already emits a per-record table with a timestamp column — you just don't yet have them in *one* place:
   - the **`$MFT`** → **MFTECmd** → a filesystem-timeline CSV (one row per file record, timestamp in `LastModified0x10`).
   - the **`.evtx` logs** → **EvtxECmd** → an event-timeline CSV (one row per event record, timestamp in `TimeCreated`).
2. **Normalize and merge.** Every source names its time column differently and describes its events differently, so you pick *one* timestamp column per source, map each to a common schema (`Time, Source, Description`), concatenate all the rows, and **sort by `Time`**. That sorted concatenation *is* the super timeline.

The merger in this module, **`merge_timeline.py`**, is a deliberately tiny, readable version of that second move. Its heart is a table of `(filename-glob, source-label, timestamp-column, description-columns)` tuples:

```
SOURCES = [
    ("*mft.csv",  "MFT",  "LastModified0x10", ["FileName", "ParentPath"]),
    ("*evtx.csv", "EVTX", "TimeCreated",      ["MapDescription", "PayloadData1", "Channel"]),
]
```

Read that as: *"for MFT CSVs, the clock is `LastModified0x10` and the human label is the file name; for EVTX CSVs, the clock is `TimeCreated` and the label is the event's mapped description."* It reads every matching CSV, emits one `(Time, Source, Description)` row per record, sorts on `Time`, and writes `super_timeline.csv`. **It is extensible on purpose:** to fold in another artifact you parsed elsewhere, add one tuple — e.g. `("*registry.csv", "REG", "LastWriteTimestamp", ["ValueName","KeyPath"])` for RegRipper/Registry Explorer output, or a Prefetch/browser-history CSV — and re-run. That one-line-per-source pattern is exactly how the production aggregators (Section 6) work, just scaled up.

> **Why keep everything in one time zone?** Merging only makes sense if the clocks agree. **EZ Tools (EvtxECmd/MFTECmd) emit UTC by default**, and this data is all UTC, so the sort is honest. (Note: EvtxECmd's `--sync` is unrelated to time zones — it just updates EvtxECmd's event Maps from GitHub.) On real evidence, the honest rule is: EZ Tools already emit UTC; for any source that *doesn't* — e.g. `mactime -z UTC` — **force UTC before merging**, or your interleave will be off by whatever the zone offsets are.

---

## 3. Setup

Open **Git Bash** on the lab VM. **MFTECmd**, **EvtxECmd**, and **`python3`** are installed **natively and already on your `PATH`** — call them by bare name (no `.exe`), exactly as in Modules 15 and 05. The VM is **offline**; nothing here touches the network.

The evidence is **already staged** in `evidence/` for you. For the record, this is the one-time step that put it there (you do **not** need to run it — shown only so you know where the artifacts came from):

```
# ONE-TIME evidence staging (already done for you — do NOT re-run):
#   cd module-18-super-timeline/data
#   sh get-data.sh
#     -> copies the $MFT from Module 15 + every .evtx from Module 05 into evidence/
#     -> prints:  evidence: MFT=yes evtx=36
```

Everything below runs from this module's `data` folder.

---

## 4. Step-by-step walkthrough

### Step 1 — Parse each source to a CSV
First turn the two raw artifact sets into two flat timelines. These are the **same invocations** you learned in Modules 15 and 05 — nothing new, we are just producing CSVs to merge.

```bash
cd module-18-super-timeline/data
MFTECmd -f evidence/MFT --csv out --csvf mft.csv
EvtxECmd -d evidence --csv out --csvf evtx.csv
```
- **`MFTECmd -f evidence/MFT`** — parse the single `$MFT` file (`-f` = one file). **`--csv out --csvf mft.csv`** writes the result to `out/mft.csv`.
- **`EvtxECmd -d evidence`** — parse a **directory** of logs (`-d`), merging every `.evtx` in `evidence/` into one table. **`--csv out --csvf evtx.csv`** writes `out/evtx.csv`.

**Real output (trimmed):**
```
MFTECmd:   FILE records found: 35 (Free records: 47)   ->  out/mft.csv
EvtxECmd:  Processed 36 files, 547 event records        ->  out/evtx.csv
```
**Read it:** you now hold two per-source timelines — **35 filesystem rows** (`out/mft.csv`, the `$MFT`) and **547 event-log rows** (`out/evtx.csv`, the merged `.evtx`). Each is sortable on its own, but they still live on **two separate clocks in two separate files**. That is the problem the next step fixes.

### Step 2 — Merge the two CSVs into one super timeline
```bash
python3 merge_timeline.py out
```
- **`merge_timeline.py out`** — point the merger at the folder holding the CSVs. It reads `out/mft.csv` and `out/evtx.csv`, normalizes each to `(Time, Source, Description)`, sorts on `Time`, and writes `out/super_timeline.csv`.

**Real output:**
```
merged super-timeline: 582 events -> out/super_timeline.csv
  span: 2019-03-15 08:34:19  ..  2026-06-29 20:14:07
```
**Read it:** **35 + 547 = 582** events are now on **one clock**, sorted, spanning **2019-03-15 → 2026-06-29**. That seven-year span across a 35-file table is itself a tell (Section 5). You have a super timeline.

### Step 3 — Read it: columns, then pivot on a keyword
A merged timeline is only useful if you can *read across* it. Start by confirming the schema, then filter it the way you'd filter any timeline — on a keyword — and watch **both sources** answer at once.

```bash
head -1 out/super_timeline.csv
grep -i coreupdater out/super_timeline.csv
```
- **`head -1`** — print the header row so you know the three columns.
- **`grep -i coreupdater`** — case-insensitively pull every row mentioning the backdoor, *regardless of which source it came from.*

**Real output:**
```
Time,Source,Description
2019-03-15 12:00:00.0000000,MFT,coreupdater.exe
```
**Read it:** the header confirms the common schema — **`Time, Source, Description`** — and the keyword pull surfaces the `coreupdater.exe` filesystem row instantly, tagged with its `Source` (`MFT`) so you always know which artifact each line came from. In this dataset the backdoor lives only on the filesystem side; had the same binary also *executed* on the MSEDGEWIN10 host, its Sysmon/Security rows would appear right underneath it — **same keyword, both sources, one filtered view.** That is the whole payoff: one `grep`, every artifact that mentions the thing, in time order.

To *see* the two sources interleave, open `out/super_timeline.csv` in a spreadsheet (or `Timeline Explorer`) and scroll — filesystem `MFT` rows and event-log `EVTX` rows sit shoulder-to-shoulder on the shared clock:
```
Time                          Source  Description
2019-03-15 08:34:19.1234567   MFT     cmd.exe
2019-03-15 12:00:00.0000000   MFT     coreupdater.exe
2019-04-...                   EVTX    A new process has been created
2020-...                      EVTX    BITS transfer has started
...
2026-06-15 09:10:05.3312044   MFT     update.ps1
2026-06-29 20:14:07.xxxxxxx   EVTX    PowerShell script block logged
```
That interleaving — a filesystem create adjacent to the event-log activity around it — is the entire reason a super timeline exists.

> **Load everything into Timeline Explorer.** Every CSV here — `mft.csv`, `evtx.csv`, and the merged `super_timeline.csv` — opens directly in Eric Zimmerman's **Timeline Explorer** (grouping, colour rules, full-text filter, bookmarking). Analysts usually *build* the merged CSV on the command line and then *read* it in Timeline Explorer, filtering to the incident window and colour-flagging the source column.

---

## 5. Reading the output — what the merged view reveals

| Signal in `super_timeline.csv` | How to see it | Why it matters |
|---|---|---|
| **`Source` column** | present on every row (`MFT` / `EVTX`) | tells you *which artifact* vouches for each event — corroboration is "same moment, two sources" |
| **Interleaving on `Time`** | scroll / sort ascending | a file create sitting inside a burst of event-log rows = the cross-artifact story of one action |
| **Keyword hitting >1 source** | `grep -i <name>` | one filter surfaces filesystem **and** log evidence of the same object |
| **A wide time span on few rows** | the `span:` line | `2019 … 2026` across 35 files hints at **timestomping** (a 2019 date parked next to 2026 activity) |
| **Density clusters** | rows bunching in a few seconds | real attacker actions cluster; isolate the window, then read every source in it |

**Triage discipline:** the merged timeline does not *judge* — it *arranges*. A 2019 row is not automatically evil (real OS files are old — that is Module 15's `win32k.sys` control). What the super timeline gives you is **adjacency**: it puts the questionable file next to the log activity of its moment so you can decide with context instead of guessing. The 2019-vs-2026 spread you see here is the same timestomp tell Module 15 proved at the `$SI`-vs-`$FN` level — on the merged timeline it shows up as a lone ancient date sitting in an otherwise-2026 story.

> **A third filesystem source — the USN journal.** MFTECmd doesn't only parse the `$MFT`; it also parses **`$J` / `$UsnJrnl`**, the change journal, which records per-change **USN reason codes** (file create, rename, data-overwrite, delete). That makes it a natural *third* timeline input — add it with one more `SOURCES` tuple exactly as you would registry or Prefetch. It also closes a blind spot: the `Time` column here is `LastModified0x10`, i.e. **`$SI`** — the same `$Standard_Information` timestamp an attacker can **timestomp**. A super-timeline built only on `$SI` inherits `$SI`'s spoofability, so when a date looks wrong, pull **`$FN`** (`$File_Name`, kernel-only-writable) and the `$J` rename/create records to confirm the real order of events.

---

## 6. Where this goes in production — the tools that automate the merge

`merge_timeline.py` is the **from-scratch teaching version** so the mechanic is transparent. In real casework you use an aggregator that does the same `(glob → source → time-column → description)` mapping across *dozens* of artifact types automatically:

- **forensic-timeliner** (<https://github.com/acquiredsecurity/forensic-timeliner>) — the modern, **EZ-native** super-timeline builder. Point it at a folder of **EZ Tools / KAPE / Chainsaw / Hayabusa** CSVs and it normalizes and merges them into one Timeline Explorer-ready timeline. This is the direct, grown-up version of what you just did by hand — the same idea, every artifact type, one command.
- **KAPE `!EZParser` + the `Mini_Timeline` module** — KAPE parses a triage collection with the EZ tools, and its `Mini_Timeline` / `Mini_Timeline_Slice_by_Range` modules stitch the resulting CSVs into a combined timeline (optionally windowed to a date range). Mari DeGrazia's SANS webcast (Section 8) walks this end-to-end.
- **Plaso / log2timeline** (<https://plaso.readthedocs.io/>) — the **classic** super-timeline engine: `log2timeline.py` ingests a huge range of sources into a storage file and `psort.py` sorts/filters it. It is the reference tool for this technique, but it has **no maintained Windows binaries** (native Windows builds were discontinued ~2020) — it runs via Docker or a Python install, and isn't on the lab VM. That is precisely why this lab teaches the merge the **EZ-native way** — MFTECmd/EvtxECmd → CSV → merge → Timeline Explorer — which runs anywhere the EZ tools do.

Frame it this way: **Plaso is the classic all-in-one, forensic-timeliner/KAPE are the EZ-native automations, and `merge_timeline.py` is the ten-line version that shows you what all three are actually doing** — parse per source, normalize on a time column, sort.

---

## 7. Try-it-yourself exercises

1. **Confirm the arithmetic.** After Step 1, run `wc -l out/mft.csv out/evtx.csv` and `wc -l out/super_timeline.csv`. Show that the merged row count equals the two inputs' records combined (mind the header lines). Why is "no rows lost in the merge" a property you'd actually check on real evidence?
2. **Pivot the other way.** `grep -i desktopimgdownldr out/super_timeline.csv` (or `grep -i uguu out/super_timeline.csv`). Which `Source` do those rows carry, and why does *this* keyword hit EVTX while `coreupdater` hit MFT? What would it mean if a keyword hit **both**?
3. **Window it.** Using a spreadsheet or `grep`, isolate just the rows in **2026-06** and read them in order. Write the 3-line story that the merged filesystem + log rows tell for that window.
4. **Extend the merger.** Add a third `SOURCES` tuple to `merge_timeline.py` for a hypothetical `*registry.csv` (time column `LastWriteTimestamp`, description `["ValueName","KeyPath"]`), drop any Registry Explorer CSV into `out/`, and re-run. Confirm a new `REG`-tagged source now interleaves. This is *exactly* how you'd fold in Prefetch, Amcache, or browser history.
5. **Spot the timestomp on the timeline.** Find the earliest and latest rows in `super_timeline.csv`. Explain how a lone 2019 date sitting in an otherwise-2026 timeline is the *timeline-level* shadow of the `$SI`-vs-`$FN` timestomp you proved in Module 15.
6. **(Stretch)** Install/point **forensic-timeliner** or run KAPE's `Mini_Timeline` module at the same `out/` CSVs and compare its merged output to `super_timeline.csv`. What extra artifact types and columns does the production tool bring that the ten-line teaching merger does not?

---

## 8. Key takeaways

- A **super timeline** puts **every artifact's events on one shared clock**, sorted, so filesystem activity and event-log activity **interleave** — turning cross-artifact correlation from head-work into something you can *see* and *filter*.
- It is built in two moves: **parse each source to CSV** (MFTECmd for the `$MFT`, EvtxECmd for the `.evtx`), then **normalize + merge on a common timestamp column** and sort. `merge_timeline.py` is that second move in ten readable lines.
- The merger is **extensible by design** — one `(glob, source, time-column, description)` tuple per artifact type. Add registry, Prefetch, Amcache, or browser CSVs the same way.
- Keep every source in **one time zone (UTC)** before merging, or the interleave is a lie.
- Module 15 built a **single-source** filesystem timeline; this module **combines sources** — the same technique the whole FOR508 timeline methodology rests on.
- In production the merge is automated by **forensic-timeliner** and **KAPE's `Mini_Timeline`** (EZ-native) or the classic **Plaso/log2timeline** (no maintained Windows binaries — runs via Docker/Python, hence the EZ approach here). All of them do exactly what you just did by hand.

---

## 9. Sources & further reading

- **forensic-timeliner** — the EZ-native super-timeline aggregator (EZ / KAPE / Chainsaw / Hayabusa CSVs → one Timeline Explorer timeline): <https://github.com/acquiredsecurity/forensic-timeliner>
- **KAPE** — Eric Zimmerman: the `!EZParser` + `Mini_Timeline` / `Mini_Timeline_Slice_by_Range` modules that build the combined timeline: <https://ericzimmerman.github.io/KapeDocs/>
- **SANS webcast — "Triage Collection and Timeline Generation with KAPE"** (Mari DeGrazia) — collecting a triage image and generating the mini-timeline end-to-end: <https://www.sans.org/webcasts/triage-collection-timeline-generation-kape/>
- **13Cubed (Richard Davis) — "Introduction to MFTECmd"** — parsing the `$MFT` to the CSV that feeds the filesystem half of the timeline: <https://www.youtube.com/watch?v=Svff0Fj5Xgc> · channel: <https://www.13cubed.com/>
- **AboutDFIR — Timeline Explorer** (loading, filtering, colour rules, bookmarking merged CSVs): <https://aboutdfir.com/toolsandartifacts/windows/timeline-explorer/>
- **Eric Zimmerman tool docs** — MFTECmd, EvtxECmd, Timeline Explorer (usage, columns, the Maps model): <https://ericzimmerman.github.io/>
- **Plaso / log2timeline** — the classic super-timeline engine (`log2timeline.py` + `psort.py`; no maintained Windows binaries since ~2020 — runs via Docker or a Python install): <https://plaso.readthedocs.io/>
- **SANS FOR508** — the super-timeline / timeline-analysis methodology this module distils.
- **MITRE ATT&CK — T1070.006 (Indicator Removal: Timestomp)** — the anti-forensic technique that makes a *cross-source* timeline necessary (a faked `$SI` date is exposed the moment it sits next to real event-log activity): <https://attack.mitre.org/techniques/T1070/006/>

---
*This is an advanced add-on module. Prerequisites — the two source modules it merges: [Module 05 (EvtxECmd)](../module-05-evtx-evtxecmd) and [Module 15 (Filesystem Timeline)](../module-15-filesystem-timeline). It generalises the single-source timeline of Module 15 into the multi-source technique the [Capstone](../module-11-capstone) leans on.*


---

## Sources

- **Plaso / log2timeline / psort (classic super-timeline engine)** — [Plaso documentation — "super timeline all the things"](https://plaso.readthedocs.io/)
- **MFTECmd, EvtxECmd, Timeline Explorer (EZ Tools — parsing $MFT/.evtx to CSV, UTC output)** — [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
- **KAPE !EZParser + Mini_Timeline module (automated combined timeline)** — [KAPE Documentation (Eric Zimmerman)](https://ericzimmerman.github.io/KapeDocs/)
- **forensic-timeliner (EZ-native super-timeline aggregator across EZ/KAPE/Chainsaw/Hayabusa CSVs)** — [acquiredsecurity/forensic-timeliner (GitHub)](https://github.com/acquiredsecurity/forensic-timeliner)
- **Timeline Explorer (loading/filtering/colour-flagging merged CSVs)** — [AboutDFIR — Timeline Explorer](https://aboutdfir.com/toolsandartifacts/windows/timeline-explorer/)
- **Timestomp / $SI-vs-$FN anti-forensics (why cross-source timelining matters)** — [MITRE ATT&CK T1070.006 — Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- **SANS FOR508 timeline-analysis methodology (super-timeline concept)** — [SANS FOR508 — Advanced Incident Response, Threat Hunting and Digital Forensics](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/)
