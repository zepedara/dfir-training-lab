# Module 5 — Parsing Event Logs with EvtxECmd

**Deck mapping:** *Intrusion Hunting Playbook* → "The Investigation Lifecycle" / event-log foundations.
**Goal:** turn raw, hard-to-read `.evtx` binary logs into clean CSV you can sort, filter, and timeline — the foundation every later module builds on.

---

## Concept
Windows event logs (`.evtx`) are a binary format. Before you *hunt* them (Module 6) you often want the **raw events as a flat table** — to grep a username, sort by time, or feed a timeline. **EvtxECmd** (Eric Zimmerman) does exactly that, applying "maps" that turn cryptic event fields into labeled columns.

This module's sample is a **LOLBAS download** (`desktopimgdownldr.exe` abused to pull a file — a living-off-the-land technique).

---

## Setup
```bash
cd module-05-evtx-evtxecmd/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

## Step — Parse to CSV
```bash
EvtxECmd -d /data --csv /data --csvf events.csv
```
**Expected output:**
```
Command line: -d /data --csv /data --csvf events.csv
CSV output will be saved to /data/events.csv
Record # 1 (Event Record Id: 305352): In map for event 1, Property ...ParentUser not found! Replacing with empty string
...
```
> The `... not found! Replacing with empty string` lines are **normal** — EvtxECmd notes when a map expects a field a particular event didn't include. It still parses everything.

## Read the result
Open `events.csv` on your host. Key columns: `TimeCreated`, `EventId`, `Provider`, `Computer`, `PayloadData1..6`, `ExecutableInfo`. For this sample, look at the Sysmon **Event ID 1 (Process Creation)** rows — you'll see `desktopimgdownldr.exe` with a command line pulling a remote file (the LOLBAS abuse).

```bash
# inside the container, quick peek:
cut -d, -f2,4,5 /data/events.csv | head
```

## Why this matters
EvtxECmd gives you the **ground truth** events. Module 6's Sigma tools tell you *which* events are suspicious; EvtxECmd lets you **read the full context** around them and build a manual timeline when a rule doesn't exist for what you're chasing.

## Exercises
1. Parse a folder of mixed logs (`Security.evtx`, `Sysmon`, `PowerShell`) at once with `-d /data`.
2. Filter `events.csv` to just `EventId 1` (process creation) and read the command lines — spot the malicious one.
3. Add `--json /data` and compare; when is JSON more useful than CSV?

---
*Next: [Module 6 — Sigma Hunting](../module-06-sigma-chainsaw-hayabusa).*
