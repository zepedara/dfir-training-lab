# Module 7 — Identity & Credential Theft

**Deck mapping:** *Intrusion Hunting Playbook* → "Detecting Credential Theft & Misuse" / "Identity Context" · *Advanced Intrusion Forensic Hunting* → "Phase 2: Identity Analysis."
**Goal:** detect **credential dumping** (stealing passwords/hashes out of Windows) and read the **logon events** that reveal *who* used those credentials to move *where*.

---

## 1. Background — why this matters

### Credentials are the master key
Once an attacker can run code on one machine, breaking in again is tedious — unless they steal **credentials**. A credential is anything that proves "I am this user": a password, or more often its **hash** (a scrambled fingerprint of the password that Windows will accept in place of the password for many network logons — this is what makes **Pass-the-Hash** attacks possible). Steal an admin's credential and "one compromised laptop" becomes "the whole domain." That's why credential theft is the **hinge** of almost every serious intrusion.

### Where Windows keeps credentials — and how they get stolen
When you log in, Windows caches your credential material in the memory of a protected system process called **LSASS** (`lsass.exe` — the **Local Security Authority Subsystem Service**). LSASS is what checks your password and hands out the tickets/hashes used for network access. Because the secrets sit in LSASS's memory, the classic attack is to **read LSASS's memory and carve the secrets out**. The famous tool for this is **Mimikatz**. There are several ways attackers do it:
- **Mimikatz `sekurlsa::logonpasswords`** — opens `lsass.exe` and reads it directly.
- **`comsvcs.dll` MiniDump** — a LOLBAS trick: `rundll32.exe comsvcs.dll, MiniDump <lsass-pid> out.dmp full` makes a *signed Windows DLL* dump LSASS to a file, then the attacker carves it offline.
- **PowerShell `MiniDumpWriteDump`** — calls the same Windows API from a script.
- **DCSync** — different and sneakier: instead of touching LSASS, the attacker *asks a Domain Controller to replicate password data*, as if they were another DC. No malware on the DC at all.

### The two evidence sources (from the decks)
1. **Catch the dump.** With **Sysmon** installed, opening another process's memory is logged as **Sysmon Event ID 10 (ProcessAccess)**. When the *target* of that access is `lsass.exe`, you look at the **`GrantedAccess`** field — the exact memory-access rights that were requested. Certain values are a near-perfect fingerprint of dumping tools:

   | GrantedAccess | Meaning | Typical tool |
   |---|---|---|
   | `0x1010` | read memory + query info | Mimikatz `sekurlsa::logonpasswords` |
   | `0x1410` | adds duplicate-handle | ProcDump / Task Manager dump |
   | `0x143a` | broad read/query/VM rights | Mimikatz lsadump / Invoke-Mimikatz |

   > **Important nuance:** Sysmon compares `GrantedAccess` as a *literal string*, and tools tweak their flags over time, so these values are strong **leads**, not a complete allow/deny list. Modern Sigma rules also flag any *uncommon* access mask on LSASS regardless of the exact number. No legitimate everyday process needs to read LSASS's memory — so any of these on `lsass.exe` deserves immediate attention.

2. **Follow the logons.** After stealing a credential, the attacker *uses* it — and that produces **Security log logon events**. The key one is **Event ID 4624 (an account successfully logged on)**, whose **Logon Type** field tells you *how* they logged in:

   | Logon Type | Meaning | Why it matters to a hunter |
   |---|---|---|
   | **2** | Interactive (at the keyboard / console) | normal desktop login |
   | **3** | Network (accessing a share, etc. from another host) | how stolen creds reach across the network |
   | **9** | **NewCredentials** (`runas /netonly`) | a process kept your local identity but used *different* creds for the network — a classic **Pass-the-Hash** signal |
   | **10 / 11** | RemoteInteractive (**RDP**) / cached interactive | remote desktop / offline-cached logon |

   Companion events: **4625** (failed logon — brute force/spray), **4648** (a logon using *explicit* credentials — "run as this other account"), and **4672** (special/admin privileges assigned at logon — an admin logon).

### What you prove with all this
Tie the two together and you can prove the *spread*: "LSASS was dumped on host A at 14:49 (Sysmon 10, GrantedAccess `0x1010`), and three minutes later those creds appear in a Type-9 NewCredentials logon reaching host B (Security 4624)." That chain — **dump → abnormal logon** — is the heart of identity analysis.

---

## 2. What the tools do

You'll use three tools you already know, in their identity roles:
- **Chainsaw** — runs Sigma rules to *name* the credential-theft technique in each log (e.g. "Potential Credential Dumping Attempt Via PowerShell," "Mimikatz DC Sync").
- **Hayabusa** — its **`logon-summary`** sub-command tabulates every logon by account, computer, and logon type — the fastest way to read the "who logged in where" picture.
- **EvtxECmd** — when you need the *raw* logon rows (every field of every 4624), parse the Security log to CSV as in Module 5.

---

## 3. The scenario in this module's data

This module's `data/` folder contains **six small real `.evtx` samples** (provenance/license in `data/README.md`). Five show **different credential-theft techniques**; the sixth is a **benign logon baseline** so you can see what *not* firing looks like:

| File | Technique | Key event / fingerprint |
|---|---|---|
| `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | **Invoke-Mimikatz** (PowerShell) hits LSASS | Sysmon 10, `GrantedAccess 0x143a`, source = `powershell.exe` |
| `sysmon_10_mimikatz_sekurlsa_logonpasswords.evtx` | classic **Mimikatz.exe** `sekurlsa` | Sysmon 10, `GrantedAccess 0x1010`, source = `mimikatz.exe` |
| `sysmon_10_comsvcs_minidump_lsass.evtx` | **`comsvcs.dll` MiniDump** LOLBAS dump | Sysmon 1 + 10, `rundll32`/`comsvcs` |
| `powershell_4104_minidumpwritedump_lsass.evtx` | **PowerShell `MiniDumpWriteDump`** | PowerShell 4104 (script block) |
| `security_4662_dcsync.evtx` | **DCSync** (replicate from a DC) | Security 4662 on a Domain Controller |
| `security_4624_4625_logon_baseline.evtx` | **benign** logon sequence | Security 4624/4625 — fires *nothing*, your baseline |

---

## 4. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-07-identity-credential-theft/data
```
(Every command in this module is run **from inside this `data/` folder**. `chainsaw`, `hayabusa`, and `EvtxECmd` are installed natively and already on your `PATH`, so you call them directly by name in Git Bash; no container or Docker.)

> **Chainsaw rules/mappings path:** the `chainsaw hunt` commands point `-s` at the bundled Sigma rules and `--mapping` at `sigma-event-logs-all.yml` (shown here as `/opt/chainsaw/...`). Those live wherever **chainsaw** is installed on your lab VM — adjust if your VM's paths differ.

---

## 5. Step-by-step walkthrough

### Step 1 — Hunt every credential-theft technique at once (Chainsaw across the folder)
```bash
chainsaw hunt . \
  -s /opt/chainsaw/sigma \
  --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml \
  --csv --output chainsaw-out
```
- **`hunt .`** — run Sigma rules over **every** `.evtx` in the folder (not just one).
- **`-s /opt/chainsaw/sigma`** — the bundled Sigma rules.
- **`--mapping .../sigma-event-logs-all.yml`** — the field-translation table (see Module 6, Section 1).
- **`--csv --output chainsaw-out`** — write detections to CSV so you can compare all files side by side.

**Expected result — one row per technique, and the baseline stays silent:**
```
File                                          Event  Detection(s)
sysmon_3_10_Invoke-Mimikatz_hosted_Github     10     Potential Credential Dumping Attempt Via PowerShell
sysmon_10_mimikatz_sekurlsa_logonpasswords    10     HackTool - Generic Process Access; Uncommon GrantedAccess Flags On LSASS
sysmon_10_comsvcs_minidump_lsass              1, 10  Process Memory Dump Via Comsvcs.DLL; Uncommon Process Access Rights...
powershell_4104_minidumpwritedump_lsass       4104   Malicious PowerShell Keywords; PowerShell Get-Process LSASS in ScriptBlock; WinAPI Function Calls Via PowerShell Scripts
security_4662_dcsync                          4662   Active Directory Replication from Non Machine Account; Mimikatz DC Sync
security_4624_4625_logon_baseline             —      (no detections)
```
**Read it:** the same goal — steal credentials — shows up **five different ways**, and Chainsaw names each. Crucially, the **benign baseline fires nothing**: that contrast is how you trust the tool. A rule that screams on the attack samples and stays quiet on normal logons is a rule you can rely on.

### Step 2 — Read one dump in detail (the `GrantedAccess` fingerprint)
Run Chainsaw on just the classic Mimikatz sample to see the evidence fields:
```bash
chainsaw hunt sysmon_10_mimikatz_sekurlsa_logonpasswords.evtx \
  -s /opt/chainsaw/sigma \
  --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
**Expected output (key fields):**
```
 detections: ‣ HackTool - Generic Process Access
             ‣ Uncommon GrantedAccess Flags On LSASS
 Event ID: 10   Computer: PC04.example.corp
 TargetImage:  C:\Windows\system32\lsass.exe
 GrantedAccess: 0x1010
 SourceImage:  C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe
 CallTrace:    ...ntdll.dll+...|KERNELBASE.dll+...|mimikatz.exe+...
```
**Read it field by field:**
- **`TargetImage = lsass.exe`** — the thing being read is the credential store. Red flag #1.
- **`GrantedAccess = 0x1010`** — the exact Mimikatz `sekurlsa::logonpasswords` fingerprint (see the table in Section 1). Red flag #2.
- **`SourceImage = ...mimikatz.exe`** — and here it's not even hiding; the reader *is* Mimikatz, run from the Desktop. Red flag #3.
- **`CallTrace`** ending in `mimikatz.exe+...` confirms the code that touched LSASS lives in that binary.

Compare with `sysmon_3_10_Invoke-Mimikatz...` (GrantedAccess **`0x143a`**, source **`powershell.exe`** on host `IEWIN7`): same crime, different access mask and a *PowerShell* reader instead of an EXE — which is exactly why a hunter learns the masks and doesn't rely on the process name alone.

### Step 3 — Catch the stealthy variants (LOLBAS dump & DCSync)
Two samples don't look like "Mimikatz" at all:
- **`sysmon_10_comsvcs_minidump_lsass`** — here the *source* opening LSASS is `rundll32.exe` running `comsvcs.dll` (a trusted Windows DLL). Chainsaw's "**Process Memory Dump Via Comsvcs.DLL**" rule catches the rundll32+comsvcs+MiniDump command line, and "**Uncommon Process Access Rights**" catches the LSASS read. This is the LOLBAS way to dump creds without bringing your own tool.
- **`security_4662_dcsync`** — there's **no LSASS access here at all**. On a **Domain Controller** (`DC1.insecurebank.local`), Security **Event 4662** shows account `Administrator` performing a **directory replication** (the object access includes the `DS-Replication-Get-Changes` rights GUID). Chainsaw fires "**Mimikatz DC Sync / Active Directory Replication from Non-Machine Account**." The tell: replication should only ever be requested by *domain-controller computer accounts*, never by a user like `Administrator`. That's an attacker pulling password hashes straight from AD.

### Step 4 — Read the logons (who used the creds, and how)
After a dump, chase how the creds were *used*. The fast way is Hayabusa's logon summary; run it on the benign baseline first so you learn to read the table:
```bash
hayabusa logon-summary -f security_4624_4625_logon_baseline.evtx
```
- **`logon-summary`** — tabulate logons instead of building a full timeline.
- **`-f ...evtx`** — the Security log to summarize (use **`-d`** for a folder of them).

**Expected (shape):** a "Successful Logons" table grouped by **Target Account**, **Target Computer**, **Source Computer/IP**, and the **Event/Logon Type**, plus a "Failed Logons" table. On this baseline you'll see ordinary **Type 2 (interactive)** logons for `IEUser` and a **Type 5 (service)** for `SYSTEM`, with one **4625** failed attempt (a mistyped password). Nothing abnormal — your reference for "normal."

For the *raw* rows (every field), parse with EvtxECmd as in Module 5:
```bash
EvtxECmd -f security_4624_4625_logon_baseline.evtx --csv . --csvf logons.csv
```
Then read the `PayloadData` columns for **LogonType**. **What a hunter looks for on a real Security log:**
- **4624 / Type 9 (NewCredentials)** shortly after a dump → attacker using harvested creds (`runas /netonly`, a Pass-the-Hash signal).
- **4624 / Type 3 (Network)** from an unusual source host → lateral reach.
- **4648** (explicit credentials) → someone deliberately authenticating *as another account*.
- **4672** on a workstation → an unexpected admin logon.

### Step 5 — Build the chain
The investigative payoff is correlation. On a real case you'd line up the **dump time** (Step 2's Sysmon 10) against the **abnormal logon time** (Step 4's 4624 Type 9/3). When the harvested account shows up in a NewCredentials or Network logon minutes after its LSASS was read, you've connected *theft* to *use* — and you can name the next host the attacker reached.

> **What you can and can't demonstrate on the shipped data (read this).** This `dump → abnormal logon` chain is **illustrative of the technique**, not a worked example you can run end-to-end on the six bundled files. Those samples are **independent public captures from different hosts and clocks** (each isolates one technique), so the dump in one file and the logon in another **don't share a timeline** — the timestamps and account names won't line up. Learn the *shape* of the correlation here; you exercise the real time-and-LogonId stitching on a single shared host in the **capstone (Module 11)**, and the exercise below lets you hunt a matching logon in extra `Credential Access` samples pulled with `get-data.sh`.

---

## 6. Reading the output — suspicious vs. benign

| Signal | Benign looks like | Malicious looks like |
|---|---|---|
| Sysmon 10 on `lsass.exe` | (essentially never happens normally) | any read — especially `GrantedAccess` `0x1010`/`0x143a`/`0x1410`, or an "uncommon" mask |
| Source of the LSASS read | n/a | `mimikatz.exe`, `powershell.exe`, `rundll32 comsvcs.dll`, `procdump` |
| Security 4662 replication | a DC **computer account** ($-suffixed) | a **user** account (e.g. `Administrator`) requesting replication → DCSync |
| 4624 Logon Type | Type 2 at the console, Type 5 service | Type 9 NewCredentials, or Type 3/10 from an unexpected host, right after a dump |
| 4625 failures | the odd mistyped password | bursts of failures across many accounts → spray/brute force |

**Triaging false positives:** legitimate admin tools *can* touch LSASS (some EDR/AV, backup, or debugging software). Separate them by **who** (a known security agent vs. a user-Desktop EXE), **where** (`Program Files` vs. `C:\Users\Public`), and **context** (does a credential-theft *and* an abnormal logon appear together?). One weird event is a question; the **dump-then-logon chain** is an answer.

---

## 7. Investigative narrative — the story the evidence tells

An attacker with code execution went for the master key. Across these logs you can read every flavor of the same crime: they ran **Mimikatz** directly (`0x1010`, `mimikatz.exe`), ran it **through PowerShell** (`0x143a`, `Invoke-Mimikatz`), used the **living-off-the-land `comsvcs.dll`** trick to dump LSASS with only signed Windows code, called **`MiniDumpWriteDump` from a script**, and — on the domain controller — skipped LSASS entirely and **DCSynced** password hashes straight out of Active Directory. Chainsaw named each technique; the benign baseline stayed silent, proving the detections aren't just noise. The next move in a real case is to pivot to the **logons** (Hayabusa `logon-summary` / 4624 Type 9/3) and trace the stolen creds from host to host. Credential theft is what turns one box into the whole network — catching the **LSASS access** and then the **abnormal logons** is how you trace, and stop, the spread.

---

## 8. Try-it-yourself exercises

1. **Mask-reading.** Run Step 2 on `sysmon_3_10_Invoke-Mimikatz...` and `sysmon_10_mimikatz_sekurlsa...`. Note the two different `GrantedAccess` values and the two different source images. Why is the *mask + target* a stronger signal than the process name?
2. **LOLBAS hunt.** On `sysmon_10_comsvcs_minidump_lsass`, find the full `rundll32 ... comsvcs.dll, MiniDump ...` command line (parse with EvtxECmd, read the Event 1 row). Which argument names the LSASS PID?
3. **DCSync logic.** In `security_4662_dcsync`, identify the account that requested replication. Why does a *user* account doing this scream DCSync while a *DC computer account* doing it is normal?
4. **Baseline vs. attack.** Run Step 1's Chainsaw command and confirm `security_4624_4625_logon_baseline.evtx` produces **zero** detections. Why is a quiet baseline essential to trusting your rules?
5. **Correlate.** Using `get-data.sh`, pull more `Credential Access` samples and look for a logon (4624 Type 9) that lines up in time with a dump — connect theft to use.

---

## 9. Key takeaways

- Credentials (passwords/hashes) live in **LSASS**; stealing them is the **hinge** of an intrusion. The classic catch is **Sysmon Event 10 (ProcessAccess)** on `lsass.exe`, read via the **`GrantedAccess`** fingerprint (`0x1010`, `0x143a`, `0x1410`, or any uncommon mask).
- The same theft comes in many shapes — **Mimikatz.exe, Invoke-Mimikatz, comsvcs MiniDump, PowerShell MiniDumpWriteDump, and DCSync** (which touches a DC, not LSASS). Learn the *technique*, not one tool name.
- **Logon analysis** (Security **4624** by **Logon Type** — esp. **9 NewCredentials** and **3 Network** — plus **4648/4672**) shows *who used the creds, where*. Hayabusa **`logon-summary`** reads this fast; EvtxECmd gives the raw rows.
- A **benign baseline** that fires no rules is what makes your detections trustworthy.
- The win is the **chain**: dump → abnormal logon. Pivot the dumping **process** to Module 1 (Prefetch) and the **logons** to Module 8 (Lateral Movement).

---

## 10. Sources & further reading

- Microsoft Learn — Event 4624 (logon types reference): <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624>
- TrustedSec — Sysmon Community Guide, Process Access (Event 10 / GrantedAccess): <https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/process-access.md>
- Splunk — "You Bet Your Lsass: Hunting LSASS Access": <https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html>
- MITRE ATT&CK — OS Credential Dumping: LSASS Memory (T1003.001) & DCSync (T1003.006): <https://attack.mitre.org/techniques/T1003/001/> · <https://attack.mitre.org/techniques/T1003/006/>
- LOLBAS — `comsvcs.dll` MiniDump: <https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/>
- Hayabusa `logon-summary`: <https://github.com/Yamato-Security/hayabusa>
- Sample provenance — EVTX-ATTACK-SAMPLES (@sbousseaden, GPLv3): <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>

---
*Next: [Module 8 — Lateral Movement](../module-08-lateral-movement).*
