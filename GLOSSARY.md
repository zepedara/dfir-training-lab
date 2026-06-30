# Glossary — DFIR Training Lab

Plain-language definitions of the key terms, artifacts, tools, and event IDs used across the course. Aimed at beginners: if a module uses a word you don't know, it's probably here. Terms are grouped, then there's an A-Z of event IDs at the end.

> Where a definition makes a factual claim, a **Sources** line points to the authoritative reference.

> **Theme note.** The lab's narrative casts the victim as **Middle-earth Holdings** and the adversary as **SAURON / APT-MORDOR** (canon: [`THEME-MIDDLE-EARTH.md`](THEME-MIDDLE-EARTH.md)). These definitions are the un-themed technical ground truth; the theme never changes a tool, an event ID, or a real evidence name.

---

## Core concepts

**DFIR (Digital Forensics and Incident Response)**
The combined craft of (a) digital forensics — recovering a defensible, evidence-grade account of what happened on a computer from the traces it left — and (b) incident response — actually finding, scoping, and evicting an attacker. This whole course is DFIR.
*Sources:* NIST SP 800-86 <https://csrc.nist.gov/publications/detail/sp/800-86/final>.

**Artifact**
A trace the operating system creates as a *side effect* of normal operation (a Prefetch file, a registry cache, a log record). Because the system makes it automatically, it's good evidence — the attacker didn't choose to create it.

**Triad (Evidence-of-Execution Triad)**
The three Windows execution artifacts — **Prefetch** (it ran), **ShimCache** (the OS saw it), **Amcache** (its identity/SHA1). Each covers the others' blind spots; you read all three together. The spine of Part A.

**Timeline**
Events placed in time order so a story emerges. Most investigation work is building and reading timelines.

**Baseline**
A record of what "normal" looks like, kept beside the suspicious data so anomalies stand out. Every module pairs an attack sample with a benign baseline for this reason.

**LOLBin / LOLBAS (Living-Off-the-Land Binary / …And Scripts)**
A legitimate, signed Windows program (`powershell.exe`, `rundll32.exe`, `certutil.exe`, `mshta.exe`, `desktopimgdownldr.exe`, …) that an attacker abuses so they don't have to bring their own malware. Hard to block because the system needs these tools.
*Sources:* LOLBAS Project <https://lolbas-project.github.io/>.

**LFO (Least Frequency of Occurrence) / Stacking**
A hunting method: collect the same data point (e.g. a SHA1) from many hosts and count how often each value appears. The *rare* values are your leads; the ubiquitous ones are noise. "Rarity finds candidates; metadata convicts." (Module 4.)
*Sources:* Mandiant, *Caching Out* <https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-value-of-shimcache-for-investigators/>.

**IOC (Indicator of Compromise)**
A concrete, checkable sign of an attack — a file hash, a filename, an IP/domain, a registry key. The malware SHA1 `fd153c66…` from Case 001 is an IOC.

**UTC (Coordinated Universal Time)**
The single timezone forensics records everything in, so analysts worldwide agree on "when." All run times and event times in this course are UTC.

**MITRE ATT&CK**
A public, structured catalogue of attacker techniques (each with a `T####` ID, e.g. T1003.001 = LSASS dumping). The sample data is largely organised by ATT&CK technique.
*Sources:* <https://attack.mitre.org/>.

**SHA1 (and file hash, generally)**
A short fixed-length fingerprint computed from a file's exact bytes. Two files with the same SHA1 are (for our purposes) the same file; change one byte and the hash changes completely. This is why hunting on hash beats hunting on filename — a rename fools a name match but not a hash.

---

## Part A — execution artifacts & tools

**Prefetch (`.pf`)**
Files Windows writes in `C:\Windows\Prefetch\` to make programs start faster. As a side effect each records the program name, **run count**, the **last 8 run times**, and the **files/DLLs loaded** in the first ~10 seconds — superb execution evidence. The filename is `NAME-<hash>.pf`, where the hash encodes the path it ran from.
*Sources:* libscca PF format <https://github.com/libyal/libscca>; Magnet Forensics <https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/>.

**10-second rule**
A Prefetch timing rule: the run time *inside* the `.pf` is the program's real start; the `.pf` file's own creation time on disk is roughly **10 seconds later** (Windows writes the file after the program has been running ~10s). Use the in-file time for your timeline.

**ShimCache (AppCompatCache / Application Compatibility Cache)**
A cache inside the `SYSTEM` registry hive that Windows uses to decide if a program needs compatibility fixes. It records files the OS *evaluated* — which can include files merely browsed, not just executed — so it proves **existence/awareness, not execution**. On Windows 10/11 its "Executed" flag is unreliable. Flushed to the hive mainly at shutdown.
*Sources:* Mandiant, *Caching Out* (above); Magnet, *ShimCache vs AmCache* <https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/>.

**Amcache (`Amcache.hve`)**
A separate registry hive that inventories programs and, crucially, stores each executable's **SHA1**, full path, size, and metadata. Populated by a background appraiser task, so **inventoried ≠ executed**. Its SHA1 is the pivot you carry into cross-host hunting.
*Sources:* amcacheparser.com reference <https://www.amcacheparser.com/en/blog/amcache-hve-reference>; Securelist <https://securelist.com/amcache-forensic-artifact/117622/>.

**Registry hive**
A single file holding part of the Windows Registry (the system's big configuration database). `SYSTEM` and `Amcache.hve` are hives. You parse a hive offline with a tool rather than booting the machine.

**Transaction logs (`.LOG1` / `.LOG2`)**
Companion files to a registry hive holding the most recent changes not yet written into the hive itself. A parser **replays** them so a "dirty" (live-collected) hive reads correctly. **Always collect them alongside the hive** (e.g. `SYSTEM.LOG1/.LOG2`, `Amcache.hve.LOG1/.LOG2`).

**LinkDate (PE compile timestamp)**
A timestamp baked into a Windows executable when it was built. It's trivially **forgeable** and often garbage, so it's weak evidence — never convict on LinkDate alone.

**DLL side-loading**
An attack where a program is tricked into loading a malicious DLL from an unexpected folder (`\Temp\`, `\AppData\`, `\Users\Public\`). Prefetch's "files loaded" list is a quick way to spot a DLL loaded from somewhere it shouldn't be.

**PECmd**
Eric Zimmerman's Prefetch parser (Windows). Exports a rich timeline CSV with all 8 run times. The modules' hands-on steps use the open-source equivalent on the lab VM, the `prefetch` tool (libscca's `sccainfo`).
*Sources:* EZ Tools <https://ericzimmerman.github.io/>.

**AppCompatCacheParser**
Eric Zimmerman's tool that parses ShimCache out of a `SYSTEM` hive to CSV (auto-replaying the `.LOG` files).

**AmcacheParser**
Eric Zimmerman's tool that parses `Amcache.hve` to a set of CSVs (including the SHA1-bearing file-entry tables).

**AppCompatProcessor**
A tool (Matías Bevilacqua) for **scaling** AppCompat/Amcache analysis across many hosts — stacking, frequency analysis, masquerade/typosquat detection. Module 4's engine.
*Sources:* <https://github.com/mbevilacqua/appcompatprocessor>.

---

## Part B — event logs, detection & tools

**EVTX (`.evtx`)**
The modern Windows **Event Log** file format — a *binary* file (you can't just open it in a text editor) holding event records. Each Windows log "channel" (Security, System, Application, PowerShell, Sysmon, …) is its own `.evtx`.

**Channel**
A named stream of events, e.g. `Security`, `System`, `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational`. Different attacker actions land in different channels — corroborating across channels is stronger than one hit.

**Event ID**
A number identifying *what kind of thing happened* within a channel (e.g. Security **4624** = a logon). See the event-ID index at the end.

**EvtxECmd**
Eric Zimmerman's tool that parses `.evtx` (no Windows needed) and merges every channel into one sortable **CSV/JSON** timeline. **Maps** turn the cryptic event XML into labelled columns.
*Sources:* <https://github.com/EricZimmerman/evtx>.

**Sigma**
A vendor-neutral language for writing **detection rules** ("a saved search for bad"). One Sigma rule can be translated to run against many different log systems. A **mapping** bridges Sigma's generic field names to a specific log's real fields.
*Sources:* SigmaHQ <https://sigmahq.io/>.

**Detection rule**
A named, severity-tagged pattern that flags suspicious activity in logs. Sigma is the language; Chainsaw/Hayabusa are engines that run the rules.

**Chainsaw**
A fast log-hunting engine (WithSecure) that runs Sigma rules and built-in detections over `.evtx`, returning **named detections with the supporting evidence**.
*Sources:* <https://github.com/WithSecureLabs/chainsaw>.

**Hayabusa**
A fast log-analysis engine (Yamato Security) that produces a **severity-ranked timeline** from `.evtx` and has handy summaries like `logon-summary`.
*Sources:* <https://github.com/Yamato-Security/hayabusa>.

**Sysmon (System Monitor)**
A free Microsoft Sysinternals tool: a kernel driver + service that taps **ETW** and kernel callbacks to log rich, security-relevant events (process creation *with hashes and parent*, network connections, image loads, LSASS access, file drops, registry edits, named pipes, injection) to its own channel. Its **XML config** decides what it records — a good config (e.g. SwiftOnSecurity's template) is what makes it valuable.
*Sources:* <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>; SwiftOnSecurity config <https://github.com/SwiftOnSecurity/sysmon-config>.

**ETW (Event Tracing for Windows)**
The low-level Windows plumbing that emits a firehose of events about system activity; Sysmon subscribes to parts of it and writes filtered, readable events.

**WEF (Windows Event Forwarding)**
A built-in, agentless way to **forward** event logs from many endpoints to a central **collector**, landing them in the `ForwardedEvents` channel. Set up via `wecutil` and a source-initiated subscription pushed by GPO. The collector is what makes enterprise-scale, in-order hunting (and cross-host stacking) possible.
*Sources:* <https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection>.

**LSASS (Local Security Authority Subsystem Service, `lsass.exe`)**
The Windows process that holds users' credentials (passwords and password **hashes**) in memory so you don't re-type them constantly. Stealing those credentials means reading or dumping LSASS — the **hinge** of most intrusions. The classic catch is **Sysmon Event 10** opening a handle to `lsass.exe`.
*Sources:* MITRE T1003.001 <https://attack.mitre.org/techniques/T1003/001/>; Splunk, *You Bet Your Lsass* <https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html>.

**GrantedAccess (access mask)**
The hexadecimal permission value in a Sysmon Event 10 record showing *how much access* a process asked for when opening another process. Certain masks on `lsass.exe` (e.g. `0x1010`, `0x1410`, `0x143a`) are tell-tale credential-dumping fingerprints. Read the **mask + target**, not just the process name.
*Sources:* TrustedSec Sysmon Community Guide, Process Access <https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/process-access.md>.

**Mimikatz**
The best-known credential-dumping tool. Appears as `mimikatz.exe`, as **Invoke-Mimikatz** (a PowerShell port), and in many clones — all reading LSASS. Learn the *technique* (LSASS access, the GrantedAccess mask), not the one name.

**Credential dumping**
Stealing passwords/hashes from a host — from LSASS memory, via `comsvcs.dll` MiniDump (a LOLBAS), via PowerShell `MiniDumpWriteDump`, or from a Domain Controller via DCSync.
*Sources:* MITRE T1003 <https://attack.mitre.org/techniques/T1003/>.

**DCSync**
A credential-theft technique that *asks a Domain Controller to replicate password data*, impersonating another DC — so the secrets come out without touching LSASS. A **user** account requesting replication (Security **4662**) is the red flag; a real DC computer account doing it is normal.
*Sources:* MITRE T1003.006 <https://attack.mitre.org/techniques/T1003/006/>.

**Pass-the-Hash (PtH)**
Authenticating to another system using a stolen password **hash** directly, without ever knowing the plaintext password. Often shows as a **Logon Type 9 (NewCredentials)** event near the credential theft.

**Lateral movement**
Spreading from one compromised host to others inside the network. Every built-in method (PsExec/services, DCOM, WMI, scheduled tasks, remote registry, RDP) leaves a **delivery** event *and* a **carrier logon** (Security **4624 Type 3** + **4672**), tied together by **LogonId**.
*Sources:* JPCERT/CC, *Detecting Lateral Movement through Tracking Event Logs* <https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf>.

**PsExec**
A Sysinternals admin tool (and the template for many attacker clones) that runs commands on a remote host by installing a temporary service. Leaves a **7045** (service installed), **5145** on the `\PSEXESVC` (or renamed) pipe, and Sysmon **17/18** pipe events.

**DCOM / WMI**
Built-in Windows remote-execution mechanisms attackers abuse for lateral movement (e.g. `MMC20.Application`, `ShellWindows` via DCOM; WMI for remote process creation). DCOM activity is parented by `svchost.exe -k DcomLaunch`; failed activations show as System **10016**.

**RDP (Remote Desktop Protocol)**
Windows' graphical remote-login. Investigated via the `RdpCoreTS` channel (e.g. **131** = a connection accepted, with the client IP — useful even when the logon fails) and tools like SharpRDP that abuse `\tsclient\` redirection.
*Sources:* The DFIR Spot, *RDP Event Logs* <https://www.thedfirspot.com/post/lateral-movement-remote-desktop-protocol-rdp-event-logs>.

**Named pipe**
An inter-process communication channel (e.g. `\PSEXESVC`, `\atsvc`, `\svcctl`). Sysmon logs **17 (Pipe Created)** and **18 (Pipe Connected)** — *created* = a server pipe appeared; *connected* = someone dialled in.

**LogonId**
A per-session identifier in logon events. It's the *glue* that ties an action (a created service, a changed task) to the specific remote session that did it, rather than to background noise.

**Logon Type**
A number on a Security **4624/4625** event saying *how* someone logged on: **2** = interactive (at the keyboard), **3** = network (e.g. a share/PsExec), **9** = NewCredentials (often Pass-the-Hash), **10** = RemoteInteractive (RDP). The type frequently matters more than the fact of the logon.
*Sources:* Microsoft, Event 4624 <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624>.

**Script Block Logging (PowerShell 4104)**
PowerShell logging that records the **fully de-obfuscated script text** at compile time — so even a Base64-launched script is captured in clear. The single best PowerShell-attack source; read its `ScriptBlockText` for intent.
*Sources:* Microsoft, *about_Logging_Windows* <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows>.

**Module Logging (PowerShell 4103)**
The per-command companion to 4104, logging pipeline execution details. Taught conceptually in Module 9.

**Constrained Language Mode (CLM)**
A PowerShell lock-down that restricts dangerous features. Attackers try to **disable** it; that attempt (Sysmon 12/13 registry events) is itself a signal that something bad is coming.

**Unmanaged / in-memory PowerShell**
Running PowerShell *without* `powershell.exe` by loading `System.Management.Automation.dll` into another process — which **bypasses 4104**. Caught instead by Sysmon **7** (that DLL loaded into a non-PowerShell process) and **8** (CreateRemoteThread injection).

**WinRM (Windows Remote Management)**
The service behind PowerShell Remoting; remote PS sessions run in `wsmprovhost.exe` and authenticate via WinRM events (e.g. **169**).

---

## Event-ID quick index

**Security log**
- **4624** — successful logon (read the **Logon Type**).
- **4625** — failed logon.
- **4648** — logon using explicit credentials (runas / "explicit creds").
- **4662** — operation on a directory object; with replication rights = **DCSync** signal.
- **4672** — special/admin privileges assigned at logon (the "this was an admin logon" flag).
- **4698 / 4699 / 4702** — scheduled task created / deleted / updated.
- **4742** — a computer account was changed (e.g. the Zerologon machine-account reset).
- **4776** — NTLM credential validation.
- **5140 / 5145** — a network share was accessed / a share object was checked (file-level; `5145` names the pipe like `svcctl`, `atsvc`, `PSEXESVC`).
- **7045** — a new service was installed (PsExec and many remote-exec tools).
- **1102** — the Security log was cleared (anti-forensics).

**Sysmon (`Microsoft-Windows-Sysmon/Operational`)**
- **1** — process creation (with command line, hashes, **ParentImage**) — the backbone.
- **3** — network connection.
- **7** — image (DLL) loaded — side-loading and unmanaged-PowerShell hunting.
- **8** — CreateRemoteThread — process injection.
- **10** — process accessed another process — the **LSASS** credential-theft catch (read **GrantedAccess**).
- **11** — file created — e.g. a `.dmp` of LSASS, a dropped payload.
- **12 / 13** — registry object created-deleted / value set — CLM/ExecutionPolicy tampering, UAC-bypass keys.
- **16** — Sysmon's own config changed (sensor tampering).
- **17 / 18** — named pipe created / connected.

**PowerShell (`Microsoft-Windows-PowerShell/Operational`)**
- **4103** — module/pipeline logging (per command).
- **4104** — script block logging (the de-obfuscated script).

**Other channels**
- **BITS-Client 59 / 60** — a BITS background download started/completed (LOLBAS download via `desktopimgdownldr`, etc.).
- **WinRM 169 / 193** — WinRM authentication / session (PowerShell Remoting).
- **RdpCoreTS 131 / 98 / 140 / 104** — RDP connection events (131 carries the client IP).
- **System 10016** — DCOM permission/activation error (failed DCOM lateral movement leaves a cluster of these).

*See each module's README and **[COURSE.md](COURSE.md)** for these IDs in context, and **[ANSWER-KEY.md](ANSWER-KEY.md)** for worked exercises that use them.*
