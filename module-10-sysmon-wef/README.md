# Module 10 — Sysmon + Windows Event Forwarding (The Visibility Layer)

**Deck mapping:** *Intrusion Hunting Playbook* → "Building Visibility: Sysmon & WEF" · *Advanced Intrusion Forensic Hunting* → "Instrumentation: Seeing the Attack."
**Goal:** understand the telemetry that made Modules 6–9 possible. **Sysmon** is the high-fidelity sensor on each endpoint; **Windows Event Forwarding (WEF)** is the plumbing that ships every endpoint's logs to one place to hunt. Learn the **Sysmon event-ID map** and you can read any sample in this lab; understand **WEF** and you can do it across 5,000 machines at once.

> **Prerequisite:** Modules 5 and 6. This module ties the whole of Part B together, so it helps to have seen the earlier samples. Every event ID and count below was produced by parsing the bundled files in the `dfir-aio` container.

---

## 1. Background — why this matters

### The problem Sysmon solves
Out of the box, Windows logs surprisingly little about *what programs do*. The default audit policy will tell you someone logged on, but it usually will not tell you that `winword.exe` spawned `powershell.exe` which opened a handle into `lsass.exe`. That process-level story — the stuff attackers actually leave behind — is mostly invisible by default.

**Sysmon** (System Monitor, a free Sysinternals tool) fixes that. It is the single biggest visibility upgrade you can deploy on a Windows endpoint, and it is *why* Chainsaw and Hayabusa had so much to find in the earlier modules.

### How Sysmon actually works (the mechanism)
Sysmon is two parts: a **kernel driver** (`SysmonDrv`) and a **service**. When you install Sysmon, the driver loads early at boot at a fixed "altitude" (385201 — its place in the stack of filter drivers) so it sees activity before most other software. The driver and service tap into **ETW (Event Tracing for Windows)** — the built-in Windows pipeline that emits a stream of low-level events — plus kernel callbacks for things like process creation and image loads. Sysmon filters that firehose down to attacker-relevant events using an **XML configuration file**, then writes the survivors to its own log: `Microsoft-Windows-Sysmon/Operational`.

Two consequences worth understanding:
- **Sysmon is only as good as its config.** A blank config logs almost nothing useful; a good config (the community-standard **SwiftOnSecurity** template is the usual starting point) logs the right things without drowning you in noise. The config decides which processes, registry keys, and network connections are recorded.
- **Sysmon enriches as it records.** A Sysmon process-create (Event ID 1) includes the full command line, the file **hashes**, *and the parent process* — so you get the process *tree*, not just isolated launches. That parent→child chain is what catches "Word launched PowerShell."

### What WEF solves, and how
Great — now you have rich telemetry. But it is sitting on 5,000 endpoints, and you cannot log into each one during an incident. **Windows Event Forwarding (WEF)** is the built-in, **agentless** answer (it ships in Windows; no third-party software to install):
- Each endpoint is a **source**. In the common **source-initiated** design, you push one Group Policy setting telling machines "forward your logs to collector `WEC01`," and the built-in forwarder (using **WinRM** over HTTP/HTTPS) does the rest.
- A **Windows Event Collector (WEC)** server receives them. You configure it once with `wecutil qc` (quick-config: it enables the collector service and the destination channel) plus a **subscription** that says which logs and which events to pull.
- Everything lands in one log on the collector: **`ForwardedEvents`**.

That single `ForwardedEvents` store is what you point Chainsaw or Hayabusa at. It turns per-host Sysmon into the **enterprise-wide** data set that Module 4's cross-host stacking and Module 6's Sigma sweeps assume. WEF being built-in and agentless is why it is the classic budget-friendly visibility stack.

> **The arc closes here.** The Triad (Modules 1–4) proves execution on *one* host; Sysmon + WEF is the layer that lets you run that same hunt across the *whole estate*, in order, from one console.

### The data set (multiple samples for this module)
The bundled files (see `data/README.md` for provenance/license) let you practice the Sysmon ID map across **several distinct techniques**, and compare what **default Windows logging** sees versus what **Sysmon** sees:

| File | Source | What it shows | Real event IDs |
|---|---|---|---|
| `Sysmon_UACME_45.evtx` | EVTX-ATTACK-SAMPLES | UAC bypass via a hijacked auto-elevation **registry** value | 1 ×5, 12 ×1, 13 ×1, 5 ×1 |
| `Sysmon_UACME_63.evtx` | EVTX-ATTACK-SAMPLES | a *different* UAC bypass that also touches LSASS | 1, 7, 10 |
| `sysmon_10_11_lsass_memdump.evtx` | EVTX-ATTACK-SAMPLES | credential dumping: handle into LSASS + dump file written | 10 ×2, 11 ×2 |
| `meterpreter_migrate_to_explorer_sysmon_8.evtx` | EVTX-ATTACK-SAMPLES | Meterpreter **process injection** into `explorer.exe` | 8 ×1 |
| `Zerologon_Sysmon.evtx` | hayabusa-sample-evtx | the **Sysmon** view of a Zerologon attack | 1 ×10, 5 ×10, 16 |
| `Zerologon_DefaultLogging_Security.evtx` | hayabusa-sample-evtx | the **default Security-log** view of the *same* attack | 4624 ×10, 4672 ×10, 4742, 4769 ×4, 4634 ×9, 1102 |

The last two are a matched pair on purpose: they let you *see for yourself* what changes when Sysmon is present.

---

## 2. The Sysmon event-ID map (memorise this)
| ID | Event | What it catches |
|---|---|---|
| **1** | Process Create | full command line, **hashes**, **ParentImage** (the process tree) |
| **2** | File creation time changed | **timestomping** |
| **3** | Network Connection | C2 / lateral connections (proc → IP:port) |
| **5** | Process Terminated | end of a process's life (pairs with 1) |
| **6** | Driver Loaded | malicious/unsigned drivers |
| **7** | Image Loaded | **DLL side-loading**; `Automation.dll` in a non-PS proc (Module 9) |
| **8** | CreateRemoteThread | **process injection** (Module 9's PSInject; Meterpreter migrate) |
| **9** | RawAccessRead | raw disk reads (`\\.\C:`) — `$MFT`/credential theft |
| **10** | ProcessAccess | **LSASS access** = credential dumping (Module 7) |
| **11** | FileCreate | dropped files; Startup-folder persistence (Module 8) |
| **12/13/14** | Registry (key / value / rename) | autoruns, **UAC-bypass keys**, CLM/ExecutionPolicy (Module 9), new shares (Module 8) |
| **15** | FileCreateStreamHash | **Mark-of-the-Web** / Alternate Data Streams (downloaded files) |
| **16** | Sysmon config change | Sysmon's own state (someone re-configured the sensor) |
| **17/18** | Pipe Created / Connected | **PsExec & named-pipe** lateral movement (Modules 6, 8) |
| **19/20/21** | WMI Event subscription | WMI persistence |
| **22** | DNS Query | C2 domain resolution |
| **23/26** | File / stream delete | anti-forensic wiping |

---

## 3. Setup
```bash
cd module-10-sysmon-wef/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```
(Flags explained in Module 8 §3. **Windows-native:** `C:\DFIR\tools\EvtxECmd.exe`, `hayabusa.exe`.)

---

## 4. Step-by-step walkthrough

### Step 1 — Timeline the whole folder at once (Hayabusa)
Start by treating `data/` the way you would treat a real collection: many logs, one timeline. **Hayabusa** ranks events by how alarming they are.

```bash
hayabusa csv-timeline -d /data -o /data/timeline.csv -w
```
- `hayabusa` — the timeline/triage tool.
- `csv-timeline` — the mode that produces one ranked CSV across everything.
- `-d /data` — the **d**irectory of `.evtx` to scan (all six files at once).
- `-o /data/timeline.csv` — the **o**utput CSV (lands back on your host via the mount). Hayabusa writes straight into `/data`; it will not create a missing sub-folder, so don't point `-o` at a directory that doesn't exist yet.
- `-w` — **no-wizard**: don't ask any questions, just scan with all rules (the same flag used in Module 6).

**Expected output:** a console summary of how many events matched each severity (critical/high/medium/low), then a `timeline.csv` you can sort. Sort by the rule **`Level`** column and the worst hits — LSASS access, CreateRemoteThread, the UAC bypass — float to the top. This is exactly how you would triage a freshly collected `ForwardedEvents` export.

### Step 2 — Read a Sysmon registry-based UAC bypass end-to-end
`Sysmon_UACME_45.evtx` is a **UACME** UAC-bypass (technique #45). UAC ("User Account Control") is the prompt that asks "do you want to allow this app to make changes?" A UAC bypass tricks an **auto-elevating** Windows binary (one allowed to elevate *without* a prompt) into running the attacker's code, so a normal process gets an *elevated* child with **no prompt**.

```bash
EvtxECmd -f /data/Sysmon_UACME_45.evtx --csv /data/_out --csvf uacme45.csv
```
Real contents: Sysmon **1 ×5, 12 ×1, 13 ×1, 5 ×1**. Read it as a story:
1. The **Sysmon 13 (registry value set)** is the bypass itself — UACME #45 writes a value to a registry key that an auto-elevating binary reads, redirecting it to the attacker's command.
2. The resulting **Sysmon 1 (process create)** is the payoff — a child process launches **elevated**, and there is **no `consent.exe`** (the UAC prompt process) anywhere in the tree. Elevation with no consent.exe = bypass.
3. The **Sysmon 5 (process terminated)** is that process tearing down afterward.

List every Sysmon 1 with its **Image** and **ParentImage** and draw the parent→child chain; find where elevation appears without a prompt.

### Step 3 — Compare a second UAC bypass (different IDs, same idea)
```bash
EvtxECmd -f /data/Sysmon_UACME_63.evtx --csv /data/_out --csvf uacme63.csv
```
Real contents: Sysmon **1, 7, 10**. A *different* UACME technique — note it shows up with an **Image Load (7)** and even a **ProcessAccess (10)** into LSASS, where #45 was a *registry* story (12/13). Lesson: the same goal (silent elevation) can surface through **different Sysmon IDs** depending on *how* the bypass works. You read the IDs to reconstruct the method.

### Step 4 — Credential dumping in pure Sysmon (10 + 11)
```bash
EvtxECmd -f /data/sysmon_10_11_lsass_memdump.evtx --csv /data/_out --csvf lsassdump.csv
```
Real contents: **10 ×2** + **11 ×2**. This is the cleanest possible teaching example of credential theft as Sysmon sees it:
- **Sysmon 10 (ProcessAccess)** — a process opened a handle into **`lsass.exe`** (LSASS holds logged-on users' credentials). Read the **GrantedAccess** field; values like `0x1010`/`0x1410` are the classic "read process memory" rights a dumper needs.
- **Sysmon 11 (FileCreate)** — the **dump file** being written to disk (e.g. an `.dmp`). Access LSASS *then* write a `.dmp` = credentials being exfiltrated. No PowerShell log, no 4104 — Sysmon alone tells the whole story (compare Module 9, which caught the same act via 4104).

### Step 5 — Catch process injection (Sysmon 8)
```bash
EvtxECmd -f /data/meterpreter_migrate_to_explorer_sysmon_8.evtx --csv /data/_out --csvf migrate.csv
```
Real contents: **Sysmon 8 ×1 (CreateRemoteThread)**. This is **Meterpreter's `migrate`** — the implant injecting a thread into `explorer.exe` so its code lives inside a trusted process. Read the **SourceImage** (who injected) and **TargetImage** (`explorer.exe`, the victim). A process creating a remote thread inside another is rarely benign; this single event is the whole injection.

### Step 6 — The headline comparison: default logging vs Sysmon
Here is the lesson of the entire module in two files. Both capture a **Zerologon** attack (a critical Active-Directory exploit that resets a domain controller's machine password). One was captured with **only default Windows auditing**; the other with **Sysmon** running.

```bash
EvtxECmd -f /data/Zerologon_DefaultLogging_Security.evtx --csv /data/_out --csvf zl_default.csv
EvtxECmd -f /data/Zerologon_Sysmon.evtx                  --csv /data/_out --csvf zl_sysmon.csv
```
- **`Zerologon_DefaultLogging_Security.evtx`** (Security log): **4624 ×10**, **4672 ×10** (logons + admin rights), **4742** (a *computer account was changed* — the smoking-gun artefact of the password reset), **4769 ×4** (Kerberos tickets), **4634 ×9** (logoffs), **1102** (log cleared). The default log captures the **authentication and the AD change**.
- **`Zerologon_Sysmon.evtx`** (Sysmon log): **1 ×10** (the *process* activity — the tools the attacker actually ran), **5 ×10**, **16**. Sysmon captures the **execution** side that the Security log never sees.

**Reading the comparison:** neither sensor sees everything. The Security log caught the **4742** AD change; Sysmon caught the **process tree** that drove it. An investigator wants *both*, centralized — which is precisely the argument for Sysmon **and** WEF: forward the Security log *and* the Sysmon log from every host into one `ForwardedEvents` store, so a single Sigma sweep sees the full picture.

> **About a "benign baseline":** these captures come from *real, busy hosts*, so most events in any file are ordinary Windows activity — that benign background *is* your baseline. The skill is spotting the one anomalous chain (the `lsass` handle, the parent-less elevated process, the `explorer.exe` thread injection) against the normal traffic in the *same* file. Train your eye to ignore the routine and lock onto the outlier.

---

## 5. Reading the output — what makes a Sysmon event suspicious
- **Sysmon 1:** judge it by the **parent**. `winword.exe → powershell.exe`, `services.exe → cmd.exe`, `svchost.exe -k DcomLaunch → mshta.exe` are all parent/child chains that should never happen normally. Also check the **hash** against known-good and the **command line** for encoded blobs.
- **Sysmon 10:** any handle into **`lsass.exe`** with memory-read **GrantedAccess** is suspicious unless it is a known security product.
- **Sysmon 8:** CreateRemoteThread into another live process = injection until proven otherwise.
- **Sysmon 12/13:** writes to auto-elevation keys, `__PSLockdownPolicy`, `Run`/`RunOnce`, or `LanmanServer\Shares` are persistence/evasion tells.
- **Sysmon 7:** a signed-but-unexpected DLL loaded from a temp/user path = side-loading; `Automation.dll` in a non-PowerShell process = unmanaged PowerShell.
- **Sysmon 16:** *Sysmon's own config changed* — if you did not change it, an attacker may be blinding the sensor.

---

## 6. Investigative narrative — the story the evidence tells
Read the six files as one estate under attack:
- An attacker silently elevates with a **UAC bypass** — sometimes a registry redirect (`UACME_45`: Sysmon 12/13 → elevated 1), sometimes a DLL/LSASS path (`UACME_63`: 7/10).
- They **dump credentials**: a handle into LSASS and a `.dmp` on disk (`sysmon_10_11_lsass_memdump`: 10 + 11).
- They **hide** by injecting into a trusted process (`meterpreter_migrate`: Sysmon 8 into `explorer.exe`).
- They **attack the domain** itself (Zerologon). Default auditing records the **AD change** (4742) and logons; Sysmon records the **execution**. Only together do they tell the full story — and only WEF gets them into one place to be read together.

This is the foundation under everything in Part B: every Sysmon ID you just read is one Chainsaw/Hayabusa was matching against in Modules 6–9.

---

## 7. Try-it-yourself exercises
1. **Build the tree.** From `Sysmon_UACME_45.evtx`, list every **Sysmon 1** with its **Image** and **ParentImage** and draw the parent→child chain. Where does elevation appear without a `consent.exe` prompt? Which single event (the **registry 13**) *is* the bypass, and which (**process 1**) is the payoff?
2. **Two bypasses, different IDs.** Compare `Sysmon_UACME_45.evtx` (12/13) with `Sysmon_UACME_63.evtx` (7/10). Both end in silent elevation — explain how the *different* Sysmon IDs reflect *different* bypass methods.
3. **Dump in two views.** `sysmon_10_11_lsass_memdump.evtx` shows credential theft as **Sysmon 10 + 11**; Module 9's `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` showed the same act as **4104**. Which fields (GrantedAccess, the `.dmp` path, the ScriptBlockText) prove it in each, and why do you want both sensors?
4. **Default vs Sysmon.** Parse both Zerologon files. Which artefact (Security **4742**) only the default log has, and which (the **process tree**, Sysmon **1**) only Sysmon has? Write one sentence arguing why WEF should forward *both* logs.
5. **WEF design.** You have 200 endpoints running Sysmon. Sketch the WEF setup — a GPO-pushed source-initiated subscription, a `wecutil qc` collector, the `ForwardedEvents` channel — and explain why Chainsaw/Hayabusa run against the **collector**, not each host.
6. **(Stretch)** Use `get-data.sh` to pull more Sysmon samples and re-run `hayabusa csv-timeline` — confirm the same ID map explains techniques you haven't seen yet.

---

## 8. Key takeaways
- **Sysmon** = a kernel driver + service tapping **ETW** and kernel callbacks, filtered by an **XML config**, writing rich process/network/registry/pipe/injection events to `Microsoft-Windows-Sysmon/Operational`. Its config decides its value (start from the SwiftOnSecurity template).
- The **Sysmon ID map** is the takeaway: **1** (process+tree+hashes), **3** (network), **7** (image load/side-load), **8** (injection), **10** (LSASS), **11** (file drop), **12/13** (registry), **16** (sensor tampered), **17/18** (pipes). These are the exact IDs Modules 6–9 hunted.
- **Default logging and Sysmon are complementary** — the Zerologon pair proves it: the Security log caught the **AD change (4742)**, Sysmon caught the **execution**. Collect both.
- **WEF** centralizes everything into `ForwardedEvents` on a collector (`wecutil` + a source-initiated subscription pushed by GPO; agentless, built-in). That single store is what makes enterprise-scale, in-order hunting — and Module 4's cross-host stacking — possible.

---

## 9. Sources & further reading
- Microsoft Sysinternals — *Sysmon* (official docs, event schema, config): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- TrustedSec — *Sysmon Community Guide* (how the driver + config work): https://github.com/trustedsec/SysmonCommunityGuide
- SwiftOnSecurity — *sysmon-config* (the community-standard, heavily commented config template): https://github.com/SwiftOnSecurity/sysmon-config
- Microsoft Learn — *Use Windows Event Forwarding to help with intrusion detection*: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection
- Microsoft Learn — *Setting up a Source-Initiated Subscription* (`wecutil`, GPO, `ForwardedEvents`): https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription
- @sbousseaden — *EVTX-ATTACK-SAMPLES*; Yamato-Security — *hayabusa-sample-evtx* (the sources of this module's data): https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES · https://github.com/Yamato-Security/hayabusa-sample-evtx

See `data/README.md` for the exact provenance and license of each bundled `.evtx`.

## Pivot
- This is the foundation under the whole of **Part B** — re-run any Module 6–9 sample now knowing exactly what each Sysmon ID means.
- Centralised Sysmon → **Module 6 (Sigma hunting)** at scale; cross-host artifacts → **Module 4 (stacking)**.

---
*Back to the [curriculum](../README.md). You can now take a triage collection and build a full incident timeline — **"Master the Triad. Close the Gap."***
