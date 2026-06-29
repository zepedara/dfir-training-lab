# Module 8 — Lateral Movement

**Deck mapping:** *Intrusion Hunting Playbook* → "Detecting Lateral Movement" · *Advanced Intrusion Forensic Hunting* → "Phase 3: Lateral Movement."
**Goal:** recognise how an attacker hops host-to-host — **PsExec/remote services, DCOM, WMI, named pipes, scheduled tasks, remote registry/shares, and RDP** — by the exact events each technique burns into the logs.

---

## Concept (from the decks)
Once credentials are stolen (Module 7), the attacker spreads. Almost every remote-execution method leaves a recognisable pair of footprints: **how the command arrived** (a service install, a DCOM activation, a named pipe, a scheduled task) and **the network logon that carried it** (Security **4624 Type 3** + **4672**). Learn the signatures and lateral movement stops being invisible.

This module's data is a curated slice of **EVTX-ATTACK-SAMPLES** (sbousseaden) — one `.evtx` per technique, each named for the event IDs it contains. Every event ID and detection below was confirmed by parsing the bundled files.

---

## Setup
```bash
cd module-08-lateral-movement/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```
Two ways to work: **Chainsaw/Hayabusa** name the technique automatically (Module 6 style); **EvtxECmd** gives you the raw events to read the fields by hand. Use both.

---

## The lateral-movement signatures (what's in the data)

### 1. PsExec & remote services — `7045`, `5145`, Sysmon `17/18`
PsExec (and clones: RemCom, Impacket `psexec`) **installs a service** on the target and talks to it over a **named pipe**.
- **`LM_Remote_Service02_7045.evtx`** → System log **7045 = "A service was installed"** (Service Control Manager). Read the **Service Name** and **ImagePath** — PsExec's default service is `PSEXESVC`; clones rename it.
- **`LM_renamed_psexecsvc_5145.evtx`** → **5145 = "A network share object was checked for access"** (Detailed File Share auditing) ×22. 5145's **RelativeTargetName** shows the pipe/share touched (e.g. `\PSEXESVC`, or a renamed pipe) over `\IPC$`.
- **`LM_Remote_Service01_5145_svcctl.evtx`** → 5145 on the **`svcctl`** pipe = remote Service Control Manager (the SCM call that creates the service).
- **`LM_REMCOM_5145_TargetHost.evtx`** (RemCom, 5145 ×30) and **`LM_5145_Remote_FileCopy.evtx`** (5145 ×869 = files copied over `\ADMIN$`/`\C$` before execution).
- **`LM_sysmon_psexec_smb_meterpreter.evtx`** → Sysmon `1/3/10/13/18`. Chainsaw flags **"PowerShell as a Service"** (parent = `services.exe`) and **"Base64 Encoded PowerShell"** — a Meterpreter PsExec payload landing as a service-spawned, encoded PowerShell.

```bash
# Read the service install:
EvtxECmd -f /data/LM_Remote_Service02_7045.evtx --csv /data --csvf svc.csv   # 3 × 7045
# Let Chainsaw name the SMB/PsExec payload:
chainsaw hunt /data/LM_sysmon_psexec_smb_meterpreter.evtx \
  -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```

### 2. DCOM lateral movement — Sysmon `1/3`, System `10016`
DCOM lets you instantiate a COM object on a remote host; the object's process (`mshta.exe`, `mmc.exe`, Office) executes your payload, **parented by `svchost.exe -k DcomLaunch`**.
- **`LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx`** → Chainsaw: **"Potential LethalHTA Technique"** — `mshta.exe` spawned via DCOM.
- **`LM_impacket_docmexec_mmc_sysmon_01.evtx`** → Chainsaw: **"MMC20 Lateral Movement"** — Impacket `dcomexec` driving the **`MMC20.Application`** COM object → `mmc.exe`.
- **`LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx`** → Sysmon 3 (network) for the **ShellWindows / ShellBrowserWindow** DCOM objects.
- **`LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx`** → System **10016 = "DistributedCOM permission"** ×4 — *failed* DCOM activations leave 10016 even when the technique doesn't fully execute. A cluster of 10016 to unusual CLSIDs is itself a DCOM-lateral lead.

### 3. Named-pipe remote shells — Sysmon `17` (created) / `18` (connected)
- **`lm_sysmon_18_remshell_over_namedpipe.evtx`** → Sysmon **18 = "Pipe Connected"** + Sysmon 1/3/10; Chainsaw flags **"Non Interactive PowerShell"** — a PowerShell shell tunnelled over a named pipe (`invoke-pipeshell`).
- **`LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx`** → Sysmon 13 — a **NullSessionPipes** registry add (Turla-style) that lets a pipe be reached anonymously. (Recall **Module 6** proved PsExec via the **`\PSEXESVC`** pipe with Sysmon **17 = Pipe Created**.)

### 4. Scheduled tasks & remote task ops — `4698/4702`, `atsvc`
- **`LM_ScheduledTask_ATSVC_target_host.evtx`** → a rich Security trail: **4698 = task created**, **4699 = deleted**, plus `4624`/`4672` (the network logon), `4776`, `5140/5145` on the **`atsvc`** pipe, `4661/4688`. Remote schtasks = the `ATSVC` named pipe + a new task.
- **`remote task update 4624 4702 same logonid.evtx`** → **4702 = task updated**, correlated to a **4624** with the *same LogonId* — proving the task op rode a specific remote logon.

### 5. Remote registry & share creation — Sysmon `12/13`, `5140/5145`
- **`lm_remote_registry_sysmon_1_13_3.evtx`** → Sysmon 1/3/12/13 — remote registry edits (winreg pipe).
- **`LM_NewShare_Added_Sysmon_12_13.evtx`** → Sysmon 12/13 on `…\LanmanServer\Shares` — a new share stood up (often to stage/retrieve tools).
- **`lateral_movement_startup_3_11.evtx`** → Sysmon **11 = FileCreate** in a **Startup** folder reached over an admin share = remote persistence drop.

### 6. RDP lateral movement — RdpCoreTS `131/140/104`, SharpRDP
- **`dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx`** → on the **target**, `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` events **131** (connection accepted) / 68 / 168.
- **`DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx`** → client-side RdpCoreTS **104** ×21.
- **`LM_sysmon_3_12_13_1_SharpRDP.evtx`** / **`LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx`** → SharpRDP (RDP abused for non-interactive command execution): Sysmon 1/3/12/13, with `\tsclient\` paths giving away the redirected drive.

### 7. The logon that carried it — `4624 Type 3`, `4672`, PtH
- **`LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`** → on the **source** box: `4624`, **4672 (admin logon)**, `4688` (mimikatz process), `1102`. This is the `sekurlsa::pth` machine — Pass-the-Hash being *launched*.
- **`ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx`** → Sysmon 1/3/18 + Security **4624** + **5145** — local PtH then a pipe/share hop.
- **`LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`** → Sysmon 1 for **`wsmprovhost.exe`** = the WinRM/PowerShell-Remoting target process (covered deeper in Module 9).

> **WMI note:** the decks list **WMI** (`wmic`/`Win32_Process` → `wmiprvse.exe` parent) alongside DCOM. The bundled set demonstrates its cousin **DCOM** (MMC20/ShellWindows) and Impacket `dcomexec`; for a pure `wmiexec` sample, `get-data.sh` points at the EVTX-ATTACK-SAMPLES *Lateral Movement* and *Execution* folders.

---

## Exercises
1. **Service vs logon:** parse `LM_Remote_Service02_7045.evtx` and read the 7045 **Service Name / ImagePath**. Then in a sample that has both, tie the install to its **4624 Type 3 + 4672**. What does the pairing prove that either event alone doesn't?
2. **DCOM line-up:** run Chainsaw on the three DCOM samples. Match each to its COM object (`MMC20.Application`, `ShellWindows`/`ShellBrowserWindow`, `mshta`/LethalHTA) and note the common parent `svchost.exe -k DcomLaunch`. Why are the failures only visible as System **10016**?
3. **Pipe rhythm:** in `lm_sysmon_18_remshell_over_namedpipe.evtx`, find the Sysmon **18 (Pipe Connected)** and the PowerShell it carried. Compare to Module 6's **17 (Pipe Created)** `\PSEXESVC` — what's the difference between *created* and *connected*?
4. **Same LogonId:** in `remote task update 4624 4702 same logonid.evtx`, confirm the **4702** and **4624** share a LogonId. Why is LogonId the glue that lets you attribute the task change to a specific remote session?

## Answers / what to find
- **PsExec/remote service:** System **7045** (service install, e.g. `PSEXESVC` or renamed) + **5145** on `\IPC$\svcctl` / the service pipe + Sysmon **17/18**. Meterpreter variant = `services.exe` → Base64 PowerShell.
- **DCOM:** Sysmon **1/3** with parent `svchost.exe -k DcomLaunch`; Chainsaw names **MMC20 Lateral Movement**, **LethalHTA**, ShellWindows/ShellBrowserWindow; failed activations = System **10016**.
- **Named pipe shell:** Sysmon **18 (Pipe Connected)** carrying non-interactive PowerShell.
- **Scheduled task:** **4698** (created) / **4702** (updated) / **4699** (deleted) over the **`atsvc`** pipe, tied to a **4624** by LogonId.
- **Remote registry/share/startup:** Sysmon **12/13** (registry), **11** (FileCreate in Startup), **5140/5145** (share access).
- **RDP:** RdpCoreTS **131/104/168** + SharpRDP Sysmon 1/3/12/13 with `\tsclient\` artefacts.
- **The carrier logon everywhere:** **4624 Type 3** (network) + **4672** (admin) — the through-line of lateral movement.

## Pivot
- Any flagged **process** → **Module 1 (Prefetch)** to prove it ran on the target.
- The **PowerShell** payloads here → **Module 9 (PowerShell tradecraft)**.
- The Sysmon events that made all of this visible → **Module 10 (Sysmon + WEF)**.

---
*Next: [Module 9 — PowerShell Tradecraft](../module-09-powershell-tradecraft).*
