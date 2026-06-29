# Module 8 — Lateral Movement

**Deck mapping:** *Intrusion Hunting Playbook* → "Detecting Lateral Movement" · *Advanced Intrusion Forensic Hunting* → "Phase 3: Lateral Movement."
**Goal:** learn to recognise how an attacker hops from one Windows machine to the next — **PsExec / remote services, DCOM, WMI, named pipes, scheduled tasks, remote registry & shares, and RDP** — by reading the exact events each technique burns into the logs.

> **New to this lab?** Do Module 5 (EvtxECmd) and Module 6 (Chainsaw/Hayabusa) first. This module assumes you can already parse an `.evtx` file to CSV and run a Sigma sweep. Every event ID and count below was produced by parsing the bundled files in the `dfir-aio` container, so what you read here is exactly what you will see on screen.

---

## 1. Background — why this matters

### What "lateral movement" actually is
An intrusion almost never ends on the first machine. The attacker lands somewhere (a phished laptop), steals credentials (Module 7), and then **moves sideways** — host to host — hunting for the data, the domain controller, or the backup server they actually want. That sideways hopping is **lateral movement**. It is the phase where a single infected laptop turns into a company-wide breach, so catching it early is the whole game.

### The one idea that makes it findable
Here is the key insight, and it is simpler than it looks. **A Windows machine cannot run a program on a *different* Windows machine by magic.** To execute code on a remote host, the attacker has to use one of a small number of built-in Windows remote-control mechanisms — the Service Control Manager, DCOM, WMI, the Task Scheduler, WinRM, or RDP. **Every one of those mechanisms is itself a Windows feature that writes its own log events.** So remote execution always leaves *two* footprints:

1. **The delivery mechanism** — *how the command arrived*: a service got installed, a COM object got activated, a named pipe got opened, a scheduled task got created.
2. **The carrier logon** — *the network session that carried it*: a **Security Event ID 4624 with Logon Type 3** (a logon that came in over the network, not from the keyboard) and usually a **4672** (that logon was granted administrator privileges).

Learn to spot the delivery mechanism, then tie it to its carrier logon, and lateral movement stops being invisible. That pairing — *"a service was installed"* **+** *"...by a network logon from host X at 02:14"* — is the sentence an investigator is trying to write.

### Two terms defined once
- **Named pipe** — a built-in Windows feature that lets two programs talk to each other, locally or *across the network over SMB* (the file-sharing protocol). Pipes have names like `\PSEXESVC` or `\svcctl`. Remote-admin tools use named pipes as their command channel, so a strange pipe name is a strong lead.
- **Logon Type 3 (network logon)** — when you sit at a keyboard you create a Type 2 (interactive) logon. When a *remote* machine authenticates to *this* machine to use a share, a service, or RPC, Windows records a **Type 3** logon. Lateral movement is overwhelmingly Type 3. (Type 10 = RDP; Module 7 covers the full type list.)

### The data set
This module's data is a curated slice of **EVTX-ATTACK-SAMPLES** by @sbousseaden — a public library of real ATT&CK-technique event logs. There is roughly **one `.evtx` per technique**, and each file is named for the event IDs it contains. The bundled files and their *real* contents are listed below; you will run tools against them by hand. See `data/README.md` for the full file-by-file provenance.

---

## 2. What the tools do

You will use the two tools you already met in Modules 5 and 6, on the same evidence, for two different jobs:

- **EvtxECmd** (Eric Zimmerman) — a parser. It reads a binary `.evtx` file and writes a flat **CSV** where every event is one row and the buried XML fields are pulled out into readable columns (`MapDescription`, `PayloadData1..6`, `RemoteHost`, `UserName`). Use it when you want to *read the raw fields by hand* — service names, pipe names, LogonIds.
- **Chainsaw** (WithSecure) — a hunter. It runs **Sigma rules** (community-written detection logic) across the events and prints a table that *names the technique* for you ("MMC20 Lateral Movement", "LethalHTA"). Use it when you want the tool to tell you *what* it found before you go read the details.

Rule of thumb for this module: **Chainsaw to name it, EvtxECmd to prove it.**

---

## 3. Setup

```bash
cd module-08-lateral-movement/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```
What each piece means:
- `docker run -it` — start the container interactively (so you get a shell).
- `--rm` — delete the container when you exit (your CSV output stays on the host because of the mount).
- `--network none` — run with **no network at all**. Forensics tooling never needs the internet, and cutting it off guarantees a sample can't "phone home." All analysis here is offline by design.
- `-v "$PWD":/data` — **mount** your current folder (the module's `data/`) into the container at `/data`. The container sees the evidence at `/data`; anything a tool writes to `/data` lands back in your real folder.
- `dfir-aio:v2` — the offline toolbox image; every tool below is already inside it.

> **Windows-native note:** the lab VM also ships the same EZ Tools natively under `C:\DFIR\tools`. There you would run `EvtxECmd.exe -f C:\path\file.evtx --csv C:\out` — identical flags, just `.exe` and Windows paths instead of the container's `/data`. Chainsaw/Hayabusa are likewise `chainsaw.exe` / `hayabusa.exe`. Everything below uses the container form.

Inside the container the prompt changes; `/data` is your evidence folder. The commands in the rest of this module are run **from that container shell**.

---

## 4. Step-by-step walkthrough

### Step 1 — Get the lay of the land (parse everything at once)
Before chasing any single technique, dump every file to CSV so you can see what is here.

```bash
EvtxECmd -d /data --csv /data/_out --csvf all_events.csv
```
- `EvtxECmd` — the parser.
- `-d /data` — **input directory**. Pointed at a *folder*, EvtxECmd parses every `.evtx` inside it. (Use `-f /data/one.evtx` to parse a single file instead — that `-f` form is what the per-technique steps below use.)
- `--csv /data/_out` — write CSV output into `/data/_out` (created if missing). Because `/data` is mounted, the result appears in your real `data/_out/` folder too.
- `--csvf all_events.csv` — the **f**ilename for that CSV (otherwise EvtxECmd auto-names it with a timestamp).

**Expected output (tail):** a per-file line for each `.evtx`, then a combined run summary ("Processed 26 files..."). Open `all_events.csv` in any spreadsheet. The columns you will live in for this module:
- **`EventId`** — the numeric event ID (7045, 5145, 4624...).
- **`MapDescription`** — EvtxECmd's plain-English label for that event ("A new service was installed", "A network share object was checked for access").
- **`PayloadData1..6`** — the important fields lifted out of the event XML (service name, pipe name, account).
- **`RemoteHost` / `UserName`** — who/where, when the event carries it.
- **`Payload`** — the full raw JSON, for when you need a field the columns didn't surface.

### Step 2 — PsExec & remote services (System **7045**, Security **5145**, Sysmon **17/18**)
**The mechanism:** tools in the *PsExec family* (Sysinternals PsExec, and clones RemCom and Impacket `psexec`) work in three moves: (a) copy a service executable to the target over the hidden `\ADMIN$` or `\C$` share; (b) ask the target's **Service Control Manager (SCM)** to install and start it as a Windows service — this is what writes **System Event ID 7045, "A service was installed"**; (c) talk to that running service over a **named pipe** to send commands and stream output. PsExec's default service is named `PSEXESVC` and its pipe is `\PSEXESVC`; clones rename both to blend in.

Parse the service-install file and read it:
```bash
EvtxECmd -f /data/LM_Remote_Service02_7045.evtx --csv /data/_out --csvf svc.csv
```
This file holds **three** 7045 events. The fields that matter are **Service Name** and **ImagePath** (the program the service runs). The real contents here are:

| # | Service Name | ImagePath |
|---|---|---|
| 1 | `spoolfool` | `cmd.exe` |
| 2 | `spoolsv`   | `cmd.exe` |
| 3 | `remotesvc` | `calc.exe` |

**Reading the output:** a legitimate service points its ImagePath at a real service binary in `System32` or `Program Files`. **Every row here is a red flag** — a Windows *service* whose job is to launch `cmd.exe` or `calc.exe` is never normal; that is the signature of execution-via-service. Note also the **deceptive names**: `spoolsv` and `spoolfool` are designed to look like the real print-spooler service `spoolsv.exe`. (This is exactly why you read the *ImagePath*, not just the name: the name lies, the ImagePath tells the truth.)

> **Accuracy note (corrected in this rewrite):** an earlier version of this README implied this file shows PsExec's `PSEXESVC`. It does **not** — the real services are `spoolfool` / `spoolsv` / `remotesvc` with `cmd.exe`/`calc.exe` image paths. The teaching point (read Service Name + ImagePath; a service launching `cmd`/`calc` is malicious) is unchanged, but the names are now accurate to the bundled data.

Now the SMB side. PsExec-style tools light up **Security Event ID 5145, "A network share object was checked for access"** (this requires *Detailed File Share* auditing, which the samples were captured with). 5145's key field is **RelativeTargetName** — the share path or pipe that was touched:

```bash
EvtxECmd -f /data/LM_Remote_Service01_5145_svcctl.evtx --csv /data/_out --csvf svcctl.csv
EvtxECmd -f /data/LM_renamed_psexecsvc_5145.evtx       --csv /data/_out --csvf renamed.csv
EvtxECmd -f /data/LM_REMCOM_5145_TargetHost.evtx       --csv /data/_out --csvf remcom.csv
EvtxECmd -f /data/LM_5145_Remote_FileCopy.evtx         --csv /data/_out --csvf filecopy.csv
```
What each file proves (real counts):
- **`LM_Remote_Service01_5145_svcctl.evtx`** — a single 5145 on the **`svcctl`** pipe over `\IPC$`. `svcctl` is the named pipe for the **remote Service Control Manager** — i.e. the RPC call that *creates the remote service*. svcctl-then-7045 is the textbook remote-service-install sequence.
- **`LM_renamed_psexecsvc_5145.evtx`** — **22 ×** 5145. A *renamed* PsExec service pipe (the attacker changed the default `\PSEXESVC` to hide). The pipe name in RelativeTargetName is your tell.
- **`LM_REMCOM_5145_TargetHost.evtx`** — **30 ×** 5145, from **RemCom** (an open-source PsExec clone) hitting the target.
- **`LM_5145_Remote_FileCopy.evtx`** — **869 ×** 5145. That huge count is **files being copied over an admin share** (`\ADMIN$` / `\C$`) — the staging step before execution. A burst of hundreds of 5145s to an admin share = tooling being dropped.

Finally, let Chainsaw name the Meterpreter-over-PsExec payload:
```bash
chainsaw hunt /data/LM_sysmon_psexec_smb_meterpreter.evtx \
  -s /opt/chainsaw/sigma \
  --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
- `chainsaw hunt FILE` — run detections against FILE.
- `-s /opt/chainsaw/sigma` — the folder of Sigma **r**ules baked into the image (3,700+).
- `--mapping ...sigma-event-logs-all.yml` — tells Chainsaw how to translate Sigma's field names onto Windows event fields. Without the mapping, the rules can't line up with the data.

This file is Sysmon `1/3/10/13/18`. Chainsaw flags **"PowerShell as a Service"** (a process whose parent is `services.exe` — i.e. spawned *by* a service) and **"Base64 Encoded PowerShell"** — a Meterpreter payload that landed as a service and ran encoded PowerShell. That `services.exe → encoded powershell.exe` parent/child chain is the heart of the detection.

### Step 3 — DCOM lateral movement (Sysmon **1/3**, System **10016**)
**The mechanism:** **DCOM** (Distributed COM) lets one machine create and drive a COM *object* on another machine. Some built-in COM objects can be coerced into running a command — `MMC20.Application`, `ShellWindows`, `ShellBrowserWindow`, `Excel.Application`, or `mshta`. When abused remotely, the object's host process (`mmc.exe`, `mshta.exe`, an Office app) runs the attacker's payload, and crucially it is **parented by `svchost.exe -k DcomLaunch`** (the service that brokers DCOM). That unusual parent is the giveaway.

```bash
chainsaw hunt /data/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx               -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
chainsaw hunt /data/LM_impacket_docmexec_mmc_sysmon_01.evtx               -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
chainsaw hunt /data/LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
What you see (real contents):
- **`LM_DCOM_MSHTA_LethalHTA_*`** (Sysmon 1 + 3) — Chainsaw: **"LethalHTA"** — `mshta.exe` spawned via DCOM to run a remote HTA payload.
- **`LM_impacket_docmexec_mmc_*`** (Sysmon 1 ×5, 3 ×4) — Chainsaw: **"MMC20 Lateral Movement"** — Impacket's `dcomexec` driving the **`MMC20.Application`** object → `mmc.exe`.
- **`LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx`** (Sysmon 3 ×3) — the **ShellWindows / ShellBrowserWindow** DCOM objects; here you mostly see the *network* (Sysmon 3) side.

Now the **failures**:
```bash
EvtxECmd -f /data/LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx --csv /data/_out --csvf dcom10016.csv
```
This file is **4 ×** System **10016, "The application-specific permission settings do not grant... DistributedCOM permission."** 10016 fires when a DCOM activation is *denied*. **Failed DCOM lateral movement still leaves 10016 events**, even when the payload never ran. A cluster of 10016 referencing unusual CLSIDs (the GUIDs that identify COM objects) is itself a DCOM-lateral lead — you can catch the *attempt*, not just the success.

### Step 4 — Named-pipe remote shells (Sysmon **17** created / **18** connected)
**The mechanism:** many remote shells (and C2 frameworks like Cobalt Strike) tunnel their command channel through a **named pipe** over SMB. Sysmon records pipe activity as **Event ID 17 = Pipe Created** (a process opened a new pipe to *listen* on) and **Event ID 18 = Pipe Connected** (a process *connected* to an existing pipe). Created = the server side stood up; connected = something talked to it.

```bash
chainsaw hunt /data/lm_sysmon_18_remshell_over_namedpipe.evtx -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
EvtxECmd -f /data/LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx --csv /data/_out --csvf nullpipe.csv
```
- **`lm_sysmon_18_remshell_over_namedpipe.evtx`** (Sysmon 1 ×3, 3, 10 ×2, **18**) — Chainsaw flags **"Non Interactive PowerShell"**: a PowerShell shell tunnelled over a named pipe (`invoke-pipeshell`-style). The Sysmon 18 is the pipe the shell rode in on.
- **`LM_add_new_namedpipe_..._nullsession_registry_turla_like_ttp.evtx`** (Sysmon **13** ×1) — a registry write that adds a pipe name to **`NullSessionPipes`** (Turla-style). That setting lets a pipe be reached **anonymously**, with no credentials — a stealth backdoor channel. The registry edit (Sysmon 13) is the artefact.

> Recall **Module 6** proved PsExec via the `\PSEXESVC` pipe with **Sysmon 17 (Pipe Created)**. Created vs Connected is the difference between *the listener appeared* and *someone dialled in*.

### Step 5 — Scheduled tasks & remote task ops (Security **4698/4702/4699**, `atsvc`)
**The mechanism:** the Windows Task Scheduler can be driven *remotely* over the **`atsvc`** named pipe (the classic `schtasks /s <host>` or Impacket `atexec`). Creating a task on the target writes **Security 4698 "A scheduled task was created"**; updating writes **4702**; deleting writes **4699**. A favourite trick is *create task → run once → delete* so the task is gone by morning — but 4698 *and* 4699 both survive in the log.

```bash
EvtxECmd -f /data/LM_ScheduledTask_ATSVC_target_host.evtx --csv /data/_out --csvf sched.csv
EvtxECmd -f "/data/remote task update 4624 4702 same logonid.evtx" --csv /data/_out --csvf taskupd.csv
```
- **`LM_ScheduledTask_ATSVC_target_host.evtx`** is a rich trail (real counts): **4698** (task created) ×1, **4699** (deleted) ×1, plus **4624** ×6 and **4672** ×5 (the network logons), **4776** ×4 (credential validation), **5140/5145** on the `atsvc` pipe, and **4661/4688**. Walk it top to bottom and you see the whole remote-schtasks operation: authenticate → open `atsvc` → create task → (run) → delete task.
- **`remote task update 4624 4702 same logonid.evtx`** — a **4702** (task updated) plus **4624** logons (×6) and a **1102** (log cleared). The lesson is **LogonId**: the 4702 and the relevant 4624 share the *same LogonId* value. LogonId is a number Windows assigns to one logon session; matching it across events is how you prove "*this* task change rode *that* specific remote logon," not some unrelated local activity.

### Step 6 — Remote registry, new shares & startup drops (Sysmon **12/13**, **11**; Security **5140/5145**)
**The mechanism:** with admin rights an attacker can reach across the network to (a) edit the target's **registry** (over the `winreg` pipe) to plant autoruns or weaken settings, (b) **create a new SMB share** to stage or exfiltrate tools, or (c) **drop a file into a Startup folder** over an admin share for persistence. Sysmon sees registry as **12** (key created/deleted), **13** (value set), **14** (renamed); file drops as **11 (FileCreate)**; the Security log sees share access as **5140/5145**.

```bash
EvtxECmd -f /data/lm_remote_registry_sysmon_1_13_3.evtx --csv /data/_out --csvf remreg.csv
EvtxECmd -f /data/LM_NewShare_Added_Sysmon_12_13.evtx   --csv /data/_out --csvf newshare.csv
EvtxECmd -f /data/lateral_movement_startup_3_11.evtx    --csv /data/_out --csvf startup.csv
```
- **`lm_remote_registry_sysmon_1_13_3.evtx`** (Sysmon 1/3/12/13) — remote registry edits arriving over the network.
- **`LM_NewShare_Added_Sysmon_12_13.evtx`** (Sysmon 12 ×1, 13 ×2) — registry writes under `...\LanmanServer\Shares` = **a new share was stood up**. New shares appearing on a workstation are abnormal and worth a hard look.
- **`lateral_movement_startup_3_11.evtx`** (Sysmon 3 + **11**) — a **FileCreate in a Startup folder**, reached over an admin share = remote persistence drop. Whatever lands in Startup runs at next logon.

### Step 7 — RDP lateral movement (RdpCoreTS **131 / 98 / 140 / 104**, SharpRDP)
**The mechanism:** RDP is the graphical "remote desktop" you already know, but attackers also abuse it for *non-interactive command execution* (tools like **SharpRDP** type commands into the login screen / run-box). On the **target**, RDP connection events live in `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`. The most useful IDs:
- **131** — the server **accepted a new TCP connection** from a client IP. This fires *before* authentication, so it captures the **source IP of whoever is knocking** — even on failed attempts.
- **98** — a connection was **successfully established** (the TCP/RDP session came up).
- **140** — a **failed** authentication where the username does *not* exist; also records the source IP. Great for spotting password-spray against RDP.

```bash
EvtxECmd -f /data/dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx        --csv /data/_out --csvf rdp_target.csv
EvtxECmd -f /data/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx   --csv /data/_out --csvf rdp_client.csv
chainsaw hunt /data/LM_sysmon_3_12_13_1_SharpRDP.evtx           -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
chainsaw hunt /data/LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx  -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
- **`dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx`** — on the **target**: **131** ×22 (connections accepted), plus 68 ×9 and 168 ×9 (session/reconnect bookkeeping).
- **`DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx`** — **client-side** RdpCoreTS **104** ×21. Client-side RDP artefacts are how you prove a given workstation was the *source* of an RDP hop.
- The two **SharpRDP** files (Sysmon 1/3/12/13, with **17 registry edits** in one) show RDP being abused without a human at the screen; watch for **`\tsclient\`** paths in the data — that is the attacker's *redirected local drive* showing up on the target, a strong sign the "RDP session" was really a tool.

### Step 8 — The logon that carried it (Security **4624 Type 3**, **4672**, Pass-the-Hash)
Every technique above rides a logon. Two files show the **source** and the **handoff**:
```bash
EvtxECmd -f /data/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx --csv /data/_out --csvf pth_src.csv
EvtxECmd -f "/data/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx" --csv /data/_out --csvf pth_local.csv
```
- **`LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`** — on the **attacker's** box: **4624** + **4672** (a logon granted admin) + **4688** ×3 (the mimikatz process) + **1102** (the Security log being cleared). This is the machine *launching* `sekurlsa::pth` (**Pass-the-Hash** — authenticating with a stolen password *hash* instead of the password). 1102 right after the attack tool is the classic "cover your tracks" tell.
- **`ImpersonateUser-via local Pass The Hash...evtx`** — Sysmon 1/3/18 + Security **4624** + **5145**: a local PtH, then a pipe/share hop. The **4624 Type 3** is the through-line.
- **`LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`** (Sysmon 1) — `wsmprovhost.exe`, the **WinRM / PowerShell-Remoting target process**. Seeing `wsmprovhost.exe` means *someone remoted in via WinRM*. (Module 9 goes deep on this.)

> **WMI note:** the decks pair **WMI** (`wmic`/`Win32_Process` → child of `wmiprvse.exe`) with DCOM. The bundled set demonstrates DCOM (MMC20/ShellWindows) and Impacket `dcomexec`; for a pure `wmiexec` capture, `get-data.sh` pulls the full EVTX-ATTACK-SAMPLES *Lateral Movement* and *Execution* folders so you can practice the WMI variant too.

---

## 5. Reading the output — suspicious vs benign at a glance

| Artefact | Benign version | Suspicious version |
|---|---|---|
| **7045** service install | ImagePath in `System32`/`Program Files`, signed vendor service | ImagePath = `cmd.exe`/`calc.exe`/`powershell.exe`/temp path; random or spoofed name (`spoolsv` vs real `spoolsv.exe`) |
| **5145** share access | occasional `\IPC$`, normal file shares | bursts to `\ADMIN$`/`\C$`, or pipes named `\svcctl`, `\PSEXESVC`, `\atsvc`, `\winreg` |
| **Sysmon 1** process | parent matches the child's normal launcher | parent = `services.exe` (service-spawned shell) or `svchost.exe -k DcomLaunch` (DCOM) for `cmd`/`mshta`/`mmc` |
| **Sysmon 17/18** pipe | known app pipes | unusual pipe carrying PowerShell; `NullSessionPipes` edited |
| **4698/4702** task | admin creating a known maintenance task | task created *and deleted* minutes apart; action runs an encoded command |
| **RdpCoreTS 131/140** | expected admin IPs | external/unexpected source IP; many 140s = username spray |
| **4624 Type 3 + 4672** | service accounts to expected servers | admin Type 3 from a *workstation*, off-hours, right before a 7045/4698 |

The single most powerful move in this whole module is **correlation**: take a delivery event (7045, 4698, a DCOM Sysmon 1) and find the **4624 Type 3 + 4672** within a second or two of it, with a matching **LogonId**. That pairing is what turns "a weird service exists" into "host A, user *svc-backup*, pushed a service to host B at 02:14 over the network."

---

## 6. Investigative narrative — the story the evidence tells

Stitch the files into one intrusion and they read like a timeline:

1. On the **source** machine, `mimikatz sekurlsa::pth` runs (**4688**) and grabs an admin token; the attacker clears the log (**1102**) — *`LM_4624_mimikatz...source_machine`*.
2. Using that stolen hash, they authenticate to a **target** as a **network logon** (**4624 Type 3 + 4672**).
3. They pick a delivery method:
   - push a **service** that runs `cmd.exe` (**7045**) over `svcctl` (**5145**) — *the `spoolfool`/`remotesvc` installs*; or
   - fire **DCOM** so `mshta`/`mmc` runs under `DcomLaunch` (**LethalHTA**, **MMC20**); or
   - drop a **scheduled task** over `atsvc` (**4698**), run it, and **delete** it (**4699**); or
   - open an **RDP** session (RdpCoreTS **131**) and drive **SharpRDP**.
4. They establish a foothold: a **named-pipe shell** (**Sysmon 18**), a **new share** (Sysmon 12/13), or a **Startup drop** (Sysmon 11) for persistence.
5. Everywhere they go, the **4624 Type 3** carrier logon is the thread that ties each delivery event back to a specific session — and the matching **LogonId** lets you attribute it.

That is lateral movement told as a story: *credential theft → network logon → remote execution → persistence*, host to host.

---

## 7. Try-it-yourself exercises

1. **Service vs logon.** Parse `LM_Remote_Service02_7045.evtx`; list each 7045's **Service Name** and **ImagePath**. Which two names impersonate a real Windows service, and how does the ImagePath give them away? Then, in a file that has both, tie a 7045 to its **4624 Type 3 + 4672**. What does the pairing prove that either event alone doesn't?
2. **DCOM line-up.** Run Chainsaw on the three DCOM samples. Match each to its COM object (`MMC20.Application`, `ShellWindows`/`ShellBrowserWindow`, `mshta`/LethalHTA) and note the shared parent `svchost.exe -k DcomLaunch`. Then open `LM_dcom_..._10016.evtx` — why are the *failed* activations only visible as System **10016**, and why is a cluster of 10016 still a useful lead?
3. **Pipe rhythm.** In `lm_sysmon_18_remshell_over_namedpipe.evtx`, find the Sysmon **18 (Pipe Connected)** and the PowerShell it carried. Compare to Module 6's **17 (Pipe Created)** on `\PSEXESVC`. In your own words, what is the difference between *created* and *connected*, and which one means "someone dialled in"?
4. **Same LogonId.** In `remote task update 4624 4702 same logonid.evtx`, confirm the **4702** and a **4624** share a LogonId. Why is LogonId the glue that lets you attribute the task change to one specific remote session rather than to background noise?
5. **Find the source IP.** In `dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx`, read a **131** event. What client IP is knocking, and why is 131 useful even when the logon *fails*?

---

## 8. Key takeaways

- Remote execution needs a built-in Windows mechanism, and **every mechanism logs itself** — so lateral movement always leaves a *delivery* event **and** a *carrier logon*.
- **Delivery signatures:** PsExec/services = **7045** + **5145**(`svcctl`/pipe) + Sysmon **17/18**; DCOM = Sysmon **1/3** parented by `DcomLaunch` (failures = System **10016**); named-pipe shell = Sysmon **18**; scheduled task = **4698/4699/4702** over `atsvc`; remote registry/share/startup = Sysmon **12/13/11** + **5140/5145**; RDP = RdpCoreTS **131/98/140/104** + SharpRDP `\tsclient\`.
- **The carrier logon is always there:** **4624 Type 3** (network) + **4672** (admin). Correlate it to the delivery event by **time** and **LogonId** to attribute the hop.
- **Read the ImagePath, not the name** — service/process names lie (`spoolsv` vs `spoolsv.exe`); the path and parent tell the truth.
- **Chainsaw to name it, EvtxECmd to prove it.**

---

## 9. Sources & further reading

- JPCERT/CC — *Detecting Lateral Movement through Tracking Event Logs* (the reference catalogue of which tool leaves which event): https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf
- Microsoft Learn — *4624: An account was successfully logged on* (logon types): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10-security/auditing/event-4624
- Microsoft Learn — *4697 / 7045: A service was installed in the system*: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10-security/auditing/event-4697
- Cyber Triage — *DFIR Breakdown: Impacket Remote Execution (smbexec/psexec/atexec)*: https://www.cybertriage.com/blog/dfir-breakdown-impacket-remote-execution-activity-smbexec/
- The DFIR Spot — *Lateral Movement: RDP Event Logs* (RdpCoreTS 131/140): https://www.thedfirspot.com/post/lateral-movement-remote-desktop-protocol-rdp-event-logs
- Ponder The Bits — *Windows RDP-Related Event Logs: Identification, Tracking, and Investigation*: https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
- @sbousseaden — *EVTX-ATTACK-SAMPLES* (the source of this module's data): https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

See `data/README.md` for the exact provenance and license of each bundled `.evtx`.

## Pivot
- Any flagged **process** → **Module 1 (Prefetch)** to prove it executed on the target.
- The **PowerShell** payloads here → **Module 9 (PowerShell tradecraft)**.
- The Sysmon events that made all of this visible → **Module 10 (Sysmon + WEF)**.

---
*Next: [Module 9 — PowerShell Tradecraft](../module-09-powershell-tradecraft).*
