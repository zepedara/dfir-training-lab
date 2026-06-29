# Module 9 — PowerShell Tradecraft

**Deck mapping:** *Intrusion Hunting Playbook* → "Hunting Malicious PowerShell" · *Advanced Intrusion Forensic Hunting* → "Living-off-the-Land / Script-Based Attacks."
**Goal:** catch obfuscated, encoded, in-memory PowerShell — the attacker's favourite "living-off-the-land" tool — using **Script Block Logging (Event ID 4104)** and **Module Logging (4103)**, and know the **Sysmon backstop** for when those logs are switched off.

> **Prerequisite:** Modules 5 and 6 (parsing `.evtx`, running Chainsaw). Every event ID, count, and Chainsaw detection name below was produced by parsing the bundled files on the lab VM.

---

## 1. Background — why this matters

### Why attackers love PowerShell
PowerShell is the scripting language built into every modern Windows box. Attackers reach for it constantly because it is:
- **Already there and trusted** — it is signed by Microsoft, so it sails past app-allow-listing ("living off the land" = using the tools already installed instead of dropping a new `.exe`).
- **Memory-resident** — it can download code and run it *straight from memory* (`IEX (New-Object Net.WebClient).DownloadString(...)`), leaving nothing on disk for antivirus to scan.
- **Trivially obfuscated** — the same command can be Base64-encoded, string-reversed, or split into a hundred concatenated pieces, so the *command line* you see in a process log is often gibberish.

That last point is the whole problem: if you only watch command lines, a determined attacker hides from you. Defenders answer with logging that records **what PowerShell actually ran**, not what was typed.

### The three PowerShell log sources (and how each works)
1. **Script Block Logging — Event ID 4104** in the `Microsoft-Windows-PowerShell/Operational` log. **This is the crown jewel.** Here is the mechanism that makes it special: PowerShell logs a *script block* **at compile time** — the moment *after* the engine has decoded every layer of obfuscation but *before* it runs the code. So no matter how the attacker encoded the command, **4104 records the final, de-obfuscated, human-readable script**. (PowerShell hands that same compiled text to **AMSI**, the Antimalware Scan Interface, for inspection — same hook, same de-obfuscated view.) A long script is split across several 4104 events that share one **ScriptBlockId**. Critically, even if an admin never *fully* enabled Script Block Logging, PowerShell **auto-logs script blocks it deems suspicious at Warning level** — so tokens like `Invoke-Expression`, `FromBase64String`, or `DownloadString` often get recorded anyway.
2. **Module Logging — Event ID 4103** (same log): records each command in the pipeline *with its parameter values*. Where 4104 gives you the whole script block, 4103 gives you the per-command play-by-play.
3. **Classic engine events** — `400/403/600` in the older `Windows PowerShell` log, plus host/IPC events `40961/40962/53504`: weaker and less detailed, but present even on old or minimally configured machines, so worth knowing.

### When the logs are off: the Sysmon backstop
Smart attackers try to *disable* script logging, or run PowerShell **without `powershell.exe`** at all — they load the PowerShell engine DLL (`System.Management.Automation.dll`) into some *other* process ("unmanaged" or "in-memory" PowerShell, e.g. Cobalt Strike's `powerpick`, PSInject). That kind of PowerShell **never produces a 4104**. But **Sysmon** still sees the behaviour:
- **Sysmon 1** — the `powershell.exe` command line (when it is used).
- **Sysmon 7 (Image Loaded)** — `System.Management.Automation.dll` loaded by a **non-PowerShell** process = the tell-tale sign of unmanaged PowerShell.
- **Sysmon 8 (CreateRemoteThread)** — code injection into another process.
- **Sysmon 10 (ProcessAccess)** — one process opening a handle into another, classically **LSASS** = credential dumping.

So the lesson of this module is a *layered* one: **4104 reads the script; Sysmon catches the PowerShell that tried not to be a script.**

### The data set
The bundled files are **EVTX-ATTACK-SAMPLES** captures from the Execution and Defense-Evasion categories. Each is named for the event IDs it contains; the real contents are listed per step. See `data/README.md` for full provenance.

---

## 2. What the tools do
- **EvtxECmd** — parses an `.evtx` to CSV. For this module the gold column is **`PayloadData`/`Payload`**, which holds the **ScriptBlockText** (the decoded script) for 4104 events.
- **Chainsaw** — runs Sigma rules and *names* the malicious PowerShell behaviour ("Malicious PowerShell Keywords", "PowerShell Get-Process LSASS in ScriptBlock", "Remote Thread Creation").

**Chainsaw to name it, EvtxECmd to read the actual script.**

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-09-powershell-tradecraft/data
```
(Every command in this module is run **from inside this `data/` folder**. `EvtxECmd` and `chainsaw` are installed natively and already on your `PATH`, so you call them directly by name in Git Bash — no container, no Docker. The VM is kept offline. See Module 8 §3.)

> **Chainsaw rules/mappings path:** the `chainsaw hunt` commands below point `-s` at the bundled Sigma rules and `--mapping` at `sigma-event-logs-all.yml` (shown here as `/opt/chainsaw/...`). Those live wherever **chainsaw** is installed on your lab VM — adjust if your VM's paths differ.

---

## 4. Step-by-step walkthrough

### Step 1 — Read the de-obfuscated script blocks (Event ID 4104)
There are three real Script-Block-Logging samples. Parse them and read the script text directly.

```bash
EvtxECmd -f exec_emotet_ps_4104.evtx                                  --csv _out --csvf emotet.csv
EvtxECmd -f phish_windows_credentials_powershell_scriptblockLog_4104.evtx --csv _out --csvf phish.csv
EvtxECmd -f Powershell_4104_MiniDumpWriteDump_Lsass.evtx             --csv _out --csvf minidump.csv
```
- `-f <file>` — the single `.evtx` to parse.
- `--csv _out` — output folder (`_out`, created right beside the evidence in the current `data/` folder).
- `--csvf <name>.csv` — the output filename.

Open each CSV and read the **`Payload`** column — for a 4104 event it contains the **ScriptBlockText**, the decoded script. Real contents:
- **`exec_emotet_ps_4104.evtx`** — **one** 4104 carrying an obfuscated **Emotet** downloader block.
- **`phish_windows_credentials_powershell_scriptblockLog_4104.evtx`** — **two** 4104 events; the **Invoke-CredentialPhisher** technique — it pops a *fake* Windows authentication box and validates what the victim types via a `ValidateCredentials` loop (a credential stealer written in pure PowerShell).
- **`Powershell_4104_MiniDumpWriteDump_Lsass.evtx`** — **one** 4104 plus host events `40961/40962/53504`. The script (`C:\Users\Public\lsass_wer_ps.ps1`) calls **`MiniDumpWriteDump`** against **`Get-Process lsass`** — i.e. it dumps the memory of LSASS (where Windows keeps credentials) entirely in PowerShell.

Now let Chainsaw name the MiniDump sample:
```bash
chainsaw hunt Powershell_4104_MiniDumpWriteDump_Lsass.evtx \
  -s /opt/chainsaw/sigma \
  --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
**Expected output (real, abridged):**
```
[+] Group: Sigma
 timestamp            detections                                          Event ID  Computer      Channel
 2020-06-30 14:24:08  ‣ Malicious PowerShell Keywords                     4104      MSEDGEWIN10   PowerShell/Operational
                      ‣ PowerShell Get-Process LSASS in ScriptBlock
                      ‣ Suspicious Process Discovery With Get-Process
                      ‣ WinAPI Function Calls Via PowerShell Scripts
 ScriptBlockText: "function Memory($path) ... $Process = Get-Process lsass ...
                   $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump'...
 Path: C:\Users\Public\lsass_wer_ps.ps1
```
**Reading the output:** *four independent Sigma rules* fire on a **single** 4104 event. The attacker never typed the word "lsass" on a visible command line — but `MiniDumpWriteDump` + `Get-Process lsass`, written to a script in `C:\Users\Public\`, is unambiguous credential theft, and **the script block text gave it all up**. This is the whole point of 4104: obfuscation hides the *command line*, not the *compiled script*.

### Step 2 — The Sysmon backstop (when 4104 is off or bypassed)
Now the same goal — dumping credentials with PowerShell — but seen through **Sysmon** instead of 4104, because the attacker ran unmanaged/in-memory PowerShell.

```bash
chainsaw hunt babyshark_mimikatz_powershell.evtx -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
chainsaw hunt de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
- **`babyshark_mimikatz_powershell.evtx`** — Sysmon `1/3/4/5/7/10/11/12/16`. Chainsaw flags **"Potential Credential Dumping Attempt Via PowerShell"** (driven by **Sysmon 10 / ProcessAccess** opening `lsass.exe`) and **"Non Interactive PowerShell."** This is the *Sysmon* view of a PowerShell credential attack — **no 4104 needed**. (The Sysmon **16** events here are Sysmon's own config-state-change records.)
- **`de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx`** — Sysmon **7** (image load) + **8 (CreateRemoteThread) ×82** + **10**. A non-PowerShell process loaded `System.Management.Automation.dll` (Sysmon 7) and then injected **82** remote threads (Sysmon 8) = **unmanaged PowerShell injection** (PSInject / `powerpick`-style). Chainsaw flags **"PowerShell Core DLL Loaded By Non PowerShell Process"** (the Sysmon 7 unmanaged-PowerShell load) and **"Remote Thread Creation In Uncommon Target Image"** (the Sysmon 8 injection).

**Why this matters:** unmanaged PowerShell is *invisible to 4104* because no script block is compiled by `powershell.exe` — but the **DLL load (7)** and **thread injection (8)** are loud in Sysmon. If you only had the PowerShell log enabled, you would have missed this entirely. That is the argument for running *both* sensors.

### Step 3 — Evasion & remoting traces
Attackers prepare the ground by weakening PowerShell's defences first; those changes are themselves detections.

```bash
EvtxECmd -f DE_Powershell_CLM_Disabled_Sysmon_12.evtx        --csv _out --csvf clm.csv
EvtxECmd -f de_powershell_execpolicy_changed_sysmon_13.evtx  --csv _out --csvf execpol.csv
EvtxECmd -f RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx --csv _out --csvf winrm.csv
EvtxECmd -f LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx  --csv _out --csvf remoting.csv
chainsaw hunt LM_sysmon_remote_task_src_powershell.evtx -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
- **`DE_Powershell_CLM_Disabled_Sysmon_12.evtx`** — Sysmon **12** (registry key event). **Constrained Language Mode (CLM)** is a PowerShell lockdown that blocks the dangerous API calls attackers need; this sample is an attempt to *disable* it (via `__PSLockdownPolicy`) so full PowerShell can run.
- **`de_powershell_execpolicy_changed_sysmon_13.evtx`** — Sysmon **13** ×5 — the **ExecutionPolicy** flipped via the registry. ExecutionPolicy is a weak control (it is trivially bypassed), but *changing it* is still a behavioural tell worth flagging.
- **`RemotePowerShell_..._EventID_169.evtx`** — `Microsoft-Windows-WinRM/Operational` **169** ×3 (a user **authenticated** over WinRM) + **193** ×3. This is the authentication trail of **PowerShell Remoting** (running PowerShell on a remote box via WinRM).
- **`LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`** — Sysmon **1** for **`wsmprovhost.exe`**, the process that hosts an incoming PowerShell-Remoting session. Seeing `wsmprovhost.exe` spawn things = someone is driving this box remotely.
- **`LM_sysmon_remote_task_src_powershell.evtx`** — Sysmon 3/7 — PowerShell acting as the *source* of a remote scheduled task (ties straight back to Module 8).

---

## 5. Reading the output — suspicious vs benign

| Signal | Benign | Suspicious |
|---|---|---|
| **4104 ScriptBlockText** | admin one-liners, signed modules | `IEX`, `FromBase64String`, `DownloadString`, `-enc`, `MiniDumpWriteDump`, `Get-Process lsass`, reflection into `Win32` APIs |
| **4104 Level** | Information | **Warning** (PowerShell auto-flagged it as suspicious) |
| **Sysmon 7** image load | `Automation.dll` loaded by `powershell.exe`/`pwsh.exe` | `Automation.dll` loaded by a *non-PowerShell* process (unmanaged PowerShell) |
| **Sysmon 8** | rare, from debuggers | bursts of CreateRemoteThread into `explorer`, `lsass`, browsers |
| **Sysmon 10** target | normal inter-process | handle into **`lsass.exe`** from PowerShell = credential dump |
| **Sysmon 12/13** | software installs | `__PSLockdownPolicy` / ExecutionPolicy changed right before a PowerShell burst |
| **WinRM 169 / `wsmprovhost.exe`** | expected admin remoting | remoting from an unexpected host or account |

The headline skill: **read the decoded `ScriptBlockText`.** Obfuscation lives on the command line; intent lives in the compiled script, and 4104 hands you the script.

---

## 6. Investigative narrative — the story the evidence tells
Put the files in attacker order and a coherent operation appears:
1. **Prepare:** disable **CLM** (Sysmon 12) and flip **ExecutionPolicy** (Sysmon 13) so unrestricted PowerShell will run.
2. **Deliver:** an obfuscated **Emotet** downloader runs — but 4104 logs the *decoded* block anyway (`exec_emotet_ps_4104`).
3. **Steal credentials**, two ways:
   - in-script, caught by **4104** — `MiniDumpWriteDump` against `Get-Process lsass` (`Powershell_4104_MiniDumpWriteDump_Lsass`); or
   - in-memory, caught by **Sysmon 10** opening `lsass.exe` (`babyshark_mimikatz_powershell`), or by **Sysmon 7+8** when the PowerShell engine is injected into another process (`de_unmanagedpowershell_psinject`).
4. **Phish more creds** with a fake auth prompt (`Invoke-CredentialPhisher`, 4104).
5. **Spread:** authenticate over **WinRM** (169), land as **`wsmprovhost.exe`**, and create remote scheduled tasks from PowerShell — handing off to Module 8.

The moral: **two telemetries, one truth.** Where 4104 is on, it reads the script; where it is off, Sysmon catches the behaviour. An investigator wants both, because attackers specifically try to blind the first.

---

## 7. Try-it-yourself exercises
1. **Obfuscation can't hide intent.** Read the **ScriptBlockText** in `exec_emotet_ps_4104.evtx` and `Powershell_4104_MiniDumpWriteDump_Lsass.evtx`. List the give-away tokens (`IEX`, `FromBase64String`, `DownloadString`, `MiniDumpWriteDump`, `Get-Process lsass`). Explain in one sentence why the *decoded* text betrays the attack even when the launch command was Base64.
2. **Same goal, two telemetries.** `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` (4104) and `babyshark_mimikatz_powershell.evtx` (Sysmon 10) both dump LSASS via PowerShell. Which log caught which? What would you have **missed** if only one source were enabled?
3. **Spot the injection.** In `de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx`, find the Sysmon **7** loading `System.Management.Automation.dll` into a non-PowerShell process and the burst of Sysmon **8 (CreateRemoteThread)** (there are 82). Why is "unmanaged PowerShell" invisible to 4104?
4. **Evasion first.** If you saw `DE_Powershell_CLM_Disabled_Sysmon_12.evtx` and `de_powershell_execpolicy_changed_sysmon_13.evtx` *before* a 4104 burst on the same host, what story do those changes tell about what is coming next?
5. **Count the rules.** Run Chainsaw on the MiniDump file and count how many distinct Sigma rules fire on the **single** 4104 event. Why do multiple independent rules firing on one event raise your confidence?

---

## 8. Key takeaways
- **4104 (Script Block Logging)** is the headline source: it records the **fully de-obfuscated script**, captured at compile time, even when the launch command was encoded — and PowerShell auto-logs suspicious blocks at **Warning** even without full configuration.
- **4103 (Module Logging)** is the per-command companion; the bundled captures are 4104-centric, so 4103 is taught conceptually (`get-data.sh` pulls samples that include it).
- **Sysmon is the backstop:** **10** (PowerShell → LSASS), **8** (CreateRemoteThread injection), **7** (`Automation.dll` in a non-PS process = unmanaged PowerShell), **1** (the command line). Run it *alongside* PowerShell logging.
- **Evasion leaves marks:** Sysmon **12/13** for CLM / ExecutionPolicy tampering; WinRM **169** + `wsmprovhost.exe` for remote PowerShell.
- **Read the decoded ScriptBlockText** — that is where intent lives.

---

## 9. Sources & further reading
- Microsoft — *About Logging Windows / PowerShell Script Block Logging* (the official mechanism): https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- TrustedSec — *Building a Detection Foundation, Part 3: PowerShell and Script Logging*: https://trustedsec.com/blog/building-a-detection-foundation-part-3-powershell-and-script-logging
- Splunk — *Hunting for Malicious PowerShell using Script Block Logging*: https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
- Red Canary Threat Detection Report — *PowerShell*: https://redcanary.com/threat-detection-report/techniques/powershell/
- FireEye/Mandiant — *Greater Visibility Through PowerShell Logging* (4103/4104 background): https://cloud.google.com/blog/topics/threat-intelligence/greater-visibility/
- @sbousseaden — *EVTX-ATTACK-SAMPLES* (the source of this module's data): https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

See `data/README.md` for the exact provenance and license of each bundled `.evtx`.

## Pivot
- LSASS access here → **Module 7 (Identity & Credential Theft)** for the logon fallout.
- PowerShell-driven remote tasks / remoting → **Module 8 (Lateral Movement)**.
- The Sysmon IDs that made the backstop work → **Module 10 (Sysmon + WEF)**.

---
*Next: [Module 10 — Sysmon + WEF](../module-10-sysmon-wef).*
