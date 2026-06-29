# Module 9 — PowerShell Tradecraft

**Deck mapping:** *Intrusion Hunting Playbook* → "Hunting Malicious PowerShell" · *Advanced Intrusion Forensic Hunting* → "Living-off-the-Land / Script-Based Attacks."
**Goal:** catch obfuscated, encoded, in-memory PowerShell — the attacker's favourite LOLBin — using **Script Block Logging (4104)** and **Module Logging (4103)**, and know the Sysmon backstop for when those logs are off.

---

## Concept (from the decks)
PowerShell is ideal for attackers: signed, everywhere, runs code straight from memory, and encodes/obfuscates trivially. Defenders answer with three log sources:
- **Script Block Logging — Event ID 4104** (`Microsoft-Windows-PowerShell/Operational`). The crown jewel: PowerShell logs the **fully de-obfuscated script block text** *after* it decodes `-EncodedCommand`/Base64/string-concat tricks. The attacker can obfuscate the command line all they like — **4104 records what actually ran.** Auto-flagged suspicious blocks are logged at **Warning** level even if Script Block Logging isn't fully enabled.
- **Module Logging — Event ID 4103** (`…/PowerShell/Operational`): per-pipeline command + parameter logging.
- **Classic engine events** — `400/403/600` (`Windows PowerShell` log) and host/IPC events `40961/40962/53504`: weaker, but present even on old boxes.

When script logging is **disabled** (attackers try: see the CLM/ExecutionPolicy samples below), you fall back to **Sysmon** — `1` (powershell command line), `7` (`System.Management.Automation.dll` loaded by a non-PowerShell process = "unmanaged"/injected PowerShell), `8` (CreateRemoteThread injection), `10` (LSASS access from PowerShell).

This module's bundled data is **EVTX-ATTACK-SAMPLES** Execution/Defense-Evasion captures; every event ID and detection below was confirmed by parsing the files.

---

## Setup
```bash
cd module-09-powershell-tradecraft/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

---

## Step 1 — Read the de-obfuscated script blocks (4104)
The three real Script-Block-Logging samples:
- **`exec_emotet_ps_4104.evtx`** → one **4104** carrying an obfuscated **Emotet** downloader block.
- **`phish_windows_credentials_powershell_scriptblockLog_4104.evtx`** → **4104** ×2; Chainsaw catches the `ValidateCredentials` loop of **Invoke-CredentialPhisher** (a fake auth-prompt credential stealer).
- **`Powershell_4104_MiniDumpWriteDump_Lsass.evtx`** → **4104** + host events `40961/40962/53504`; the block at `C:\Users\Public\lsass_wer_ps.ps1` calls **`MiniDumpWriteDump`** against **`Get-Process lsass`** — credential dumping in pure PowerShell.

```bash
# Parse and read the script block text:
EvtxECmd -f /data/Powershell_4104_MiniDumpWriteDump_Lsass.evtx --csv /data --csvf ps4104.csv
# The PayloadData / ScriptBlockText columns hold the decoded script.

# Or let Chainsaw name the technique:
chainsaw hunt /data/Powershell_4104_MiniDumpWriteDump_Lsass.evtx \
  -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
**Expected output (real):**
```
 timestamp            detections                              Event ID  Computer      Channel
 2020-06-30 14:24:08  ‣ Malicious PowerShell                  4104      MSEDGEWIN10   PowerShell/Operational
                      ‣ LSASS in ScriptBlock
                      ‣ PowerShell Get-Process
                      ‣ Suspicious Process Discovery Via PowerShell Scripts
```
**Read it:** four independent rules fire on one **4104** event — `MiniDumpWriteDump` + `Get-Process lsass` written to `C:\Users\Public\` is unambiguous credential theft. The attacker never typed `lsass` on a visible command line; **the script block gave it up.**

---

## Step 2 — The Sysmon backstop (when 4104 is off)
Attackers disable logging or run **in-memory/unmanaged** PowerShell that never spawns `powershell.exe`. Sysmon still sees it:
- **`babyshark_mimikatz_powershell.evtx`** → Sysmon `1/3/7/10/11/12`; Chainsaw: **"Potential Credential Dumping Attempt Via PowerShell"** from Sysmon **10 (ProcessAccess)** opening `lsass.exe`, plus **"Non Interactive PowerShell."** This is the *Sysmon* view of a PowerShell credential attack — no 4104 needed.
- **`de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx`** → Sysmon **8 (CreateRemoteThread)** ×82 + **7 (image load)** + **10**; Chainsaw: **"Remote Thread Creation."** A non-PowerShell process loaded `System.Management.Automation.dll` and injected threads = **unmanaged PowerShell injection** (e.g. PSInject / Cobalt Strike `powerpick`).

```bash
chainsaw hunt /data/babyshark_mimikatz_powershell.evtx \
  -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```

---

## Step 3 — Evasion & remoting traces
- **`DE_Powershell_CLM_Disabled_Sysmon_12.evtx`** → Sysmon **12** — an attempt to disable **Constrained Language Mode** (`__PSLockdownPolicy`) so unrestricted PowerShell can run.
- **`de_powershell_execpolicy_changed_sysmon_13.evtx`** → Sysmon **13** ×5 — **ExecutionPolicy** flipped via registry (a weak control, but the change itself is a tell).
- **`LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`** → Sysmon 1 for **`wsmprovhost.exe`** = PowerShell Remoting / WinRM target.
- **`RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx`** → `Microsoft-Windows-WinRM/Operational` **169** ×3 (a user **authenticated** over WinRM) + 193 — the remoting authentication trail.
- **`LM_sysmon_remote_task_src_powershell.evtx`** → Sysmon 3/7 — PowerShell as the *source* of a remote scheduled task (ties back to Module 8).

---

## Exercises
1. **Obfuscation can't hide intent:** open `exec_emotet_ps_4104.evtx` and `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` and read the **ScriptBlockText**. List the give-away tokens (`IEX`, `FromBase64String`, `DownloadString`, `MiniDumpWriteDump`, `Get-Process lsass`). Note how the *decoded* text betrays the attack even when the launch command was encoded.
2. **Same goal, two telemetries:** `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` (4104) and `babyshark_mimikatz_powershell.evtx` (Sysmon 10) both dump LSASS via PowerShell. Which log caught which, and what would you have **missed** if only one source were enabled?
3. **Spot the injection:** in `de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx`, find Sysmon **7** loading `System.Management.Automation.dll` into a non-PowerShell process and the burst of Sysmon **8 (CreateRemoteThread)**. Why is "unmanaged PowerShell" invisible to 4104?
4. **Evasion first:** correlate `DE_Powershell_CLM_Disabled_Sysmon_12.evtx` / `de_powershell_execpolicy_changed_sysmon_13.evtx` — if you saw these *before* a 4104 burst on the same host, what story do they tell?

## Answers / what to find
- **4104 (Script Block Logging)** is the headline: it logs **de-obfuscated** script text. The bundled 4104 samples are **Emotet downloader**, **Invoke-CredentialPhisher**, and **MiniDumpWriteDump → LSASS** (`C:\Users\Public\lsass_wer_ps.ps1`, host `MSEDGEWIN10`).
- **4103 (Module Logging)** is the per-command companion; the bundled captures are 4104-centric, so 4103 is taught conceptually — `get-data.sh` points at samples that include it.
- **Sysmon is the backstop:** **10** (PowerShell → LSASS), **8** (CreateRemoteThread injection), **7** (`Automation.dll` in a non-PS process = unmanaged PowerShell), **1** (the command line).
- **Evasion leaves marks:** Sysmon **12/13** for CLM/ExecutionPolicy tampering; WinRM **169** for remote-PowerShell authentication; `wsmprovhost.exe` for the remoting target.

## Pivot
- LSASS access here → **Module 7 (Identity & Credential Theft)** for the logon fallout.
- PowerShell-driven remote tasks / remoting → **Module 8 (Lateral Movement)**.
- The Sysmon IDs that made the backstop work → **Module 10 (Sysmon + WEF)**.

---
*Next: [Module 10 — Sysmon + WEF](../module-10-sysmon-wef).*
