# Module 9 data — provenance & license

All `.evtx` in this folder are from **EVTX-ATTACK-SAMPLES** by @sbousseaden
(https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), Execution / Defense-Evasion categories,
published for detection research and education. Upstream license: **GPL** (`LICENSE.GPL`).
Files are unmodified; use `../get-data.sh` to pull the full upstream *Execution* category for more.

Real contents (verified by parsing the files):

| File | Technique | Key event IDs (counts) |
|---|---|---|
| `exec_emotet_ps_4104.evtx` | obfuscated Emotet downloader (decoded by 4104) | 4104 ×1 |
| `phish_windows_credentials_powershell_scriptblockLog_4104.evtx` | Invoke-CredentialPhisher (fake auth prompt) | 4104 ×2 |
| `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` | MiniDumpWriteDump vs `Get-Process lsass` in pure PS | 4104 ×1, 40961/40962/53504 |
| `babyshark_mimikatz_powershell.evtx` | PowerShell credential dump (Sysmon view) | Sysmon 1 ×7,3,4,5 ×2,7 ×11,10 ×2,11 ×3,12 ×4,16 ×2 |
| `de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx` | unmanaged/in-memory PowerShell injection | Sysmon 7,8 ×82,10 |
| `DE_Powershell_CLM_Disabled_Sysmon_12.evtx` | Constrained Language Mode disable attempt | Sysmon 12 |
| `de_powershell_execpolicy_changed_sysmon_13.evtx` | ExecutionPolicy flipped via registry | Sysmon 13 ×5 |
| `RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx` | WinRM authentication (PS Remoting) | WinRM 169 ×3, 193 ×3 |
| `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | PS-Remoting target process | Sysmon 1 (wsmprovhost.exe) |
| `LM_sysmon_remote_task_src_powershell.evtx` | PowerShell as source of remote task | Sysmon 3 ×2,7 |

> Inert event logs (no live payloads); safe to parse. All analysis runs offline in the lab VM (tools on your `PATH`, no network needed).
