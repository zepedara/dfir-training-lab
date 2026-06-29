# Module 7 — sample data

Six small real `.evtx` samples: five distinct **credential-theft** techniques plus one **benign logon baseline**. All come from the public **EVTX-ATTACK-SAMPLES** library by **@sbousseaden** (**GPLv3**): <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES> (`Credential Access/` folder). Contents are unmodified; some files were renamed for clarity.

| File | Origin (EVTX-ATTACK-SAMPLES name) | Technique | Fingerprint to find |
|---|---|---|---|
| `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | (same) | Invoke-Mimikatz via PowerShell → LSASS | Sysmon 10, `GrantedAccess 0x143a`, source `powershell.exe` |
| `sysmon_10_mimikatz_sekurlsa_logonpasswords.evtx` | (same) | Classic Mimikatz.exe `sekurlsa::logonpasswords` | Sysmon 10, `GrantedAccess 0x1010`, source `mimikatz.exe` |
| `sysmon_10_comsvcs_minidump_lsass.evtx` | `sysmon_10_1_memdump_comsvcs_minidump.evtx` | LOLBAS LSASS dump via `rundll32 comsvcs.dll MiniDump` | Sysmon 1 + 10 |
| `powershell_4104_minidumpwritedump_lsass.evtx` | `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` | PowerShell `MiniDumpWriteDump` API dump | PowerShell 4104 (script block) |
| `security_4662_dcsync.evtx` | `CA_DCSync_4662.evtx` | DCSync — replicate password data from a DC | Security 4662 on a DC, user requesting replication |
| `security_4624_4625_logon_baseline.evtx` | `CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | **Benign** failed-then-successful interactive logon | Security 4624/4625 — fires no detections |

Run `chainsaw hunt /data ...` across the folder (README Step 1) to see each technique named and the baseline stay silent. `get-data.sh` (online host) pulls the full `Credential Access` category for more practice.
