# Module 5 — sample data

Four small real Windows event-log samples, chosen to show **EvtxECmd parsing different channels** and to tell **two halves of one attack**. All four come from the public **EVTX-ATTACK-SAMPLES** library by **@sbousseaden** (<https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>), which is licensed **GPLv3**. They are real attack-technique captures published for training/detection-engineering use.

| File | Origin (EVTX-ATTACK-SAMPLES path) | Channel / Event IDs | Scenario it represents |
|---|---|---|---|
| `sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx` | `Execution/` | Sysmon — 1, 11 | LOLBAS download: `desktopimgdownldr.exe` fetches a `.7z` from `uguu.se` (the Sysmon view). |
| `bits_lolbas_desktopimgdownldr_59_60.evtx` | `Execution/windows_bits_4_59_60_lolbas desktopimgdownldr.evtx` | BITS-Client — 59, 60 | The **same** download, recorded by the BITS service that actually performed it. |
| `security_4624_4625_logon_baseline.evtx` | `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | Security — 4624, 4625 | A normal failed-then-successful interactive logon — the **benign baseline**. |
| `powershell_4104_scriptblock.evtx` | `Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx` | PowerShell Operational — 4104 | A captured PowerShell credential-phishing script (Script Block Logging). |

Files were renamed for clarity; contents are unmodified. To fetch more practice samples on an online host, run `../get-data.sh` (pulls the full EVTX-ATTACK-SAMPLES `Execution` category).
