# Module 6 — sample data

23 curated attack-technique `.evtx` files for practicing Sigma hunting with Chainsaw and Hayabusa. They are drawn from two public, education-oriented sample sets:

- **hayabusa-sample-evtx** — Yamato Security: <https://github.com/Yamato-Security/hayabusa-sample-evtx>
- **EVTX-ATTACK-SAMPLES** — @sbousseaden (**GPLv3**): <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>

Contents are unmodified; some filenames were kept as-published so they map back to their source.

| File(s) | Technique it represents |
|---|---|
| `sysmon_privesc_psexec_dwell.evtx` | **Guided sample** — PsExec lateral movement to SYSTEM (`\PSEXESVC` pipe). |
| `metasploit-psexec-*` (5 files, security/system) | Metasploit PsExec variants (native + PowerShell payload). |
| `mimikatz-privesc-hashdump.evtx`, `mimikatz-privilegedebug-tokenelevate-hashdump.evtx` | Mimikatz credential/hash dumping. |
| `Powershell-Invoke-Obfuscation-*` (3 files) | Obfuscated/encoded PowerShell (Invoke-Obfuscation). |
| `powersploit-security.evtx`, `powersploit-system.evtx`, `psattack-security.evtx` | PowerSploit / PS-Attack offensive PowerShell frameworks. |
| `password-spray.evtx`, `smb-password-guessing-security.evtx` | Brute-force / password-spray logon attacks. |
| `new-user-security.evtx` | Account creation (persistence). |
| `disablestop-eventlog.evtx`, `eventlog-dac.evtx` | Event-log tampering / disabling (defense evasion). |
| `UACME_59_Sysmon.evtx` | UAC bypass (UACME technique 59). |
| `many-events-application.evtx`, `many-events-security.evtx`, `many-events-system.evtx` | Large mixed logs — good for `-d` folder runs and `hayabusa logon-summary`. |

Run `chainsaw hunt /data ...` and `hayabusa csv-timeline -d /data ...` across the whole folder to triage all 23 at once (Step 4 in the README).
