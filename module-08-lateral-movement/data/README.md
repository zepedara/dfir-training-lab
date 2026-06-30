# Module 8 data — provenance & license

All `.evtx` in this folder are a curated slice of **EVTX-ATTACK-SAMPLES** by @sbousseaden
(https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), a public library of real ATT&CK-technique
Windows event logs published for detection research and education. Upstream license: **GPL**
(see the repository's `LICENSE.GPL`). Files are unmodified copies; each is named for the event
IDs it contains. Use `../get-data.sh` to pull the full upstream *Lateral Movement* / *Execution*
categories for extra practice.

Real contents (verified by parsing the files):

| File | Technique | Key event IDs (counts) |
|---|---|---|
| `LM_Remote_Service02_7045.evtx` | service install (svc names: spoolfool/spoolsv/remotesvc → cmd/calc) | 7045 ×3 |
| `LM_Remote_Service01_5145_svcctl.evtx` | remote SCM over `svcctl` pipe | 5145 ×1 |
| `LM_renamed_psexecsvc_5145.evtx` | renamed PsExec service pipe | 5145 ×22 |
| `LM_REMCOM_5145_TargetHost.evtx` | RemCom (PsExec clone) | 5145 ×30 |
| `LM_5145_Remote_FileCopy.evtx` | tool staging over admin share | 5145 ×869 |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | Meterpreter PsExec → encoded PS | Sysmon 1/3/10/13/18 |
| `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx` | DCOM → mshta (LethalHTA) | Sysmon 1,3 |
| `LM_impacket_docmexec_mmc_sysmon_01.evtx` | Impacket dcomexec → MMC20 | Sysmon 1 ×5, 3 ×4 |
| `LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx` | ShellWindows/ShellBrowserWindow DCOM | Sysmon 3 ×3 |
| `LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx` | failed DCOM activations | System 10016 ×4 |
| `lm_sysmon_18_remshell_over_namedpipe.evtx` | PowerShell shell over named pipe | Sysmon 1 ×3,3,10 ×2,18 |
| `LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx` | NullSessionPipes registry add | Sysmon 13 |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | remote schtasks over `atsvc` | 4698,4699,4624 ×6,4672 ×5,4776 ×4,5140/5145,4661/4688 |
| `remote task update 4624 4702 same logonid.evtx` | task update tied to logon by LogonId | 4702,4624 ×6,1102 |
| `lm_remote_registry_sysmon_1_13_3.evtx` | remote registry edits | Sysmon 1/3/12/13 |
| `LM_NewShare_Added_Sysmon_12_13.evtx` | new SMB share created | Sysmon 12 ×1,13 ×2 |
| `lateral_movement_startup_3_11.evtx` | Startup-folder drop over admin share | Sysmon 3,11 |
| `dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx` | target-side RDP connection accepts | RdpCoreTS 131 ×22,68 ×9,168 ×9 |
| `DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx` | client-side RDP artefacts | RdpCoreTS 104 ×21 |
| `LM_sysmon_3_12_13_1_SharpRDP.evtx` | SharpRDP (non-interactive RDP exec) | Sysmon 1 ×8,3 ×4,12 ×17,13 ×9 |
| `LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx` | SharpRDP with `\tsclient\` redirect | Sysmon 1 ×2,3,12 ×4,13 ×2 |
| `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx` | source box launching Pass-the-Hash | 4624,4672,4688 ×3,1102 |
| `ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx` | local PtH → pipe/share hop | Sysmon 1 ×4,3 ×7,18 + 4624,5145 |
| `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | WinRM/PS-Remoting target process | Sysmon 1 (wsmprovhost.exe) |
| `LM_ImageLoad_NFSH_Sysmon_7.evtx` | image-load trace | Sysmon 7 ×2 |
| `LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx` | regsvc / directory-service abuse | Sysmon 3 ×3,12,13,18 |

> These are real attacker techniques captured for defensive training. They are inert event logs
> (no executable payloads) and safe to parse; all analysis runs offline in the lab VM (the tools are already on your `PATH` — no network needed).
