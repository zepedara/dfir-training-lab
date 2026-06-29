# Module 10 data — provenance & license

This folder mixes samples from two public, education-oriented repositories so you can practice the
Sysmon event-ID map across several techniques and compare **default Windows auditing vs Sysmon**.

- **EVTX-ATTACK-SAMPLES** by @sbousseaden — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
  (license: **GPL**, `LICENSE.GPL`).
- **hayabusa-sample-evtx** by Yamato-Security — https://github.com/Yamato-Security/hayabusa-sample-evtx
  (public sample-log collection curated for testing Hayabusa/Sigma detection rules).

Files are unmodified copies (the two Zerologon files were renamed for clarity only).
Real contents (verified by parsing in the `dfir-aio:v2` container):

| File | Source | Technique | Real event IDs (counts) |
|---|---|---|---|
| `Sysmon_UACME_45.evtx` | EVTX-ATTACK-SAMPLES | UAC bypass via auto-elevation registry value | Sysmon 1 ×5, 12 ×1, 13 ×1, 5 ×1 |
| `Sysmon_UACME_63.evtx` | EVTX-ATTACK-SAMPLES | a different UAC bypass (image load + LSASS) | Sysmon 1, 7, 10 |
| `sysmon_10_11_lsass_memdump.evtx` | EVTX-ATTACK-SAMPLES | credential dumping (LSASS handle + .dmp write) | Sysmon 10 ×2, 11 ×2 |
| `meterpreter_migrate_to_explorer_sysmon_8.evtx` | EVTX-ATTACK-SAMPLES | Meterpreter process injection into explorer.exe | Sysmon 8 ×1 |
| `Zerologon_Sysmon.evtx` | hayabusa-sample-evtx | Sysmon view of a Zerologon attack | Sysmon 1 ×10, 5 ×10, 16 |
| `Zerologon_DefaultLogging_Security.evtx` | hayabusa-sample-evtx | default Security-log view of the same attack | 4624 ×10, 4672 ×10, 4742, 4769 ×4, 4634 ×9, 1102 |

The last two are a matched pair (same attack, two sensors) used in Step 6 to show what Sysmon adds
over default auditing. There is no separate "benign baseline" file: these captures come from real,
busy hosts, so the ordinary Windows activity *within each file* is the benign background you learn
to distinguish the anomaly from.

> Inert event logs (no live payloads); safe to parse. Analysis runs offline (`--network none`).
> Pull more Sysmon samples with `../get-data.sh`.
