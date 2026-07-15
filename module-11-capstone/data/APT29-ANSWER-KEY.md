# Capstone Answer Key — APT29 (MITRE ATT&CK Evals, Day 1)

Grade your kill-chain reconstruction against this. Every row was confirmed present in
`apt29_day1.json` (196,081 events) with `apt29_hunt.py`. The dataset is the OTRF
`detection-hackathon-apt29` recording of the MITRE Engenuity APT29 (Cozy Bear)
evaluation — a reputable, ATT&CK-mapped, inert Windows-telemetry benchmark.

Source of ground truth: MITRE ATT&CK Evals — APT29 (https://attackevals.mitre-engenuity.org/enterprise/apt29)
and the OTRF emulation plan (`emulation-plans/apt29.xlsx`). Techniques below are the
subset **demonstrably observable in the day-1 telemetry** — the point students verify.

| Kill-chain stage | ATT&CK technique | Evidence in the telemetry (`apt29_hunt.py <stage>`) | Expected |
|---|---|---|---|
| Execution (LOLBins) | **T1059.001** PowerShell, **T1059.003** cmd | Sysmon 1: `powershell.exe` / `rundll32.exe` spawned by `cmd.exe`/office | 19 chains |
| Script execution | **T1059.001** | PowerShell **4104** script-block logging | 414 blocks |
| Credential access | **T1003.001** LSASS memory | Sysmon **10** ProcessAccess → `lsass.exe`, grouped by `GrantedAccess` | 1,064 accesses |
| ↳ the actual dump | **T1003.001** | `GrantedAccess=0x1FFFFF` from **PowerShell.exe** (full access = reflective Mimikatz), plus `0x1478`/`0x1400` (write/inject rights) — contrast the benign `0x1000` query-only noise | 3 × 0x1FFFFF, 186 × 0x1478 |
| Domain replication | **T1003.006** DCSync | Security **4662** with replication GUID `1131f6aa-…` from a non-DC account | **exactly 1** |
| Lateral movement | **T1047** WMI, **T1021.003** DCOM | WMI-Activity **5857–5861** (provider/operation events); `WmiPrvSE.exe`-spawned processes | 90 WMI events |
| Persistence | **T1547.001** Run keys, **T1543.003** service | Sysmon **13** Run-key value sets; Security **7045** service installs | 209 Run + 5 svc |

## Grading rubric (self-assess)
1. **Coverage** — did you find all seven stages above? (Each is one `apt29_hunt.py` subcommand.)
2. **Evidence-to-technique traceability** — for each ATT&CK ID, can you cite the *specific* event (EventID + field), not just the technique name? That is the FOR508/DFIR-Report standard.
3. **Signal vs. noise** — did you separate the real LSASS dump (`0x1FFFFF`, `0x1478`) from the ~830 benign `0x1000` query-only accesses? (This is the module-07 GrantedAccess lesson applied at scale.)
4. **The DCSync needle** — one 4662 event in 196,081. Finding it is the capstone's marquee catch.
5. **Detection gaps** — note where a stage is *thin* in the telemetry; the MITRE evals methodology explicitly scores visibility gaps, not just hits.

## Dual framing
- **Cyber Kill Chain** (Lockheed Martin) for the intrusion narrative: delivery → execution → credential access → domain dominance (DCSync) → lateral movement → persistence.
- **ATT&CK** for the granular per-artifact mapping (the table above).

Both are correct lenses; a strong capstone writes the narrative in kill-chain terms and cites ATT&CK IDs per artifact.
