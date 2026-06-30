# Module 4 — data provenance (`data/fleet/`)

This module's data is an **eight-host synthetic fleet** of Application-Compatibility (ShimCache) collections, one CSV per host, used to demonstrate **stacking / least-frequency-of-occurrence (LFO)** — the technique only works with many hosts to count against. There is no clean, license-clear public multi-host AppCompat set, so the fleet is **generated, not downloaded**, and is clearly labelled synthetic. It is **not** real case evidence; it is a teaching construct (the same Middle-earth theme as the rest of the lab — see [`../../THEME-MIDDLE-EARTH.md`](../../THEME-MIDDLE-EARTH.md)).

> See the **[module README](../README.md)** for the full walkthrough (it explains every ACP command run against this folder), and **[`../tools/build_fleet_csvs.py`](../tools/build_fleet_csvs.py)** for the generator — the script is documented and is itself part of the lesson (it shows exactly what "normal vs intrusion" looks like in this artifact).

## File format — `appcompat_csv`
`data/fleet/` holds **one CSV per host**, and **the filename *is* the hostname** (e.g. `MINAS-TIRITH-DC01.csv`). Each file is a ShimCacheParser-style table that ACP's **`appcompat_csv`** ingest plugin reads, with the header:

```
Last Modified,Last Update,Path,File Size,Exec Flag
```

Load the whole folder at once with `acp <db> load data/fleet`; ACP keys hosts off the filenames, so the stack counts "how many hosts each program appears on."

## The fleet (8 hosts)
| Host (CSV) | Role | State |
|---|---|---|
| `RIVENDELL-WS01.csv`, `GONDOR-WS02.csv`, `ROHAN-WS03.csv` | Workstations | clean baseline |
| `LOTHLORIEN-FS01.csv` | File server | clean baseline |
| `EREBOR-SQL01.csv` | SQL server | clean baseline (carries legitimate-rare SQL tooling) |
| `ISENGARD-WS04.csv` | Workstation | **compromised** — the insider `saruman.white`; lateral-movement launch point |
| `BAG-END-LT01.csv` | Laptop | **compromised** — patient zero (`frodo.baggins`, phished) |
| `MINAS-TIRITH-DC01.csv` | Domain controller | **compromised** — the crown jewel (also carries legitimate-rare DC tooling) |

The clean hosts share a realistic common-software baseline (System32 OS binaries, `explorer.exe`, `Teams.exe`, `Acrobat.exe`, …) so ubiquitous software **stacks high** while the intruder's tooling **stacks low** — the whole point of LFO.

## The planted SAURON toolkit (synthetic)
The three compromised hosts carry a planted toolkit with a clear **2024-09-13 / 2024-09-14** incident-window timestamp, dropped in classic staging paths so the path itself tells the story:

| File | Lands on | Path (in the CSV) |
|---|---|---|
| `theonering.exe` (dropper) | `BAG-END-LT01` | `C:\Users\frodo.baggins\Downloads\theonering.exe` |
| `gollum.exe` (%TEMP% stager) | `BAG-END-LT01` | `C:\Users\frodo.baggins\AppData\Local\Temp\gollum.exe` |
| `palantir.exe` (recon/C2 beacon) | `ISENGARD-WS04` → `MINAS-TIRITH-DC01` | `C:\ProgramData\palantir.exe`; `C:\Windows\Temp\palantir.exe` |
| `nazgul.exe` (lateral movement) | `ISENGARD-WS04`, `MINAS-TIRITH-DC01` | `C:\Windows\Temp\nazgul.exe` |
| `mordor-update.exe` (fake updater persistence) | `ISENGARD-WS04` | `C:\Users\saruman.white\AppData\Roaming\mordor-update.exe` |
| `morgul.dll` (NTDS / DCSync) | `MINAS-TIRITH-DC01` | `C:\Windows\NTDS\morgul.dll` |
| `balrog.exe` (end-objective payload) | `MINAS-TIRITH-DC01` | `C:\PerfLogs\balrog.exe` |

`palantir.exe` and `nazgul.exe` land on **two** hosts each (Count = 2) — the classic lateral-movement signature ACP surfaces in the stack — while the single-host implants and the legitimate-rare role tools (DC `repadmin`/`netdom`/`ntdsutil`, SQL `sqlservr`/`Ssms`) share the Count = 1 tail you must triage. The full mapping of each file to what it actually does is in the [module README, §5](../README.md) and the canonical [`../../THEME-MIDDLE-EARTH.md`](../../THEME-MIDDLE-EARTH.md).

## License
Generated for this lab; freely reusable. No third-party data. Re-generate or extend the fleet (add hosts, plant your own tool) by editing and re-running [`../tools/build_fleet_csvs.py`](../tools/build_fleet_csvs.py).
