# Module 11 (Capstone) — data provenance & licence

## This module ships **no new evidence files** — and that's deliberate

The "Operation Hollow Update" capstone is a **composite teaching scenario**. Rather than duplicate gigabytes of artifacts, it **reuses the real sample data already committed in Modules 1-10**, woven into a single end-to-end intrusion narrative. You work the case by `cd`-ing into the relevant module's `data/` folder and running the container there — exactly as in that module.

This file documents **where every artifact really comes from**, so the case stays honest and reproducible.

## Honesty note (a real DFIR lesson)

The capstone is a *composite*, not a single capture:

- The **patient-zero host** (`DESKTOP-SDN1RPT`) artifacts — Prefetch, ShimCache, Amcache (Modules 1-4) — are a **single, real, documented intrusion** (DFIR Madness Case 001). They share one host and one real clock; their timestamps (e.g. `coreupdater.exe` running **2020-09-19 03:40:49 UTC**) are genuine.
- The **Part B `.evtx`** (Modules 5-10) are **real attack-technique captures from public libraries**, each representing a *technique* an intruder of this kind would use. They originate from **different captures on different hosts** and therefore **do not share a single wall-clock** with each other or with the Case 001 host.

Because of that, the capstone timeline is built as an **attack-phase (kill-chain) narrative** — phases ordered Initial Access → Execution → Credential Access → Lateral Movement → Hands-on-keyboard — pinning **real timestamps only where the host data provides them** and ordering the Part B techniques *logically*, not by a fabricated shared clock. Knowing what your evidence is — and isn't — is itself part of the craft. No timestamps were altered to fake correlation.

## Artifact → module → source map

| Case phase | Data used (folder) | Upstream source | Licence |
|---|---|---|---|
| Execution Triad on patient zero | `../module-01-prefetch-pecmd/data` (197 `.pf`, `pf.csv`) | DFIR Madness Case 001 disk image | Education/defensive use; respect author's terms |
| | `../module-02-shimcache-appcompatcache/data` (`SYSTEM` hive + logs, `shimcache.csv`) | DFIR Madness Case 001 | as above |
| | `../module-03-amcache-amcacheparser/data` (`Amcache.hve` + logs, CSV set) | DFIR Madness Case 001 | as above |
| Fleet stacking | `../module-04-scaling-appcompatprocessor/data` (real `DESKTOP` host + 2 **synthetic** benign peers) | Case 001 host + lab-generated peers | Case 001 terms; peers are lab-generated/freely reusable |
| Initial access / download | `../module-05-evtx-evtxecmd/data` (4 `.evtx`) | EVTX-ATTACK-SAMPLES (@sbousseaden) | **GPLv3** |
| Sigma triage | `../module-06-sigma-chainsaw-hayabusa/data` (23 `.evtx`) | EVTX-ATTACK-SAMPLES + hayabusa-sample-evtx | GPLv3 / public sample set |
| Credential theft | `../module-07-identity-credential-theft/data` (6 `.evtx`) | EVTX-ATTACK-SAMPLES (`Credential Access/`) | **GPLv3** |
| Lateral movement | `../module-08-lateral-movement/data` (26 `.evtx`) | EVTX-ATTACK-SAMPLES (`Lateral Movement`/`Execution`) | **GPL** |
| PowerShell tradecraft | `../module-09-powershell-tradecraft/data` (10 `.evtx`) | EVTX-ATTACK-SAMPLES (`Execution`/`Defense Evasion`) | **GPL** |
| Sensor / centralisation view | `../module-10-sysmon-wef/data` (6 `.evtx`) | EVTX-ATTACK-SAMPLES + hayabusa-sample-evtx | GPL / public sample set |

Each module's own `data/README.md` carries the **per-file** provenance (exact upstream filenames, channels, and verified event-ID counts). Treat those as the authoritative record; this table is the index that ties them into the one capstone case.

## Sources / licences (full)

- **DFIR Madness — "The Stolen Szechuan Sauce" (Case 001):** <https://dfirmadness.com/the-stolen-szechuan-sauce/> — a publicly published, documented Windows intrusion dataset for training. Use for **defensive/training forensics only**; respect the author's terms; don't redistribute for non-educational purposes.
- **EVTX-ATTACK-SAMPLES** by **@sbousseaden:** <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES> — real ATT&CK-technique Windows event logs for detection research. Licence **GPLv3** (see the repo's `LICENSE.GPL`).
- **hayabusa-sample-evtx** by **Yamato Security:** <https://github.com/Yamato-Security/hayabusa-sample-evtx> — public sample-log collection for testing Hayabusa/Sigma.

All bundled `.evtx` are **inert event logs (no executable payloads)** and safe to parse; the case is worked **offline** (`--network none`). The Module-4 peer hosts (`WORKSTATION-07/12`) are **synthetic, malware-free** counting baselines — never treat them as real evidence.

## Reproducing the case without copying files

From the repo root, point the container at whichever phase you're working:
```bash
cd module-01-prefetch-pecmd/data        # (or any module's data/)
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```
The capstone [`README.md`](README.md) Walkthrough (Section 4) lists the exact commands per phase. If you'd rather assemble a single physical `capstone/` evidence folder, copy each module's `data/` contents into subfolders named for the host/phase and keep this provenance file alongside them — but it isn't necessary to work the case.
