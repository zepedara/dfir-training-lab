# DFIR Training Lab — Evidence of Execution → Intrusion Hunting

A hands-on, **guided lab** that walks every tool from the source decks (*Windows Execution Forensics*, *Intrusion Hunting Playbook*, *Advanced Intrusion Forensic Hunting*) **in teaching order**, with **real training data** to practice on at each step. Pairs with the offline **[dfir-aio container](https://github.com/zepedara/dfir-drop)** — every tool you need is already in it.

> **How to use:** load the `dfir-aio` container, `cd` into a module's `data/` folder, run `docker run -it --rm -v "$PWD":/data dfir-aio:v2`, and follow that module's `README`. Each module = **theory (from the deck) → tool → guided exercises → what to find.**

---

## Curriculum (in order)

### Part A — Evidence of Execution *(the Triad)*
| # | Module | Tool | Question it answers | Data |
|---|---|---|---|---|
| 1 | [Prefetch](module-01-prefetch-pecmd) | `PECmd` | *What ran, when, how often?* | real `.pf` (extracted from Case 001) |
| 2 | [ShimCache](module-02-shimcache-appcompatcache) | `AppCompatCacheParser` | *What did the OS see (even if never run)?* | `SYSTEM` hive |
| 3 | [Amcache](module-03-amcache-amcacheparser) | `AmcacheParser` | *Full inventory + SHA1 attribution* | `Amcache.hve` |
| 4 | [Scaling the hunt](module-04-scaling-appcompatprocessor) | `AppCompatProcessor` | *Find the one weird binary across many hosts* | multi-host artifacts |

> **The Triad idea (from the decks):** Prefetch = *execution proof* (timeline), ShimCache = *existence* (the OS saw it), Amcache = *identity* (SHA1 fingerprint). Each fills the others' gaps.

### Part B — Intrusion Hunting
| # | Module | Tool | Focus | Data |
|---|---|---|---|---|
| 5 | [Event logs](module-05-evtx-evtxecmd) | `EvtxECmd` | parse `.evtx` → CSV | sample EVTX |
| 6 | [Sigma hunting](module-06-sigma-chainsaw-hayabusa) | `Chainsaw` + `Hayabusa` | detect attacker behavior | hayabusa-sample-evtx (599) |
| 7 | [Identity & credential theft](module-07-identity-credential-theft) | event-log analysis | logons 4624/4648/4672, Type 9/11 | EVTX-ATTACK-SAMPLES › Credential Access |
| 8 | [Lateral movement](module-08-lateral-movement) | event-log analysis | PsExec 7045, DCOM, WMI, named pipes (Sysmon 17/18) | EVTX-ATTACK-SAMPLES › Lateral Movement |
| 9 | [PowerShell tradecraft](module-09-powershell-tradecraft) | event-log analysis | Script Block Logging 4104, module 4103 | EVTX-ATTACK-SAMPLES › Execution |
| 10 | [Sysmon + WEF](module-10-sysmon-wef) | concepts + Sysmon EVTX | the visibility layer | Sysmon sample EVTX |

---

## Training data (provenance)
- **EVTX-ATTACK-SAMPLES** (sbousseaden) — 278 EVTX of real attack techniques, organized by MITRE ATT&CK → modules 7–10.
- **hayabusa-sample-evtx** (Yamato-Security) — 599 EVTX → module 6.
- **DFIR Madness Case 001** disk image → real Prefetch/ShimCache/Amcache extracted for Part A (a documented intrusion with a known story, so the exercises have *answers*).

All data is bundled in each module's `data/` folder (or fetched by a per-module `get-data.sh`). All analysis runs **offline** in the container.

---

## Suggested path
Work **1 → 10**. Part A teaches you to prove execution on a single host; Part B teaches you to hunt an intrusion across the logs. By module 10 you can take a triage collection and build a full incident timeline — exactly the decks' goal: *"Master the Triad. Close the Gap."*

*(Modules are being filled in with full walkthroughs + exercises — check back as they land.)*
