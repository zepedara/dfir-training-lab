# DFIR Training Lab — Evidence of Execution → Intrusion Hunting

A hands-on, **guided lab** that walks every tool from the source decks (*Windows Execution Forensics*, *Intrusion Hunting Playbook*, *Advanced Intrusion Forensic Hunting*) **in teaching order**, with **real training data** to practice on at each step. It runs on the prebuilt **Windows analysis lab VM**, where every tool you need is **installed natively and already on your `PATH`** — no container, no Docker, nothing to install.

> **How to use:** open **Git Bash** on the lab VM, `cd` into a module's `data/` folder, and follow that module's `README` — you call each tool directly by name from inside that folder. The VM is kept **offline** so evidence can never phone home. Each module = **theory (from the deck) → tool → guided exercises → what to find.**

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

> **Part B data:** these modules teach each technique on **representative public attack captures** (EVTX-ATTACK-SAMPLES, hayabusa-sample-evtx) — real attacks, but on assorted hosts, **not** the Case-001 host that Part A follows. They teach the *method*; the **capstone (11)** fuses the method back onto Case-001. Each module's `data/README.md` gives exact provenance.

### Capstone
| # | Module | Focus | Data |
|---|---|---|---|
| 11 | [Capstone investigation](module-11-capstone) | work one full intrusion end-to-end across the Triad + event logs → timeline & findings report | full triage collection |

### Part C — Advanced add-on modules
Deeper, self-contained modules that extend the lab below the artifact layer (raw memory and raw disk) and out to the initial-access front door. Take them after the capstone, in any order.

| # | Module | Tool | Focus | Data |
|---|---|---|---|---|
| 12 | [Memory forensics](module-12-memory-volatility3) | `Volatility 3` (`vol`) | reconstruct processes, injection, network & persistence from a RAM capture | Win7 memory image (`get-data.sh`) |
| 14 | [Malicious documents](module-14-malicious-documents) | `oletools` + Didier Stevens suite | statically dissect a weaponised Office macro doc & PDF; carve the next-stage IOCs | bundled teaching samples |
| 15 | [Filesystem & timelines](module-15-filesystem-timeline) | The Sleuth Kit + `MFTECmd` | partition→file→bytes, recover deleted files, catch timestomping, build the filesystem timeline | synthetic NTFS image |
| 16 | [Registry forensics](module-16-registry-regripper) | RegRipper (`rip`) | persistence, accounts, USB history & program execution recovered from the registry hives | DFIR-Madness Case 001 hives |

> **Why the numbering jumps from 12 to 14:** there is **no Module 13** — the number is intentionally **reserved/held** for a future module and skipped, so the advanced track runs **12 → 14 → 15 → 16**. The gap is deliberate, not a missing file.

---

## Training data (provenance)
- **EVTX-ATTACK-SAMPLES** (sbousseaden) — 278 EVTX of real attack techniques, organized by MITRE ATT&CK → modules 7–10.
- **hayabusa-sample-evtx** (Yamato-Security) — 599 EVTX → module 6.
- **DFIR Madness Case 001** disk image → real Prefetch/ShimCache/Amcache extracted for Part A (a documented intrusion with a known story, so the exercises have *answers*).
- **Advanced-track data** → a published Win7 RAM capture for Module 12 (fetched by `get-data.sh`), purpose-built benign maldoc samples for Module 14, and a synthetic NTFS disk image for Module 15. Each module's `data/README.md` gives exact provenance and licensing.

All data is bundled in each module's `data/` folder (or fetched by a per-module `get-data.sh` on an online host). All analysis runs **offline** on the lab VM.

---

## Suggested path
Work **1 → 11, in order**. Part A teaches you to prove execution on a single host (the real **DFIR-Madness Case-001** host); Part B teaches the intrusion-hunting techniques on **representative public attack captures**; the **capstone (11)** fuses both into one composite case — pinning Case-001's real timestamps and ordering the technique samples into a single kill-chain. Then take the **advanced add-on modules (12, 14, 15, 16)** to go below the artifact layer — raw memory, raw disk — out to the malicious-document front door, and into the registry. By the capstone you can take a triage collection and build a full incident timeline — exactly the decks' goal: *"Master the Triad. Close the Gap."*

*Modules 1–12, 14, 15 and 16 are complete (there is **no Module 13** — see the note above). Each has a full walkthrough from the source decks, real bundled data, guided exercises, and an **answers / what to find** section. Work the core arc **1 → 11**, then the advanced add-ons **12, 14, 15, 16**.*
