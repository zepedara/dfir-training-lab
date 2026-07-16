# DFIR Training Lab — Evidence of Execution → Intrusion Hunting → Anti-Forensics

A hands-on, **guided lab** that walks every tool from the source decks (*Windows Execution Forensics*, *Intrusion Hunting Playbook*, *Advanced Intrusion Forensic Hunting*) **in teaching order**, with **real training data** to practice on at each step. It runs on the prebuilt **Windows analysis lab VM**, where every tool you need is **installed natively and already on your `PATH`** — no container, no Docker, nothing to install.

> **How to use:** open **Git Bash** on the lab VM, `cd` into a module's `data/` folder, and follow that module's `README` — you call each tool directly by name from inside that folder. The VM is kept **offline** so evidence can never phone home. Each module = **theory (from the deck) → tool → guided exercises → what to find.**

> **No malware — by design.** Every exercise in this lab works on inert forensic **artifacts and detection signatures** — event logs, registry hives, prefetch, `$MFT`/`$LogFile`/`$UsnJrnl` records, extracted tool output, and benign synthetic evidence. No live malware, weaponized documents, or infected images appear anywhere in it. That's a deliberate design choice, so the lab is safe to run on any machine.

---

## Curriculum

The lab runs in five arcs. **Work Part A → the Capstone (Modules 1–11) in order** — the pivots only make sense forward. The advanced tracks (**Parts C–E**) are self-contained; take them after the capstone in any order.

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
| 11 | [Capstone investigation](module-11-capstone) | work one full intrusion end-to-end across the Triad + event logs → timeline & findings report | APT29 triage collection |

### Part C — Host Forensics Deep-Dive
*Go below the OS-artifact layer — raw memory, raw disk, the registry — and out to the initial-access front door. Single-host, evidence-grade.*

| # | Module | Tool | Focus | Data |
|---|---|---|---|---|
| 12 | [Memory forensics](module-12-memory-volatility3) | `Volatility 3` (`vol`) | reconstruct processes, injection, network & persistence from a RAM capture | Win7 memory image (`get-data.sh`) |
| 14 | [Malicious documents](module-14-malicious-documents) | `oletools` + Didier Stevens suite | statically dissect a weaponised Office macro doc & PDF; carve next-stage IOCs | bundled teaching samples |
| 15 | [Filesystem & NTFS timelines](module-15-filesystem-timeline) | The Sleuth Kit + `MFTECmd` | partition→file→bytes, recover deleted files, catch timestomping, build the filesystem timeline | synthetic NTFS image |
| 16 | [Registry forensics](module-16-registry-regripper) | RegRipper (`rip`) | persistence, accounts, USB history & program execution from the registry hives | DFIR-Madness Case 001 hives |
| 17 | [User activity](module-17-user-activity) | `JLECmd`/`LECmd`/`SBECmd`/`RBCmd` | jump lists, LNK, ShellBags, Recycle Bin — what the user opened, ran & deleted | user-artifact set |
| 19 | [Browser forensics](module-19-browser-forensics) | `Hindsight` | history, downloads, sessions & the packed `transition` type from Chromium profiles | Chromium profile |

### Part D — Timeline, Triage & Detection at Scale
*Fuse everything into one timeline, collect at fleet scale, and cross the wire — then turn findings into repeatable detections.*

| # | Module | Tool | Focus | Data |
|---|---|---|---|---|
| 18 | [Super timeline](module-18-super-timeline) | `MFTECmd` + `mactime` | merge `$MFT` + event logs into one super-timeline; clock skew & MACB traps | Case-001 + host evtx |
| 20 | [Triage at scale](module-20-triage-velociraptor) | `Velociraptor` (VQL) | live/offline triage collection & hunting across a fleet with VQL + notebooks | KAPE-style triage |
| 21 | [Network forensics](module-21-network-forensics) | `tshark` / `Zeek` | carve HTTP/DNS/TLS, measure beaconing, spot port≠protocol on a PCAP | teaching PCAP |
| 22 | [Detection engineering](module-22-detection-engineering) | `Sigma` / `Chainsaw` / `Zircolite` | write, test & tune Sigma rules; correlation rules; hunt-query vs alert-rule | rules + EVTX |

### Part E — Anti-Forensics *(FOR508.5)*
*How attackers try to erase their tracks — and why NTFS remembers anyway. Builds on the NTFS internals of Modules 15 & 18.*

| # | Module | Tool | Focus | Data |
|---|---|---|---|---|
| 23 | [Wiping tool-marks](module-23-anti-forensics-wiping) | `MFTECmd` (`$J`/`$MFT`) | detect SDelete / cipher / Eraser / BCWipe by their marks; recover a wiped file's **name** | inert scratch-VHD `$J` + `$MFT` |
| 24 | [VSS destruction & recovery](module-24-anti-forensics-vss) | `EvtxECmd` (+ libvshadow) | detect shadow-copy destruction (T1490); recover from surviving shadows | inert T1490 `4688` evtx |
| 25 | [`$LogFile` transaction analysis](module-25-anti-forensics-logfile) | LogFileParser (pre-parsed) | read redo/undo opcodes to reconstruct create / rename / ADS / delete | inert scratch-VHD `$LogFile` |
| 26 | [Carving unallocated space](module-26-anti-forensics-carving) | The Sleuth Kit + `grep` | metadata-recovery vs carving; recover a deleted BitLocker key | inert scratch NTFS image |

> **Reserved module number.** There is **no Module 13** — the number is held for a future core module and skipped on purpose. The gap is deliberate, not a missing file.

---

## Training data (provenance)
- **EVTX-ATTACK-SAMPLES** (sbousseaden) — EVTX of real attack techniques, organized by MITRE ATT&CK → modules 7–10.
- **hayabusa-sample-evtx** (Yamato-Security) — sample EVTX → module 6.
- **DFIR Madness Case 001** disk image → real Prefetch/ShimCache/Amcache/registry extracted for Parts A & C (a documented intrusion with a known story, so exercises have *answers*).
- **Advanced-track data** → a published Win7 RAM capture (Module 12, `get-data.sh`), purpose-built maldoc samples (14), synthetic NTFS images (15), a Chromium profile (19), a teaching PCAP (21), and **inert artifacts generated for the Anti-Forensics track (23–26)** — scratch-VHD `$MFT`/`$LogFile`/`$UsnJrnl` records, a T1490 process-creation event log, and an NTFS carving image; marker strings only, no code. Each module's `data/README.md` gives exact provenance and licensing.

All data is bundled in each module's `data/` folder (or fetched by a per-module `get-data.sh` on an online host). All analysis runs **offline** on the lab VM.

---

## Suggested path
Work **1 → 11, in order.** Part A proves execution on a single host (the real **DFIR-Madness Case-001** host); Part B teaches intrusion-hunting techniques on **representative public captures**; the **capstone (11)** fuses both into one composite kill-chain. Then take the advanced tracks in any order: **Part C** (host deep-dive: memory, disk, registry, user activity, browser), **Part D** (super-timeline, fleet triage, network, detection engineering), and **Part E** (anti-forensics — how wiping and timestomping betray themselves in NTFS). By the capstone you can take a triage collection and build a full incident timeline — exactly the decks' goal: *"Master the Triad. Close the Gap."*

*All modules **1–12, 14–26** are complete (there is **no Module 13** — see the reserved-number note above). Each has a full walkthrough, real bundled data, guided exercises, and an **answers / what to find** section.*
