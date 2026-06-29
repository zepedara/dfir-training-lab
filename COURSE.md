# DFIR Training Lab — Course Guide

> This is the **full course index and study guide**. The repository's [`README.md`](README.md) is the quick-start landing page; this file is the deeper walk-through of *what DFIR is*, *how the ten modules fit together*, and *how to actually run the lab*. New here? Read this top-to-bottom once, then work the modules in order.

---

## 1. What is DFIR, in plain language?

**DFIR** stands for **Digital Forensics and Incident Response**.

- **Digital Forensics** = the careful, evidence-grade study of what happened on a computer, using the traces the system left behind — files, logs, registry keys, memory. The goal is a *defensible answer*: not "I think the attacker ran a program," but "this program ran on this host at this exact time, and here is the artifact that proves it."
- **Incident Response** = what you actually *do* when an organisation is attacked: find the intruder, work out what they touched, scope the damage, and help kick them out.

Put together, DFIR is the craft of **reconstructing an attacker's actions from the footprints they couldn't avoid leaving.** Windows is constantly writing little records of normal activity (so it can start programs faster, so administrators can audit logons, so it can recover from crashes). Attackers use the same Windows, so they leave the same footprints. This course teaches you to read those footprints.

A few ideas you will see over and over:

- **Artifact** — a trace the operating system creates as a side effect of normal work (e.g. a Prefetch file, a registry cache, an event-log record). We did not ask Windows to record it; it just does. That is why it is good evidence.
- **Timeline** — putting events in time order so a story emerges. Most of DFIR is *timelining*.
- **Baseline** — what "normal" looks like on a host, so the abnormal stands out. You will keep a benign baseline next to every attack sample for exactly this reason.
- **Absence isn't innocence** — not finding evidence does not prove nothing happened; an artifact can be disabled, capped, aged out, or wiped. You note the gap and corroborate elsewhere.

> **Sources:** NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response* (<https://csrc.nist.gov/publications/detail/sp/800-86/final>); SANS DFIR, *Windows Forensic Analysis* poster (<https://www.sans.org/posters/windows-forensic-analysis/>).

---

## 2. How this course is built

Every module follows the same shape, taken straight from the source decks (*Windows Execution Forensics*, *Intrusion Hunting Playbook*, *Advanced Intrusion Forensic Hunting*):

**theory (why this artifact exists) → the tool → a guided walkthrough on real data → try-it-yourself exercises → key takeaways → sources.**

You are not reading *about* forensics — at every step you run a real tool against **real artifacts from real attacks** and find the same things an analyst would find on the job. Every command runs **offline**, in the lab VM's Git Bash shell, on data that ships with the repo (or is fetched by a small `get-data.sh` on an online host).

Two big arcs run through the ten modules:

- **Part A (Modules 1-4) — Evidence of Execution.** Prove *what ran* on a single Windows host. This is where you learn **the Triad**.
- **Part B (Modules 5-10) — Intrusion Hunting.** Move from one host's execution evidence to hunting a whole intrusion across the **event logs** — credential theft, lateral movement, PowerShell, and the sensors that record it all.

A new **capstone (Module 11)** then makes you work one full intrusion end-to-end, using everything from Parts A and B.

---

## 3. The Triad (the spine of Part A)

The single most important idea in the first half of the course. Three Windows artifacts each answer a different question about a program, and **each one fills the others' blind spots**:

| Artifact | Question it answers | What it proves | What it does *not* prove |
|---|---|---|---|
| **Prefetch** | *Did it run, when, how often?* | **Execution** — name, run count, last 8 run times, files loaded | nothing about a program that never executed |
| **ShimCache** (AppCompatCache) | *Did the OS ever see this file?* | **Existence/awareness** — the path the OS evaluated (even if never run) | execution (the Win10 "Executed" flag is unreliable) |
| **Amcache** | *What exactly is this file?* | **Identity** — full path, size, and a **SHA1 fingerprint** for attribution | that it ran (an appraiser task populates it) |

> **The drill:** Prefetch says *it ran here at 03:40*. ShimCache says *the OS knew this path existed*. Amcache hands you the *SHA1* so you can confirm known-bad and hunt the same file on every other machine. When one artifact is silent — as ShimCache is for the Case 001 malware `coreupdater.exe` — the gap itself is a clue, and the other two still convict. **"Master the Triad. Close the Gap."**

Module 4 then **scales** the Triad: instead of one host, you stack the same artifact across many hosts and let *rarity* surface the one weird binary. The lesson there is the whole reason the Triad matters at scale: **rarity finds candidates; metadata convicts.**

---

## 4. The learning path — what each module teaches

### Part A — Evidence of Execution (the Triad)

1. **[Module 1 — Prefetch](module-01-prefetch-pecmd)** · tool: `PECmd` / `prefetch`
   *What ran, when, and how often.* You parse 197 real Prefetch files from a compromised desktop, build a mini-timeline, and meet the case malware `COREUPDATER.EXE` — proving it executed at **2020-09-19 03:40:49 UTC**. **You'll learn:** Prefetch fields, the filename-hash → path link, run counts, the 10-second rule, and DLL side-load hunting.

2. **[Module 2 — ShimCache](module-02-shimcache-appcompatcache)** · tool: `AppCompatCacheParser`
   *What the OS saw, even if it never ran.* You parse the `SYSTEM` hive's AppCompatCache. **You'll learn:** that ShimCache means *existence not execution*, why the Win10 "Executed" column is unreliable, why you always collect `SYSTEM.LOG1/.LOG2`, and how to read the first Triad **gap** (the malware is *absent* here).

3. **[Module 3 — Amcache](module-03-amcache-amcacheparser)** · tool: `AmcacheParser`
   *The file's identity and SHA1.* You parse `Amcache.hve` and build an "identity card" for the malware — **SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`, 7,168 bytes, not an OS component**. **You'll learn:** inventory vs execution, why `LinkDate` is fakeable, and how SHA1 becomes the pivot for the fleet-wide hunt.

4. **[Module 4 — Scaling the hunt](module-04-scaling-appcompatprocessor)** · tool: `AppCompatProcessor`
   *Find the one weird binary across many hosts.* You **stack** AppCompat/Amcache data from three hosts and watch the malware fall out as the rare outlier (Count = 1). **You'll learn:** least-frequency-of-occurrence (LFO) stacking, why hashing beats name-matching, and the "benign Count=1 trap."

### Part B — Intrusion Hunting

5. **[Module 5 — Event logs](module-05-evtx-evtxecmd)** · tool: `EvtxECmd`
   *Turn binary `.evtx` into one sortable timeline.* You parse several channels into a merged CSV and follow a LOLBAS download (`desktopimgdownldr.exe` fetching `a.uguu.se/...Bin.7z`) that shows up in **both** Sysmon and BITS logs. **You'll learn:** how `.evtx` works, EZ-Tools Maps, `-d` folder runs, and why corroboration across channels beats a single hit.

6. **[Module 6 — Sigma hunting](module-06-sigma-chainsaw-hayabusa)** · tools: `Chainsaw` + `Hayabusa`
   *Detect attacker behaviour with rules.* You run two Sigma engines across 23 attack samples to triage them in seconds. **You'll learn:** what a detection rule / Sigma / a field mapping is; Hayabusa (ranked timeline) vs Chainsaw (named detections + evidence); and how to triage a whole folder at once.

7. **[Module 7 — Identity & credential theft](module-07-identity-credential-theft)** · event-log analysis
   *The hinge of every intrusion: stealing credentials.* You read five LSASS-theft techniques (Mimikatz, Invoke-Mimikatz, `comsvcs` MiniDump, PowerShell `MiniDumpWriteDump`, DCSync) by their **Sysmon 10 `GrantedAccess`** fingerprints (e.g. `0x1010`, `0x143a`), plus logon analysis (4624 by Logon Type, 4648, 4672). **You'll learn:** to recognise the *technique* regardless of tool, and to chain *dump → abnormal logon*.

8. **[Module 8 — Lateral movement](module-08-lateral-movement)** · event-log analysis
   *How attackers hop host-to-host — and how every method logs itself.* PsExec/services (**7045** + **5145** + Sysmon **17/18**), DCOM, WMI, scheduled tasks (**4698/4702** over `atsvc`), remote registry/shares/startup, RDP (RdpCoreTS **131**), and Pass-the-Hash. **You'll learn:** every delivery leaves a *delivery* event **and** a *carrier logon* (**4624 Type 3 + 4672**), tied together by **LogonId**.

9. **[Module 9 — PowerShell tradecraft](module-09-powershell-tradecraft)** · event-log analysis
   *Reading the attacker's actual script.* **Script Block Logging (4104)** records the fully de-obfuscated script even when the launch command was Base64; Module Logging (4103) is its companion; Sysmon (7/8/10) is the backstop for "unmanaged" in-memory PowerShell. **You'll learn:** to read decoded `ScriptBlockText` for intent, and why evasion (CLM/ExecutionPolicy tampering) is itself a signal.

10. **[Module 10 — Sysmon + WEF](module-10-sysmon-wef)** · concepts + Sysmon EVTX
    *The visibility layer under all of Part B.* The full **Sysmon event-ID map** (1, 3, 7, 8, 10, 11, 12/13, 16, 17/18) and **Windows Event Forwarding (WEF)** for centralising logs at scale. A matched Zerologon pair proves default auditing and Sysmon are complementary. **You'll learn:** exactly what each Sysmon ID means (the IDs Modules 6-9 hunted) and how an enterprise collects logs for fleet-wide hunting.

### Capstone

11. **[Module 11 — Capstone investigation](module-11-capstone)**
    *One intrusion, end-to-end.* You are handed a triage collection and must work a complete case across the Triad, event logs, credential theft, lateral movement, and PowerShell — producing a **timeline + findings report**. Guiding questions first, then a walkthrough, then the full solution. This is where the ten modules become one skill.

---

## 5. How the modules build on each other

```
Part A — prove execution on ONE host
  1 Prefetch ─ "it ran @ 03:40"  ┐
  2 ShimCache ─ "OS saw the path" ├─ THE TRIAD (each fills the others' gaps)
  3 Amcache ─ "SHA1 identity"     ┘
  4 Scaling ─ same SHA1 across MANY hosts → find every infected box
        │
        ▼  pivot: from "what ran" to "what the attacker DID"
Part B — hunt the INTRUSION across the logs
  5 EvtxECmd ─ parse logs → one timeline
  6 Sigma (Chainsaw/Hayabusa) ─ rules that name the bad
  7 Credential theft ─ the hinge (LSASS, DCSync, logons)
  8 Lateral movement ─ host-to-host (delivery event + carrier logon)
  9 PowerShell ─ read the decoded script
  10 Sysmon + WEF ─ the sensor + the collector that made 6-9 possible
        │
        ▼
  11 CAPSTONE ─ do it all on one case, produce a timeline + findings
```

The pivots are deliberate. A suspicious binary in **Module 1** is confirmed in **2/3** and hunted fleet-wide in **4**; its SHA1 and execution time become anchors you carry into **Part B**, where credential theft (**7**) explains *how* the attacker spread (**8**), PowerShell (**9**) shows *what they typed*, and Sysmon/WEF (**10**) is the sensor layer that recorded all of it. The capstone (**11**) closes the loop.

---

## 6. Prerequisites

You do **not** need prior forensics experience — that is the point of the course. You should be comfortable with:

- **A command line.** Every walkthrough is a handful of shell commands, each explained word-by-word the first time it appears.
- **Basic Windows literacy** — what a file path, a registry hive, and a "service" roughly are. The modules define the rest (Prefetch, ShimCache, LSASS, Sysmon, …) as they go; the **[GLOSSARY](GLOSSARY.md)** has plain-language definitions of every term and tool.
- **The lab VM.** All hands-on work runs on the prebuilt Windows analysis VM, where every tool is installed natively and on your `PATH` and you work from a **Git Bash** shell. Nothing else needs installing — see §7, *How to run the lab*.

Helpful but optional: a passing familiarity with [MITRE ATT&CK](https://attack.mitre.org/) (the public catalogue of attacker techniques the samples map to).

---

## 7. How to run the lab

The lab runs on the prebuilt **Windows analysis VM** (the companion **dfir-lab-vm**). Every parser used in the course (`PECmd`/`prefetch`, `AppCompatCacheParser`, `AmcacheParser`, `EvtxECmd`, `Chainsaw`, `Hayabusa`, …) is **installed natively and already on your `PATH`** — nothing to install, no internet needed, no container or Docker.

You drive the tools from a **Git Bash** shell on the VM, so the Unix-style pipelines in the walkthroughs (`grep`, `awk`, `sort`, `head`, `less`, …) work exactly as written.

```bash
# 1. Open Git Bash on the lab VM.

# 2. Go into the module you're working on:
cd module-01-prefetch-pecmd/data

# 3. Run the tools directly by name, from inside that data/ folder, following
#    the module's README. Evidence files are named with simple relative paths
#    (e.g. prefetch/AM_DELTA.EXE-78CA83B0.pf), and reports you write land right
#    beside the evidence in the same folder.
```

- **All tools are on your `PATH`** — call them by name (`PECmd`, `EvtxECmd`, `chainsaw`, `hayabusa`, …); there is no wrapper to type.
- **Run each command from inside the module's `data/` folder**, so inputs and outputs use plain relative paths.
- **The VM is kept offline** (no network). The evidence is inert, but staying offline guarantees nothing can phone home — forensics should be offline by default.
- **Reports persist** — anything a tool writes lands in the module's `data/` folder, so it's there after you're done.

> **The data is the same and the answers are the same** as in any standard EZ Tools / Chainsaw / Hayabusa deployment — the VM just has them all pre-installed so you can start immediately.

### Getting the data

Each module ships its sample data in `data/` (committed to the repo), so you can start immediately. A few modules also include a `get-data.sh` that — **on an online host** — pulls the *full* upstream sample set for extra practice. The core exercises never require it.

---

## 8. Suggested study plan

- **Work 1 → 11, in order.** Part A teaches single-host execution proof; Part B teaches intrusion hunting; the capstone fuses them. The pivots only make sense forward.
- **Do the exercises.** Each module ends with 4-6 *try-it-yourself* questions on the real data. They are where the learning sticks. Worked answers live in **[ANSWER-KEY.md](ANSWER-KEY.md)** (instructor material — try first, then check).
- **Keep the [GLOSSARY](GLOSSARY.md) open** in another tab for any unfamiliar term.
- **Take notes as a timeline.** From Module 1, start a running `YYYY-MM-DD HH:MM:SS UTC | host | what | artifact` log. By the capstone you will be building one for real.

---

## 9. The whole course in one map

| Where you are | Question | Tool(s) | Key artifact / IDs |
|---|---|---|---|
| 1 Prefetch | did it run? | PECmd | `.pf`: run count, last-8 runs, files loaded |
| 2 ShimCache | did the OS see it? | AppCompatCacheParser | `SYSTEM` hive, AppCompatCache |
| 3 Amcache | what is it? | AmcacheParser | `Amcache.hve`, **SHA1** |
| 4 Scaling | which hosts have it? | AppCompatProcessor | stacking / LFO |
| 5 Event logs | what happened, in order? | EvtxECmd | `.evtx` → merged CSV |
| 6 Sigma | what's *bad* in here? | Chainsaw + Hayabusa | Sigma rules, severity |
| 7 Cred theft | who stole creds? | event analysis | Sysmon **10** `GrantedAccess`; **4624/4648/4672**; **4662** DCSync |
| 8 Lateral movement | how did they spread? | event analysis | **7045/5145**, Sysmon **17/18**, **4698/4702**, RdpCoreTS **131**, **4624 Type 3** |
| 9 PowerShell | what did they type? | event analysis | **4104/4103**, Sysmon **7/8/10** |
| 10 Sysmon + WEF | how do we see all this? | concepts | Sysmon ID map; WEF `ForwardedEvents` |
| 11 Capstone | put it all together | all of the above | timeline + findings |

---

*Start with **[Module 1 — Prefetch](module-01-prefetch-pecmd)**. By Module 11 you'll take a triage collection and build a full incident timeline — exactly the decks' goal: **"Master the Triad. Close the Gap."***
