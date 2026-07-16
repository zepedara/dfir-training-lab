# Module 11 — Capstone: APT29 (Cozy Bear) — MITRE ATT&CK Evals

> **The final exam — on a real benchmark.** You've spent Modules 1-10 learning the craft on Case-001. Now you prove it against a fresh, reputable, objectively-gradable dataset: the **MITRE ATT&CK Evaluation of APT29 (Cozy Bear)**. You're handed 196,081 pre-recorded Windows events from a full simulated intrusion, and you reconstruct the kill chain — stage by stage, artifact by artifact — then **grade yourself against a published answer key**. Work each stage before you read its interpretation.

> **Why this benchmark.** Case-001 (Modules 1-10) taught you the techniques on a single, story-driven intrusion. This capstone is different **on purpose**: it is a **standalone benchmark case** built on data the whole industry knows and trusts.
> - **Reputable.** The MITRE ATT&CK Evaluations run real red-team emulations of named adversaries against instrumented environments. APT29 is one of their canonical rounds. A large cohort of endpoint-security vendors (roughly two dozen in the APT29 round) has been evaluated against it.
> - **ATT&CK-mapped.** Every action the emulation performs is tagged to a specific ATT&CK technique ID, so "did I find it?" has an unambiguous answer.
> - **Gradable.** Because the emulation plan and technique mapping are published, we ship an **answer key** ([`data/APT29-ANSWER-KEY.md`](data/APT29-ANSWER-KEY.md)). You can score your own reconstruction — coverage, evidence traceability, signal-vs-noise, detection gaps — the way the evals themselves score a product.
>
> Treat this as a clean-room test of everything you've learned, on data you did not narrate into existence.

---

## 1. The evidence

The dataset is **`apt29_day1.json`** — the OTRF [`detection-hackathon-apt29`](https://github.com/OTRF/detection-hackathon-apt29) recording of **day 1** of the MITRE ATT&CK APT29 evaluation, in **Mordor format**: one Windows event per line as JSON, drawn from four channels:

| Channel | What it carries here |
|---|---|
| **Sysmon** (dominant) | Process creation (EID 1), LSASS access (EID 10), registry (EID 13), file writes (EID 11) |
| **Security** | DCSync directory replication (EID 4662), service installs (EID 7045), logons (EID 4624) |
| **PowerShell** | Script-block logging (EID 4104) |
| **WMI-Activity** | Provider/operation events (EID 5857-5861) for remote WMI |

**196,081 events.** It is **inert, pre-recorded telemetry** — a log of what the red team did on an instrumented host. There is nothing to detonate and nothing to run; you are reading forensic records, exactly as you would on a real triage collection.

---

## 2. Setup

The telemetry is ~120 MB compressed (~368 MB expanded), so it is **not** committed to the repo. Fetch it once, on an online host, before you start:

```
# one-time, online host only — downloads + unzips apt29_day1.json into this folder:
sh get-data.sh
```

Everything after that is offline. All of it runs natively in **Git Bash** — `python3` and `grep` are already on your `PATH`; no container, no Docker. The rest of this walkthrough assumes `apt29_day1.json` is present in `module-11-capstone/data/`.

Start every command from the data folder:

```bash
cd module-11-capstone/data
```

Sanity-check the evidence is all there:

```bash
wc -l apt29_day1.json
```

You should see **196081** — one line per event. Get your bearings on the channel mix:

```bash
python3 apt29_hunt.py summary apt29_day1.json
```

Sysmon dominates (it's the richest sensor), followed by Security, PowerShell, and WMI-Activity. That distribution *is* the story: most of your leads will come from Sysmon, but the single most damaging event of the whole intrusion lives in the Security channel (you'll find it in the DCSync stage).

> **The helper.** [`apt29_hunt.py`](apt29_hunt.py) is a triage tool, not a magic answer machine. Each subcommand isolates one ATT&CK stage and counts what it finds, so you can map **evidence → technique** yourself. Subcommands: `summary execution powershell lsass dcsync wmi persistence all`. Usage is always `python3 apt29_hunt.py <stage> apt29_day1.json`.

---

## 3. The kill-chain walkthrough

Work it in intrusion order. Each stage runs one subcommand, interprets the output, and names the ATT&CK technique plus the exact EventID/field that proves it.

### Stage 1 — Execution (LOLBins)
```bash
python3 apt29_hunt.py execution apt29_day1.json
```
**~19 LOLBIN chains.** These are **Sysmon Event 1** (process creation) where a living-off-the-land binary is spawned by an interactive parent — the signature shape is `powershell.exe  <-  cmd.exe` (PowerShell launched from a command shell), with `rundll32.exe`, `regsvr32.exe`, `wscript.exe`, and `mshta.exe` in the mix too. This is the attacker getting first code execution using tools already on the box.
- **ATT&CK:** **T1059.001** (PowerShell) and **T1059.003** (Windows Command Shell).
- **Evidence:** Sysmon EID 1, `Image` / `ParentImage` fields.

### Stage 2 — PowerShell script execution
```bash
python3 apt29_hunt.py powershell apt29_day1.json
```
**~414 script-block records.** These are **PowerShell Event 4104** (script-block logging), which captures the *compiled* script text even when the launch was Base64-encoded. Volume this high means PowerShell was the primary hands-on-keyboard tool — the attacker's staging, discovery, and dumping all flow through it.
- **ATT&CK:** **T1059.001** (PowerShell).
- **Evidence:** PowerShell EID 4104, `ScriptBlockText`.
- **Blind-spot note:** 4104 sees *managed* PowerShell. **Unmanaged / in-memory** PowerShell (the engine hosted inside another process) is invisible here — you catch that with Sysmon 7 (`System.Management.Automation.dll` loaded into a non-PS process), 8 (CreateRemoteThread), and 10 (LSASS access). Keep that gap in mind for your detection-gap score.

### Stage 3 — Credential access: LSASS  ★ signal vs. noise
```bash
python3 apt29_hunt.py lsass apt29_day1.json
```
This is the marquee lesson of the whole capstone. You get **1,064 Sysmon Event 10 (ProcessAccess) events targeting `lsass.exe`**, grouped by the **`GrantedAccess`** mask — the exact bitmask teaching from **Module 07**, now applied at scale. Reading the masks:

| `GrantedAccess` | Count | What it means |
|---|---|---|
| **`0x1000`** | **830** | `PROCESS_QUERY_LIMITED_INFORMATION` — query-only. **Benign noise.** AV, EDR, and Windows itself poke LSASS constantly. |
| **`0x1478`** | **186** | Includes write/inject rights (`VM_WRITE` / `VM_OPERATION`) — read/write into LSASS memory. **Suspicious.** |
| **`0x1400`** | **31** | `VM_READ` + query — reading LSASS memory. **Suspicious.** |
| **`0x40`** | **14** | `DUP_HANDLE` — handle duplication, a known dump primitive. |
| **`0x1FFFFF`** | **3** | `PROCESS_ALL_ACCESS` — **full access, from `PowerShell.exe`. This is the reflective-Mimikatz dump.** |

The point: **830 of 1,064 accesses are innocent.** If you alert on "anything touches LSASS," you drown. The real credential theft is the **3 × `0x1FFFFF` from PowerShell** (nothing legitimate opens LSASS with full access from a script host) plus the write-capable `0x1478`/`0x1400` masks. **Rarity + the right mask + the wrong source image = conviction.** Separating those 3 events from the 830 is the skill Module 07 built.
- **ATT&CK:** **T1003.001** (OS Credential Dumping: LSASS Memory).
- **Evidence:** Sysmon EID 10, `GrantedAccess` + `SourceImage`.

### Stage 4 — Credential access: DCSync  ★ the one-in-196,081 needle
```bash
python3 apt29_hunt.py dcsync apt29_day1.json
```
**Exactly one event.** A single **Security Event 4662** in which a **non-DC account** requests directory-replication access — identified by the replication control-access-right GUID `1131f6aa-…` (`DS-Replication-Get-Changes`). This is **DCSync**: the attacker impersonates a domain controller and asks a real DC to hand over password hashes over the wire. No LSASS touched, no malware dropped — just a legitimate protocol abused.

This is the single most consequential event in the entire dataset, and there is **exactly one of it among 196,081**. Only a domain controller's computer account should ever replicate; a *user* account requesting it is DCSync, full stop. Find this needle and you've found domain compromise — treat every credential in the domain (including `krbtgt`) as burned.
- **ATT&CK:** **T1003.006** (OS Credential Dumping: DCSync).
- **Evidence:** Security EID 4662, `Properties` GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, non-DC `SubjectUserName`.

### Stage 5 — Lateral movement: WMI
```bash
python3 apt29_hunt.py wmi apt29_day1.json
```
**~90 WMI-Activity events** (EIDs **5857-5861** on the `Microsoft-Windows-WMI-Activity/Operational` channel), plus any process spawned by `WmiPrvSE.exe`. WMI is a remote-execution and lateral-movement channel: the attacker drives commands on other hosts through the WMI provider service rather than dropping a binary. The 5857-5861 events record provider loads and operation execution — the fingerprints of remote WMI use.
- **ATT&CK:** **T1047** (Windows Management Instrumentation) and **T1021.003** (Remote Services: DCOM).
- **Evidence:** WMI-Activity EIDs 5857-5861; Sysmon EID 1 with `ParentImage = WmiPrvSE.exe`.

### Stage 6 — Persistence
```bash
python3 apt29_hunt.py persistence apt29_day1.json
```
Two persistence mechanisms:
- **~209 Sysmon Event 13 (registry value set)** writing to `…\CurrentVersion\Run` — **Run-key** autostarts that relaunch the payload at every logon.
- **5 Security Event 7045 (service installed)** — new services registered to survive reboots and run with high privilege.

- **ATT&CK:** **T1547.001** (Boot or Logon Autostart: Registry Run Keys) and **T1543.003** (Create or Modify System Process: Windows Service).
- **Evidence:** Sysmon EID 13 (`TargetObject` under a `Run` key); Security EID 7045 (`ServiceName` / `ImagePath`).

### See the raw data underneath
The helper counts for you, but you should always know how to hit the JSON directly. For example, to count every LSASS-access record (Sysmon EID 10) with plain `grep`:

```bash
grep -c '"EventID":10' apt29_day1.json
```

That's the un-abstracted view — every line is one JSON event, and every subcommand above is just a smarter filter over the same file. When a finding matters, drop to `grep` and read the actual event.

---

## 4. Two lenses: Cyber Kill Chain × ATT&CK

A strong capstone tells the story in **both** frameworks. The **Lockheed Martin Cyber Kill Chain** gives you the intrusion *narrative* (the arc of the attack); **ATT&CK** gives you the granular *per-artifact* mapping. They are not competitors — they are the wide shot and the close-up.

| Cyber Kill Chain phase | What happened here | ATT&CK technique(s) | Proof in the telemetry |
|---|---|---|---|
| **Exploitation / Installation** | LOLBins get first execution; PowerShell staged | T1059.001, T1059.003 | Sysmon 1 chains (19); PS 4104 (414) |
| **Actions on Objectives — credential access** | LSASS dumped; DCSync steals the domain | T1003.001, **T1003.006** | Sysmon 10 (`0x1FFFFF` ×3); Security **4662** (×1) |
| **Lateral Movement** | Remote execution over WMI/DCOM | T1047, T1021.003 | WMI-Activity 5857-5861 (90) |
| **Command & Control / Persistence** | Run keys + services survive reboot | T1547.001, T1543.003 | Sysmon 13 (209); Security 7045 (5) |

Narrated in kill-chain terms: the attacker **executed** via living-off-the-land binaries, **weaponized PowerShell** for hands-on work, **harvested credentials** from LSASS and then escalated to **total domain compromise via DCSync**, **moved laterally** over WMI, and **entrenched** with Run keys and services. Every clause of that sentence is backed by a specific EventID above.

---

## 5. Grade yourself

Score your reconstruction against **[`data/APT29-ANSWER-KEY.md`](data/APT29-ANSWER-KEY.md)** — it holds the full ATT&CK technique → evidence table and the rubric. Assess yourself on:

1. **Coverage** — did you find all the stages? (Each is one `apt29_hunt.py` subcommand.)
2. **Evidence-to-technique traceability** — for every ATT&CK ID, can you cite the *specific* event (EventID + field), not just the technique name? That evidence-first discipline — every ATT&CK ID backed by a concrete artifact — is the practice modelled in public write-ups like **The DFIR Report** (<https://thedfirreport.com/>) and in **MITRE ATT&CK**'s own detection guidance.
3. **Signal vs. noise** — did you separate the real LSASS dump (`0x1FFFFF`, `0x1478`) from the ~830 benign `0x1000` query-only accesses? (Module 07's GrantedAccess lesson, applied at scale.)
4. **The DCSync needle** — did you catch the single 4662 event in 196,081? That's the capstone's marquee find.
5. **Detection gaps** — where is a stage *thin* in the telemetry? The MITRE evals methodology explicitly scores visibility gaps, not just hits. Note them.

---

> **A third lens — the Pyramid of Pain.** David Bianco's *Pyramid of Pain* ranks indicators by how much it hurts an adversary to lose them: hash values and IPs sit at the bottom (trivial to swap "without breaking stride"), while **Tactics, Techniques & Procedures sit at the apex** — forcing an adversary to abandon a *behaviour* makes them reinvent their tradecraft. Every detection this capstone builds lives at that apex: you convicted DCSync on the *replication-request behaviour* (4662 + the `1131f6aa` control-access right), not on APT29's IP or a file hash. A hash-based rule dies the moment the attacker recompiles; a rule that fires on "a non-DC account requests directory replication" costs APT29 a fundamental change to evade. Grade your detections by *where on the pyramid they sit* — the higher, the harder to cheaply evade. (Bianco, *The Pyramid of Pain*, 2013.)
>
> **Guard against confirmation bias — you were handed the answer.** This capstone names the actor (APT29) and ships an answer key, which quietly invites the classic failure: forcing evidence to fit the label. Richards Heuer's **Analysis of Competing Hypotheses (ACH)** is the counter-discipline — for each finding, enumerate *competing* explanations and actively seek evidence that would **refute** each, rather than collecting confirmations for your favourite. That is exactly what separates the 830 benign `0x1000` LSASS *queries* (AV/EDR/Windows) from the 3 real dumps: you refute "malicious" for the query-only mask, you don't assume it because "APT29 dumps LSASS." State a **confidence level** per finding and name the one alternative you ruled out — a claim you cannot attack is one you cannot trust. On a real case with no answer key and no group name, this hypothesis-testing habit, not the technique catalog, is what keeps you honest. (Heuer, *Psychology of Intelligence Analysis*, ch. 8, CIA CSI.)

## 6. Try it yourself

Before you read the answer key, prove you can do these unaided:

1. **Run the whole chain in one shot** — `python3 apt29_hunt.py all apt29_day1.json` — and write a one-line finding for each stage naming the ATT&CK ID and the deciding EventID/field.
2. **Isolate the dump.** From the `lsass` output, identify the exact three events that are the real credential theft and explain — in one sentence each — why `0x1000` is *not* one of them.
3. **Pull the needle by hand.** Use `grep` to find the single DCSync 4662 event directly in the JSON, then read the full record. Who is the subject account, and why does that convict it?
4. **Score your detection gaps.** Which stage has the *least* corroborating evidence in this day-1 telemetry, and what additional sensor (think Module 10 — Sysmon vs. default logging) would close it?
5. **Write the report.** Produce a phase-ordered timeline (kill-chain order), a 5-line findings summary, your IOCs, and one containment recommendation. Compare it to the rubric.

---

## 7. What this capstone proved you can do

- Take a **196,081-event triage collection** from a reputable benchmark and, cold, reconstruct an intrusion **end-to-end**.
- Map every artifact to a **specific ATT&CK technique** with an EventID + field citation.
- Separate **signal from noise** at scale — the 3 real LSASS dumps hiding among 830 benign accesses.
- Find the **one-in-196,081 DCSync needle** and understand why it means domain-wide compromise.
- Tell the story in **both** Cyber Kill Chain and ATT&CK terms, and **grade your own work** against a published key.

> **You learned the craft on Case-001. Here you proved it on the benchmark the industry uses.**

## Sources & further reading
- **MITRE ATT&CK — APT29 (Group G0016)** — the attribution (Cozy Bear / The Dukes / SVR): <https://attack.mitre.org/groups/G0016/>
- **MITRE ATT&CK Evaluations — APT29:** <https://evals.mitre.org/enterprise/apt29/>
- **OTRF `detection-hackathon-apt29`** (the telemetry recording): <https://github.com/OTRF/detection-hackathon-apt29>
- **SANS "Hunt Evil" poster** (lateral-movement artifacts by technique): <https://www.sans.org/posters/hunt-evil/>
- **Lockheed Martin — Cyber Kill Chain:** <https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html>
- **The DFIR Report** (write-up format this capstone's report emulates): <https://thedfirreport.com/>
- **MITRE ATT&CK technique pages:**
  [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) ·
  [T1003.006 DCSync](https://attack.mitre.org/techniques/T1003/006/) ·
  [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) ·
  [T1047 WMI](https://attack.mitre.org/techniques/T1047/) ·
  [T1547.001 Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)

---
*Back to the [course guide](../COURSE.md) · [curriculum](../README.md). Terms are defined in [GLOSSARY.md](../GLOSSARY.md).*
