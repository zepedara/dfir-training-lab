# Module 6 — Sigma Hunting with Chainsaw & Hayabusa

**Deck mapping:** *Intrusion Hunting Playbook* → "Centralized Hunting" + lateral-movement detection · *Advanced Intrusion Forensic Hunting* → "Phase 3: Lateral Movement."
**Goal:** take raw Windows event logs and have detection rules surface the attacker for you — no manual log reading.

---

## Concept (from the decks)
Attackers leave fingerprints in the event logs (especially **Sysmon**). You *could* read thousands of events by hand — or run **Sigma** rules (vendor-neutral detections) that match known attacker behavior automatically. Two tools do this offline here:
- **Hayabusa** — builds one **ranked timeline**: every notable event with a severity, fast. Good for "what happened, in order?"
- **Chainsaw** — **hunts** with the full Sigma rule set and prints *which rule matched which event*. Good for "show me the named detections."

This module's data is a **PsExec lateral-movement** capture (Sysmon logs from `MSEDGEWIN10`). Your job: let the tools prove the lateral movement.

---

## Setup
```bash
cd module-06-sigma-chainsaw-hayabusa/data        # contains the sample .evtx
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
# (--network none proves it's fully offline)
```

---

## Step 1 — Hayabusa timeline
```bash
hayabusa csv-timeline -d /data -o /data/timeline.csv -w
```
> **`-w`** = no-wizard (use all rules; required when not in an interactive terminal).

**Expected output:**
```
Total detection rules: 4,636
Detection rules enabled after channel filter: 2,284
Events with hits / Total events: 8 / 12  (Data reduction: 33.33%)
Total | Unique detections: 15 | 8
```
Open `timeline.csv` — the first columns tell the story:
```
Timestamp                       RuleTitle      Computer      Channel
2020-12-09 16:52:34.622 +00:00  Pipe Created   MSEDGEWIN10   Sysmon
2020-12-09 16:52:34.562 +00:00  Proc Exec      MSEDGEWIN10   Sysmon
2020-12-09 16:52:42.933 +00:00  Net Conn       MSEDGEWIN10   Sysmon
```
**Read it:** a **pipe was created**, a **process executed**, and a **network connection** opened — within seconds, on one host. That rhythm (pipe → exec → net) is the signature of remote execution.

---

## Step 2 — Chainsaw hunt (named detections)
```bash
chainsaw hunt /data -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
**Expected output (trimmed):**
```
[!] Loaded 3613 detection rules
[+] Loaded 1 forensic artefacts (68.0 KiB)
[+] Group: Sigma
 timestamp            detections                              Event ID  Computer      Event Data
 2020-12-09 16:52:34  ‣ PsExec Default Named Pipe             17        MSEDGEWIN10   EventType: CreatePipe
                      ‣ PsExec Tool Execution From            (Sysmon)                PipeName: \PSEXESVC
                        Suspicious Locations
```
**Read it:** Chainsaw names the exact technique — **PsExec**, via its default named pipe **`\PSEXESVC`** (Sysmon **Event ID 17 = Pipe Created**). This is the "Shared Named Pipes" lateral-movement slide made concrete: PsExec drops a service and communicates over that pipe.

---

## What you just proved
You took raw Sysmon logs and, in two commands, established **lateral movement via PsExec** with the supporting evidence (the `\PSEXESVC` pipe, the process execution, the timing). That's the whole point of Sigma hunting: rules do the pattern-matching; you confirm and pivot.

## Exercises
1. Run both tools against other samples in `EVTX-ATTACK-SAMPLES/Lateral Movement/` — can you spot **WMI** (`wmic`/`Win32_Process`) and **DCOM** executions?
2. In `timeline.csv`, sort by timestamp and write the 3-line story of what the attacker did.
3. Re-run chainsaw with `--level high` — how does narrowing severity change the noise?

## Pivot (to other modules)
- The **process** chainsaw flagged → check its execution in **Module 1 (Prefetch)** on the target host.
- The **PsExec service** → **Module 8 (Lateral Movement)** goes deeper on PsExec/DCOM/WMI.
- **PowerShell** detections → **Module 9**.

---
*Next: [Module 7 — Identity & Credential Theft](../module-07-identity-credential-theft).*
