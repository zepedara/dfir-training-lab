# Module 6 — Sigma Hunting with Chainsaw & Hayabusa

**Deck mapping:** *Intrusion Hunting Playbook* → "Centralized Hunting" + lateral-movement detection · *Advanced Intrusion Forensic Hunting* → "Phase 3: Lateral Movement."
**Goal:** take raw Windows event logs and have detection rules surface the attacker for you — no manual log reading.

---

## Concept (from the decks)
Attackers leave fingerprints in the event logs (especially **Sysmon**). You *could* read thousands of events by hand — or run **Sigma** rules (vendor-neutral detections) that match known attacker behavior automatically. Two tools do this offline here:
- **Hayabusa** — builds one **ranked timeline**: every notable event with a severity, fast. Good for "what happened, in order?"
- **Chainsaw** — **hunts** with the full Sigma rule set and prints *which rule matched which event*. Good for "show me the named detections."

This module's `data/` folder bundles **23 curated attack-technique `.evtx`** (a subset of the Yamato `hayabusa-sample-evtx` / EVTX-ATTACK-SAMPLES sets). The **guided walkthrough below uses one of them** — `sysmon_privesc_psexec_dwell.evtx`, a **PsExec lateral-movement** capture (Sysmon logs from `MSEDGEWIN10`) — so the numbers are reproducible. The other 22 feed the exercises. Your job: let the tools prove the lateral movement.

---

## Setup
```bash
cd module-06-sigma-chainsaw-hayabusa/data        # 23 curated .evtx samples
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
# (--network none proves it's fully offline)
```

---

## Step 1 — Hayabusa timeline
Run it against the single PsExec sample (point at the whole folder with `-d /data` for the exercises):
```bash
hayabusa csv-timeline -f /data/sysmon_privesc_psexec_dwell.evtx -o /data/timeline.csv -w
```
> **`-w`** = no-wizard (use all rules; required when not in an interactive terminal).
> Add **`-C`** (`--clobber`) to overwrite `timeline.csv` on a re-run, or `rm /data/timeline.csv` first.

**Expected output** (exact on the lab's Windows VM; the container's Hayabusa build reports a few rules' difference — `4,628 / 2,280` — but the hit counts below are identical):
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
chainsaw hunt /data/sysmon_privesc_psexec_dwell.evtx -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
**Expected output (trimmed)** (the rule count varies with the bundled Sigma version — the current container reports `Loaded 3383 detection rules (378 not loaded)`; the single-artefact load is exact):
```
[!] Loaded 3383 detection rules (378 not loaded)
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
1. Run both tools across the **whole folder** (`hayabusa csv-timeline -d /data -o /data/all.csv -w -C` and `chainsaw hunt /data ...`). The 23 bundled samples include Mimikatz hash-dumps, PowerSploit, Invoke-Obfuscation PowerShell, password-spray, and a UACME bypass — can you name each from its detections? (Pure **WMI**/**DCOM** lateral movement lives in **Module 8**.)
2. In `timeline.csv`, sort by timestamp and write the 3-line story of what the attacker did.
3. Re-run chainsaw with `--level high` — how does narrowing severity change the noise?

## Pivot (to other modules)
- The **process** chainsaw flagged → check its execution in **Module 1 (Prefetch)** on the target host.
- The **PsExec service** → **Module 8 (Lateral Movement)** goes deeper on PsExec/DCOM/WMI.
- **PowerShell** detections → **Module 9**.

---
*Next: [Module 7 — Identity & Credential Theft](../module-07-identity-credential-theft).*
