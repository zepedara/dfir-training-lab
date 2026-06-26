# Module 7 — Identity & Credential Theft

**Deck mapping:** *Intrusion Hunting Playbook* → "Detecting Credential Theft & Misuse" / "Identity Context" · *Advanced Intrusion Forensic Hunting* → "Phase 2: Identity Analysis."
**Goal:** detect credential dumping (Mimikatz against LSASS) and read the logon events that reveal *who* moved *where*.

---

## Concept (from the decks)
Once an attacker has code execution, they go for **credentials**. The classic move: dump them from **LSASS** memory with Mimikatz. The decks flag two evidence sources:
1. **Credential dumping** → Sysmon **Event ID 10 (ProcessAccess)** where something opens `lsass.exe` with suspicious access rights.
2. **Logon analysis** → Security **4624** (successful logon) with **Logon Types** that matter: **Type 3** (network), **Type 9** (NewCredentials — runas/`/netonly`, Pass-the-Hash signal), **Type 10/11** (RDP / cached). Plus **4648** (explicit creds) and **4672** (admin logon).

This module's sample is **Invoke-Mimikatz** hitting LSASS.

---

## Setup
```bash
cd module-07-identity-credential-theft/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

## Step 1 — Detect the credential dump (Chainsaw)
```bash
chainsaw hunt /data -s /opt/chainsaw/sigma --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
**Expected output:**
```
[+] 3 Detections found on 1 documents
 timestamp            detections                          Event ID  Computer   Event Data
 2019-05-02 14:50:17  ‣ Accessing WinAPI in PowerShell    10        IEWIN7     TargetProcessId: 484
                      ‣ Credential Dumping Tools
                      ‣ Potential Credential Dumping
```
**Read it:** Sysmon **Event 10 (ProcessAccess)** — PowerShell (Invoke-Mimikatz) is **accessing another process via WinAPI**, and the `TargetProcessId` resolves to **LSASS**. Three independent rules agree: this is credential dumping.

## Step 2 — Hunt the logons (concept + commands)
On a real Security log you'd then chase how the stolen creds were used:
```bash
# parse, then filter to logon events:
EvtxECmd -d /data --csv /data --csvf sec.csv
# Then look for 4624 with Logon Type 9 (NewCredentials = PtH signal) or Type 3 from unusual hosts.
```
**What to look for (decks' checklist):**
- **4624 / Type 9** soon after the dump → attacker using harvested creds (`runas /netonly`).
- **4648** (explicit credentials) → lateral logons with a specific account.
- **4672** on a workstation → unexpected admin logon.

## Why this matters
Credential theft is the hinge of an intrusion: it's what turns "one compromised box" into "domain-wide." Catching the LSASS access (Event 10) and then the *abnormal logons* (4624 Type 9/3) is how you trace the spread.

## Exercises
1. Run chainsaw on other `Credential Access/` samples — find an **LSASS dump via comsvcs.dll** (`rundll32 comsvcs MiniDump`).
2. In a Security log, list every **4624** and bucket by **Logon Type** — which are interactive vs network vs NewCredentials?
3. Correlate a Type 9 logon time with Module 6's lateral-movement detections — same window?

## Pivot
- The dumping **process** → **Module 1 (Prefetch)** to prove it ran and when.
- The resulting **logons** → **Module 8 (Lateral Movement)** to see where the creds went.

---
*Next: [Module 8 — Lateral Movement](../module-08-lateral-movement).*
