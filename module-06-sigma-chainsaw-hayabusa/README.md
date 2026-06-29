# Module 6 — Sigma Hunting with Chainsaw & Hayabusa

**Deck mapping:** *Intrusion Hunting Playbook* → "Centralized Hunting" + lateral-movement detection · *Advanced Intrusion Forensic Hunting* → "Phase 3: Lateral Movement."
**Goal:** take raw Windows event logs and let **detection rules** surface the attacker for you — automatically — instead of reading thousands of events by hand.

---

## 1. Background — why this matters

### The problem
In Module 5 you parsed `.evtx` files into a readable table. But a single busy server can generate **tens of thousands of events an hour**. You cannot read them all. You need something that already *knows* what attacker behavior looks like and points straight at it. That something is a **detection rule**.

### What a detection rule is (plain language)
A **detection rule** is a saved description of "bad," written so a tool can match it against logs automatically. Think of it as a *saved search with a name and a severity*. For example, a rule might say: *"If a process called `lsass.exe` is opened with access rights `0x1010`, that's credential dumping — flag it as HIGH."* When the tool finds an event matching that description, it **fires** the rule and tells you the rule's name.

### What Sigma is, and how it maps to events
The problem with detection rules used to be that every product wrote them in its own language — a rule for Splunk didn't work in Elastic, and so on. **Sigma** solved that. **Sigma is a vendor-neutral, plain-text (YAML) format for writing detection rules.** You write the logic once in Sigma, and tools translate it to whatever back end you use. Sigma is maintained as a huge open community rule set (**SigmaHQ**) covering thousands of known techniques.

A Sigma rule has two key parts:
- a **`logsource`** — which log/channel/provider it applies to (e.g. Sysmon, or the Security log), and
- a **`detection`** — the field/value conditions that must match (e.g. `EventID: 17` **and** `PipeName: \PSEXESVC`).

Here is the subtle bit: a Sigma rule names **logical** fields (like `Image`, `PipeName`, `GrantedAccess`). But the actual `.evtx` event stores those values in specific XML locations. So something has to **translate Sigma's field names into the real event's field locations**. That translation table is called a **mapping** (you'll pass one to Chainsaw below). The mapping is the bridge between "what the rule calls a field" and "where that field actually lives in the event."

### How the two tools apply Sigma rules
Both tools in this module read raw `.evtx`, load the Sigma rule set, and report matches — but they answer different questions:

- **Hayabusa** (by **Yamato Security**) builds **one ranked timeline**: it scans the events, fires rules, and produces a single CSV where every notable event has a **severity level** (informational → low → medium → high → critical) and a timestamp. Best for *"what happened, in order, worst first?"*
- **Chainsaw** (by **WithSecure**) is a **hunter**: you point it at logs and a Sigma folder, and it prints **which named rule matched which event**, with the supporting fields. Best for *"show me the named detections and the evidence."*

You typically run **both**: Hayabusa for the fast big-picture timeline, Chainsaw to pull the named, evidence-rich detections you'll quote in your report.

---

## 2. What the tools do (high level)

| | Hayabusa | Chainsaw |
|---|---|---|
| Made by | Yamato Security | WithSecure (Countercept) |
| Core question | "What happened, ranked by severity?" | "Which named rule fired, with what evidence?" |
| Output | one CSV **timeline**, every event scored | a table of **detections** + the event data |
| Rules used | bundled Hayabusa+Sigma rule set | the Sigma repo you point it at, via a **mapping** |
| Bonus | `logon-summary`, `eid-metrics`, `search` | extracts the matching fields inline |

Both are **offline** — no internet, no agent, no SIEM. Perfect for triage on a collected evidence folder.

---

## 3. The scenario in this module's data

This module's `data/` folder bundles **23 curated attack-technique `.evtx`** files (a subset of the public Yamato `hayabusa-sample-evtx` / EVTX-ATTACK-SAMPLES sets — see `data/README.md`). They cover a range of techniques: Mimikatz hash-dumps, PowerSploit, Invoke-Obfuscation PowerShell, a password-spray, a UACME UAC-bypass, event-log tampering, and several **PsExec** lateral-movement captures.

The **guided walkthrough below uses one file** — `sysmon_privesc_psexec_dwell.evtx`, a **PsExec lateral-movement** capture (Sysmon logs from host `MSEDGEWIN10`) — so your numbers match exactly. Then you'll run **both tools across the whole folder** and let them name every technique. **PsExec** is Microsoft's legitimate remote-admin tool (run a command on another machine); attackers love it because it's signed and everywhere. It works by dropping a service that listens on a **named pipe** called **`\PSEXESVC`** — and that pipe is its fingerprint.

> **What's a named pipe?** A *pipe* is a private channel two programs use to talk to each other; a *named* pipe has a label (like `\PSEXESVC`) so a program on another machine can connect to it by name. PsExec uses one to send commands to the service it installed on the remote host. Sysmon logs pipe creation as **Event ID 17** and pipe connection as **Event ID 18**.

---

## 4. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-06-sigma-chainsaw-hayabusa/data        # 23 curated .evtx samples
```
(Every command in this module is run **from inside this `data/` folder**. Both tools — `chainsaw` and `hayabusa` — are installed natively and already on your `PATH`, so you call them directly by name in Git Bash; no container or Docker. The VM is kept offline so the analysis stays fully offline.)

> **Chainsaw rules/mappings path:** the `chainsaw hunt` commands below point `-s` at the bundled Sigma rules and `--mapping` at `sigma-event-logs-all.yml`. Those paths (shown here as `/opt/chainsaw/...`) live wherever **chainsaw** is installed on your lab VM — adjust them to your VM's chainsaw rules/mappings location if they differ.

---

## 5. Step-by-step walkthrough

### Step 1 — Hayabusa timeline on the PsExec sample
```bash
hayabusa csv-timeline -f sysmon_privesc_psexec_dwell.evtx -o timeline.csv -w -C
```
- **`csv-timeline`** — the sub-command that builds a CSV timeline (Hayabusa has others, like `logon-summary`).
- **`-f ...evtx`** — analyze this one **f**ile. (Use **`-d .`** for a whole **d**irectory — Step 4.)
- **`-o timeline.csv`** — write the **o**utput timeline here.
- **`-w`** — **no-wizard**: just use all the rules, don't prompt me interactively. (Required when you're not babysitting a terminal.)
- **`-C`** — **clobber**: overwrite `timeline.csv` if it already exists (otherwise Hayabusa refuses, to protect your work). On a first run you can omit it.

**Expected output (summary lines):**
```
Total detection rules: 4,628
Detection rules enabled after channel filter: 2,280
Events with hits / Total events: 8 / 12  (Data reduction: 33.33%)
Total | Unique detections: 15 | 8
Top high alerts:   PsExec Service Child Process Execution (1)
Top medium alerts: PsExec Tool Execution From Suspicious Locations (2) · PsExec Service Execution (1)
Saved file: timeline.csv
```
**Read the summary:** Hayabusa loaded ~4,600 rules, kept the ~2,280 that apply to these channels, and out of **12** events, **8** were notable — a **33% data reduction** before you read a single line. The headline alert is **HIGH: "PsExec Service Child Process Execution."** That's the whole value proposition: 12 events became one obvious lead.

### Step 2 — Read the timeline
Open `timeline.csv`. The important columns are `Timestamp`, `RuleTitle`, `Level`, `Computer`, `Channel`, `EventID`. Sorted by time, the story is:
```
Timestamp                       Level  RuleTitle                                 EventID
2020-12-09 16:52:34.622 +00:00  low    PsExec Default Named Pipe                 17  (Pipe Created)
2020-12-09 16:52:34.622 +00:00  med    PsExec Tool Execution From Suspicious...  17
2020-12-09 16:52:41.861 +00:00  med    PsExec Service Execution                  1   (Process)
2020-12-09 16:52:42.478 +00:00  low    PsExec Default Named Pipe                 18  (Pipe Connect)
2020-12-09 16:52:45.141 +00:00  high   PsExec Service Child Process Execution    1
```
**Read it:** within ~11 seconds on one host — a **`\PSEXESVC` pipe is created** (17), the **PsExec service process runs** (1), the **pipe is connected** (18), then the service **spawns a child process** (1). That rhythm — *pipe → service → pipe-connect → child process* — is the textbook signature of **remote execution via PsExec**. The `Level` column lets you start at the HIGH row and work outward.

### Step 3 — Chainsaw hunt (named detections + evidence)
```bash
chainsaw hunt sysmon_privesc_psexec_dwell.evtx \
  -s /opt/chainsaw/sigma \
  --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml
```
- **`hunt`** — run Sigma rules over the logs and print matches (Chainsaw's main mode).
- **`...evtx`** — the artifact to hunt (a file **or** a folder).
- **`-s /opt/chainsaw/sigma`** — the **s**igma rules folder bundled with chainsaw on the lab VM (adjust to your VM's path if different).
- **`--mapping .../sigma-event-logs-all.yml`** — the **mapping** (Section 1) that tells Chainsaw where each Sigma logical field lives inside a real Windows event. Without it, Chainsaw can't translate the rules to these logs.

**Expected output (trimmed):**
```
[!] Loaded 3383 detection rules (378 not loaded)
[+] Loaded 1 forensic artefacts (68.0 KiB)
[+] Group: Sigma
 timestamp            detections                          Event ID  Computer      Event Data
 2020-12-09 16:52:34  ‣ PsExec Default Named Pipe         17        MSEDGEWIN10   EventType: CreatePipe
                      ‣ PsExec Tool Execution From                                PipeName: \PSEXESVC
                        Suspicious Locations - PipeName                           Image: C:\Users\Public\psexecprivesc.exe
 2020-12-09 16:52:41  ‣ PsExec Service Execution          1         MSEDGEWIN10   Image: C:\Windows\PSEXESVC.exe
                                                                                  User: NT AUTHORITY\SYSTEM
```
> The `(378 not loaded)` is normal — those Sigma rules target log sources not present here (e.g. Linux/cloud), so Chainsaw skips them.

**Read it:** Chainsaw names the exact technique — **PsExec via its default named pipe `\PSEXESVC`** (Sysmon **Event 17 = Pipe Created**) — and hands you the evidence: the pipe was created by **`C:\Users\Public\psexecprivesc.exe`** (a copy of PsExec dropped in a world-writable folder — that's the "Suspicious Locations" rule), and the resulting **`PSEXESVC.exe`** ran as **`NT AUTHORITY\SYSTEM`** (Event 1). That is lateral movement *and* privilege to SYSTEM, proven in one command.

### Step 4 — Run BOTH tools across the WHOLE folder
Now stop cherry-picking one file. Point each tool at the directory and let it triage all 23 samples at once:
```bash
# Hayabusa: one merged, ranked timeline of everything
hayabusa csv-timeline -d . -o all-timeline.csv -w -C

# Chainsaw: every named detection across the folder, saved to CSV
chainsaw hunt . -s /opt/chainsaw/sigma \
  --mapping /opt/chainsaw/repo/mappings/sigma-event-logs-all.yml \
  --csv --output chainsaw-out
```
- **`-d .`** (Hayabusa) / pointing Chainsaw at the folder — process every `.evtx` in one shot, merging results.
- **`--csv --output chainsaw-out`** (Chainsaw) — instead of the screen table, write the detections to CSV files in that folder (one per rule group), so you can sort and filter the full set.

Open the merged outputs and you'll see each sample light up with the technique its filename hints at: the `mimikatz-*` files fire credential-dumping rules, `Powershell-Invoke-Obfuscation-*` fire encoded-PowerShell rules, `password-spray` / `smb-password-guessing` fire brute-force rules, `UACME_59` fires a UAC-bypass rule, and `disablestop-eventlog` fires a defense-evasion (log-tampering) rule. **This is the real workflow:** one command turns a folder of unknown logs into a ranked list of named leads.

### Step 5 — Tune the noise with severity
```bash
hayabusa csv-timeline -d . -o high.csv -w -C --min-level high
```
- **`--min-level high`** — only keep detections rated **high** or **critical**; drop the informational/low/medium chatter.

Compare `high.csv` to `all-timeline.csv`. Raising the floor shrinks the list to the few events most worth your attention first — but remember **low-severity events still matter** once you've found a lead (the `low` "PsExec Default Named Pipe" rows in Step 2 were part of the same attack). Severity decides *reading order*, not *importance*.

---

## 6. Reading the output — what's a real hit vs. noise

- **A cluster beats a single hit.** One "PsExec Default Named Pipe" alone could be an admin using PsExec legitimately. The same host showing *pipe → SYSTEM service → child process* in seconds is an attack. Both tools make the cluster visible.
- **`Level` / severity is a starting point, not a verdict.** Start at HIGH, then read the surrounding low/medium events to build the timeline.
- **Look at the evidence fields.** Chainsaw's `Event Data` (the `Image` path, the `PipeName`, the `User`) is what separates real from benign. `C:\Users\Public\psexecprivesc.exe` running as SYSTEM is not a sysadmin doing maintenance.
- **False positives** usually come from legitimate admin tools (PsExec, PowerShell remoting) used the normal way. Triage by asking: *right host? right account? expected time? expected source path?* If the answer is "no" to several, it's real.

---

## 7. Investigative narrative — the story the evidence tells

On `MSEDGEWIN10`, an attacker who already had a foothold used **PsExec** to execute code on the box: they dropped `psexecprivesc.exe` into the world-writable `C:\Users\Public\`, which installed the **PsExec service** (`PSEXESVC.exe`) and opened the **`\PSEXESVC`** named pipe to receive commands. The service ran as **SYSTEM**, then spawned a child process — remote execution with full privilege. You proved all of it in **two commands**: Hayabusa ranked it to the top of a 12-event timeline, and Chainsaw named the technique and handed you the pipe name, the dropped binary path, and the SYSTEM context. That's Sigma hunting: the rules do the pattern-matching; you confirm and pivot.

---

## 8. Try-it-yourself exercises

1. **Name them all.** After Step 4, open `all-timeline.csv` and the Chainsaw CSV. For each of the 23 samples, write the one-line technique its detections reveal (Mimikatz hash-dump, Invoke-Obfuscation, password-spray, UACME bypass, event-log tampering, …). Pure **WMI/DCOM** lateral movement lives in **Module 8**.
2. **Tell the story.** In `timeline.csv` (Step 2), sort by timestamp and write the 3-line account of the PsExec attack.
3. **Tune severity.** Run Step 5 with `--min-level high` vs. `--min-level low`. How does the noise change? Which level would you start triage at, and why is "high only" risky if you stop there?
4. **Cross-tool check.** Pick the `mimikatz-privesc-hashdump.evtx` sample. Does Hayabusa's top alert and Chainsaw's named rule agree on the technique? When they differ, why might that happen (different rule sets)?

---

## 9. Key takeaways

- A **detection rule** is a named, severity-tagged "saved search for bad." **Sigma** is the vendor-neutral language those rules are written in; a **mapping** bridges Sigma's field names to real event fields.
- **Hayabusa** = fast ranked **timeline** (severity-scored). **Chainsaw** = named **detections + evidence**. Run both.
- Point them at a **whole folder** (`-d` / a directory) to triage many logs at once — that's the real workflow, not one file at a time.
- **Clusters and context** make a hit real; **severity** decides reading order, not importance.
- You took raw Sysmon logs and proved **PsExec lateral movement to SYSTEM** in two commands. Pivot from here: the flagged **process** → Module 1 (Prefetch); the **PsExec service** → Module 8 (Lateral Movement); **PowerShell** detections → Module 9.

---

## 10. Sources & further reading

- Chainsaw — WithSecure Labs: <https://github.com/WithSecureLabs/chainsaw> · Usage wiki: <https://github.com/WithSecureLabs/chainsaw/wiki/Usage>
- Hayabusa — Yamato Security: <https://github.com/Yamato-Security/hayabusa> · "Analyzing Sample Timeline Results": <https://github.com/Yamato-Security/hayabusa/wiki/Analyzing-Sample-Timeline-Results>
- Sigma rules & format — SigmaHQ: <https://github.com/SigmaHQ/sigma> · About Sigma: <https://sigmahq.io/>
- MITRE ATT&CK — PsExec / Remote Services (T1021.002), Service Execution (T1569.002): <https://attack.mitre.org/techniques/T1021/002/>
- Sample provenance — hayabusa-sample-evtx (Yamato): <https://github.com/Yamato-Security/hayabusa-sample-evtx> · EVTX-ATTACK-SAMPLES (@sbousseaden): <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>

---
*Next: [Module 7 — Identity & Credential Theft](../module-07-identity-credential-theft).*
