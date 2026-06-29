# Module 10 — Sysmon + Windows Event Forwarding (The Visibility Layer)

**Deck mapping:** *Intrusion Hunting Playbook* → "Building Visibility: Sysmon & WEF" · *Advanced Intrusion Forensic Hunting* → "Instrumentation: Seeing the Attack."
**Goal:** understand the telemetry that made Modules 6–9 possible. **Sysmon** is the high-fidelity sensor on the endpoint; **Windows Event Forwarding (WEF)** is the plumbing that ships every endpoint's logs to one place to hunt. Master the **Sysmon event-ID map** and you can read any of the samples in this lab.

---

## Concept (from the decks)
The default Windows audit policy is thin. **Sysmon** (Sysinternals) is a free driver+service that writes rich, attacker-relevant events to `Microsoft-Windows-Sysmon/Operational` — process trees with hashes and command lines, network connections, image loads, registry edits, named pipes, and remote-thread injection. It's the single biggest visibility upgrade you can deploy, and it's why Chainsaw/Hayabusa had so much to find.

**WEF** answers "great telemetry, but it's on 5,000 endpoints." Endpoints are **Source-initiated subscribers**; a **Windows Event Collector (WEC)** pulls/receives their logs into one `ForwardedEvents` store (configured with `wecutil` + subscription XML). That collector is what you point a hunting tool at — it turns per-host Sysmon into the **enterprise-wide** data set Module 4's stacking and Module 6's Sigma sweeps assume. WEF is **agentless** (built into Windows), which is why it's the classic budget-friendly visibility stack.

> The decks' arc closes here: **Triad (Modules 1–4)** proves execution on a host; **Sysmon + WEF** is the layer that lets you do the same hunt across the whole estate, in order, from one console.

---

## The Sysmon event-ID map (memorise this)
| ID | Event | What it catches |
|---|---|---|
| **1** | Process Create | full command line, hashes, **ParentImage** (the process tree) |
| **2** | File creation time changed | **timestomping** |
| **3** | Network Connection | C2 / lateral connections (proc → IP:port) |
| **5** | Process Terminated | end of a process's life (pairs with 1) |
| **6** | Driver Loaded | malicious/unsigned drivers |
| **7** | Image Loaded | **DLL side-loading**; `Automation.dll` in a non-PS proc (Module 9) |
| **8** | CreateRemoteThread | **process injection** (Module 9's PSInject) |
| **9** | RawAccessRead | raw disk reads (`\\.\C:`) — credential/$MFT theft |
| **10** | ProcessAccess | **LSASS access** = credential dumping (Module 7) |
| **11** | FileCreate | dropped files; Startup-folder persistence (Module 8) |
| **12/13/14** | Registry (key/value/rename) | autoruns, **CLM/ExecutionPolicy tampering** (Module 9), new shares (Module 8) |
| **15** | FileCreateStreamHash | **Mark-of-the-Web** / ADS (downloaded files) |
| **17/18** | Pipe Created / Connected | **PsExec & named-pipe** lateral movement (Modules 6, 8) |
| **19/20/21** | WMI Event subscription | WMI persistence |
| **22** | DNS Query | C2 domain resolution |
| **23/26** | File/stream delete | anti-forensic wiping |

---

## Setup
```bash
cd module-10-sysmon-wef/data
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

## Step — Read a Sysmon capture end-to-end
**`Sysmon_UACME_45.evtx`** is a **UACME** UAC-bypass (technique #45). Parsed, it contains Sysmon **1 ×5, 12 ×1, 13 ×1, 5 ×1** — a tidy worked example of reading a process+registry story from Sysmon alone.
```bash
EvtxECmd -f /data/Sysmon_UACME_45.evtx --csv /data --csvf sysmon.csv
# or get the ranked timeline:
hayabusa csv-timeline -d /data -o /data/timeline.csv -w
```
**Read it:** the **Sysmon 13 (registry value set)** is the heart of the bypass — UACME #45 hijacks a registry key an **auto-elevating** Windows binary reads, so a normal process spawns an elevated child (the **Sysmon 1** with the auto-elevated parent) **without a UAC prompt**. The **Sysmon 5** is that process tearing down afterwards. Walk it: which registry value (13) was written, then which process (1) launched elevated as a result?

---

## Exercises
1. **Build the tree:** from `Sysmon_UACME_45.evtx`, list every **Sysmon 1** with its **Image** and **ParentImage** and draw the parent→child chain. Where does elevation appear without a `consent.exe` prompt?
2. **Map the IDs:** for each event in the file, name what it catches from the table above. Which single event (the **registry 13**) is the bypass itself, and which (**process 1**) is the payoff?
3. **WEF design:** you have 200 endpoints running Sysmon. Sketch the WEF setup — source-initiated subscription, the `wecutil` collector, the `ForwardedEvents` channel — and explain why Chainsaw/Hayabusa run against the **collector**, not each host.
4. **(Stretch)** Use `get-data.sh` to pull more Sysmon samples and re-run `hayabusa csv-timeline` — confirm the same ID map explains techniques you haven't seen yet.

## Answers / what to find
- `Sysmon_UACME_45.evtx` = Sysmon **1/12/13/5**. The **13 (registry value set)** on an auto-elevation key is the UAC bypass; the resulting elevated **1 (process create)** with no UAC prompt is the proof; **5** is teardown.
- The ID map is the takeaway: **1** (process+tree), **3** (network), **7** (image load/side-load), **8** (injection), **10** (LSASS), **11** (file drop), **12/13** (registry), **17/18** (pipes) — these are the exact IDs Modules 6–9 hunted.
- **WEF** centralises all of the above into `ForwardedEvents` on a collector; that single store is what makes enterprise-scale, in-order hunting (and Module 4's cross-host stacking) possible.

## Pivot
- This is the foundation under the whole of **Part B** — re-run any Module 6–9 sample now knowing exactly what each Sysmon ID means.
- Centralised Sysmon → **Module 6 (Sigma hunting)** at scale; cross-host artifacts → **Module 4 (stacking)**.

---
*Back to the [curriculum](../README.md). You can now take a triage collection and build a full incident timeline — **"Master the Triad. Close the Gap."***
