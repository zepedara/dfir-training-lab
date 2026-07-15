# Module 20 — Triage & VQL Hunting with Velociraptor

**Deck mapping:** *Advanced Intrusion Forensic Hunting* → "Triage & live response" / endpoint collection and hunting at scale.
**Goal:** learn the modern open-source **acquisition and hunting** front-end of DFIR. Where every other module in this lab *parses artifacts you already have*, Velociraptor is the tool that **collects** them off a live endpoint — and, using its own query language **VQL**, lets you *hunt live host state* (running processes, loaded drivers, autoruns, artifacts) with SQL-like questions. This module queries the **live lab host** directly: there is no pre-staged evidence file, because Velociraptor is a live-IR/triage tool. Every query here is **read-only and benign** (listing processes, collecting a Prefetch artifact into a zip).

> **Evidence note.** This module runs against the **live machine you are sitting at** — that is the point of a triage tool. Nothing here modifies the system, detonates anything, or reaches the network: the commands **read** process state and **collect** an inert forensic artifact (Prefetch) into an offline `collection.zip`. Velociraptor is also the **harvest tool** referenced elsewhere in this lab — it is how you *acquire* the `.evtx`, registry hives, `$MFT`, and prefetch that Modules 05, 15, 16, and 01 then parse.

---

## 1. Background — what Velociraptor is, and why it matters

**Velociraptor** is an open-source (**AGPL-licensed**) endpoint DFIR and digital-forensics platform, created by **Dr. Michael Cohen** (author of the original Rekall/GRR memory and IR tooling) and now stewarded by **Rapid7**. It exists to answer one hard question that scales badly with hand tools: *"across my endpoints — one host or ten thousand — what is running, what is persisted, and what artifacts do I need off the box right now?"*

Its engine is **VQL — the Velociraptor Query Language** — a SQL-like language that queries **live endpoint state and forensic artifacts** the same way SQL queries a database. Instead of tables, VQL selects from **plugins** (`pslist()`, `glob()`, `parse_evtx()`, `pe_dump()`, …). This one idea unlocks three things the rest of the lab cannot do on its own:

- **Live triage** — ask a question of the *running* machine (processes, network, services, drivers, handles) at the moment of response, before anything is captured to disk.
- **Artifact collection** — bundle a set of VQL queries into a reusable **artifact** (e.g. the whole KAPE triage set) and run it to *acquire and package* evidence in one command.
- **Scale** — the exact same VQL that runs on one host runs as a **hunt** across an entire fleet from a central server, and the exact same VQL runs with **no server and no agent** as a standalone **offline collector**.

> **Where this sits in the lab.** The EZ tools (Modules 01–05, 15–18) and Volatility (Module 12) **parse** artifacts you already possess. Velociraptor is the other end of that pipeline — it is the **acquisition / triage front-end** that *gets you those artifacts in the first place* (and can hunt live host state directly). Think of it as the collector; the EZ tools/Volatility are the analyzers. On a real engagement you would run Velociraptor **first** to harvest, then feed the harvest into the tools the earlier modules taught.

---

## 2. VQL basics — reading the query language

Every VQL query has the same shape as SQL:

```
SELECT column, column, ...
FROM plugin(arg=value)
WHERE condition
```

- **`SELECT`** — the columns you want back. Each plugin exposes named columns (for `pslist()`: `Name`, `Pid`, `Ppid`, `CommandLine`, `Exe`, `CreateTime`, …).
- **`FROM plugin()`** — the data source. A **plugin** is a generator that yields rows: `pslist()` yields one row per running process, `glob()` yields files matching a path pattern, `parse_evtx()` yields event-log records. This is the key difference from SQL — the "table" is *computed live from the machine*.
- **`WHERE`** — filters the rows. VQL's regex operator is **`=~`** (`WHERE Name =~ 'svchost'` keeps rows whose `Name` matches the regex `svchost`). `LIMIT n` caps the row count.

**Artifacts** are the next layer up: a named, reusable **bundle of VQL** (a YAML definition) that packages a whole collection task. The lab-relevant ones:

- **`Windows.KapeFiles.Targets`** — runs the **KAPE triage target set** as VQL: it globs and copies the standard triage artifacts (`$MFT`, registry hives, `.evtx`, prefetch, browser history, …) into a collection. This is the single most-used acquisition artifact in real IR.
- **`Windows.Forensics.Prefetch`** — collects **and parses** every `.pf` prefetch file (execution evidence — the same artifact Module 01 parses with PECmd).
- **`Windows.Detection.*`** — a family of *hunting* artifacts (e.g. YARA sweeps, suspicious-autorun detections) that encode known-bad logic in VQL.

Thousands of community artifacts live in the **Velociraptor Artifact Exchange** (<https://docs.velociraptor.app/exchange/>) — hunts for specific ATT&CK techniques, parsers for niche artifacts, detection content — all just VQL you can read, audit, and run. **One caution:** Exchange artifacts are community-contributed and **not officially supported** — some fetch or run external tooling, so read an artifact's VQL before you run it (Velociraptor's own guidance is “use at your own risk”).

---

## 3. Setup

Open **Git Bash** on the lab host and change into this module's folder. Velociraptor is installed **natively and on your `PATH` as `velociraptor`** (a shim wraps the real binary), so you call it by bare name — there is no container, no server, and (for this module) no agent to install.

```bash
cd module-20-triage-velociraptor
```

- **`velociraptor`** — the single self-contained binary. The same executable is the server, the client, the offline collector, and — as here — a standalone **VQL interpreter** (`query`).
- **`-v query "<VQL>"`** — `-v` (verbose) prints progress/log lines to stderr; `query` runs the VQL you pass and prints the result rows as **JSON** to stdout. Because it queries the live host, there is **no `-f evidence` file** — the machine *is* the evidence.
- There is **no `data/` directory** for this module — every command reads the live system, so there is nothing to download or stage.

> **Note on the single `cd`.** The `cd module-20-triage-velociraptor` above appears **only in this first block**. The later blocks continue from the same working directory — do not repeat the `cd`.

---

## 4. Step-by-step walkthrough

### Step 1 — List running processes with parentage and command lines (`pslist()`)

```bash
velociraptor -v query "SELECT Name, Pid, Ppid, CommandLine FROM pslist() LIMIT 15"
```

- **`pslist()`** is VQL's core triage plugin: it walks the OS process table and yields one row per **running** process. Selecting `Name, Pid, Ppid, CommandLine` gives you the three things that crack most triage questions — *what is running, who launched it (`Ppid` = parent PID), and with what arguments.*

**Representative output (JSON, trimmed):**
```json
{"Name":"System","Pid":4,"Ppid":0,"CommandLine":null}
{"Name":"services.exe","Pid":712,"Ppid":628,"CommandLine":"C:\\Windows\\system32\\services.exe"}
{"Name":"svchost.exe","Pid":1044,"Ppid":712,"CommandLine":"C:\\Windows\\system32\\svchost.exe -k RPCSS -p"}
{"Name":"explorer.exe","Pid":3820,"Ppid":3760,"CommandLine":"C:\\Windows\\Explorer.EXE"}
{"Name":"powershell.exe","Pid":5120,"Ppid":3820,"CommandLine":"powershell.exe"}
```

**Read it.** This is the live process list in structured form. You triage it the way memory forensics reads `pstree` (Module 12): follow **`Ppid` → `Pid`** to reconstruct parentage, and read the **`CommandLine`** for tradecraft. Normal here — `services.exe` under the System `svchost` tree, `explorer.exe` as the shell, PowerShell launched from Explorer (a user opened it).

**What "suspicious" looks like** (what you hunt for): an **odd parent→child** chain (`winword.exe` → `cmd.exe` → `powershell.exe`), a **system name from the wrong path** (a `svchost.exe` whose `CommandLine` is *not* under `C:\Windows\System32`), a **misspelled** binary (`scvhost.exe`, `lsasss.exe`), or an **encoded PowerShell** command line (`-enc <base64>`, `-nop -w hidden`). The whole point of pulling `Ppid` and `CommandLine` together is that these anomalies only show up when you can see *lineage and arguments in one row*.

### Step 2 — Hunt a specific process with a WHERE-regex filter

```bash
velociraptor -v query "SELECT Name, CommandLine FROM pslist() WHERE Name =~ 'svchost' LIMIT 5"
```

- This is the same `pslist()` source, now **filtered** with **`WHERE Name =~ 'svchost'`** — `=~` is VQL's **regex match**, so this keeps only rows whose process name matches `svchost`. This is how you go from "show me everything" to *hunting a specific thing*.

**Representative output (JSON, trimmed):**
```json
{"Name":"svchost.exe","CommandLine":"C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p"}
{"Name":"svchost.exe","CommandLine":"C:\\Windows\\system32\\svchost.exe -k RPCSS -p"}
{"Name":"svchost.exe","CommandLine":"C:\\Windows\\system32\\svchost.exe -k netsvcs -p"}
{"Name":"svchost.exe","CommandLine":"C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p"}
```

**Read it.** Every `svchost.exe` shows the classic **`svchost.exe -k <service-group>`** pattern — Windows runs many services inside shared `svchost` host processes, and the **`-k`** argument names the **service group** (`DcomLaunch`, `RPCSS`, `netsvcs`, …). This ties directly to the **DCOM and service lessons in [Module 08 (Lateral Movement)](../module-08-lateral-movement)**: `DcomLaunch` and `RPCSS` are the very hosts that back DCOM-based lateral movement, and a legitimate `svchost` is **always** launched from `C:\Windows\System32` **with** a `-k` group. **What suspicious looks like:** a "`svchost.exe`" **with no `-k` argument**, running from a **user or Temp directory**, or with a **parent that is not `services.exe`** — a classic masquerade. The regex filter is what lets you pull just these rows out of a hundred-process list to inspect them.

### Step 3 — Collect a forensic artifact into an offline container (`artifacts collect`)

```bash
velociraptor artifacts collect Windows.Forensics.Prefetch --output collection.zip
```

- **`artifacts collect <ArtifactName>`** runs a **built-in artifact** — a packaged bundle of VQL — instead of a raw query. **`Windows.Forensics.Prefetch`** globs every `.pf` file under `C:\Windows\Prefetch`, **parses** each one (executable name, run count, last-run times, loaded files), and yields the results as rows.
- **`--output collection.zip`** writes those results into a self-contained **collection zip** rather than printing them. This is the **offline-collector pattern in one line**: a single command **collects + parses + packages** the evidence.

**Representative output (verbose log, trimmed):**
```
[INFO] Collecting artifact Windows.Forensics.Prefetch
[INFO] Uploaded results to container collection.zip
Collection complete. 1 artifact, results written to collection.zip
```
…and a **`collection.zip`** (~3 MB) now sits in this folder, containing a parsed **`results/Windows.Forensics.Prefetch.json`**.

**Read it.** You just performed an *acquisition*. One command reached into a live forensic artifact source (Prefetch — the execution-evidence store Module 01 analyzes with PECmd), parsed it with VQL, and packaged the structured result into a portable container you can carry off the box and analyze anywhere. On a real engagement you would swap `Windows.Forensics.Prefetch` for **`Windows.KapeFiles.Targets`** to harvest the entire KAPE triage set the same way.

### Step 4 — Inspect the collection container (`unzip -l`)

```bash
unzip -l collection.zip
```

- **`unzip -l`** lists the container's contents **without extracting** — so you can see the Velociraptor collection format before you unpack it.

**Representative output (trimmed):**
```
Archive:  collection.zip
  Length      Name
---------  ----------------------------------------
  3014221   results/Windows.Forensics.Prefetch.json
     1876   collection_context.json
     4402   log.json
---------
  3020499   3 files
```

**Read it — the Velociraptor container format.** Every collection zip has the same three-part structure:
- **`results/<Artifact>.json`** — the actual parsed evidence, one JSON file per artifact collected (here, every parsed prefetch record). This is what you feed into analysis.
- **`collection_context.json`** — the **manifest**: which artifacts ran, their parameters, the host, and timestamps. This is your chain-of-custody metadata — *what was collected, from where, when, and how.*
- **`log.json`** — the **run log** of the collection itself (every VQL step, any errors). Auditable proof of exactly what the collector did on the endpoint.

Because this is a **lab-mode, unencrypted** container, you can inspect and extract it directly. (Real-world collectors are commonly **encrypted** to a case key so evidence cannot be read if the container is lost — you decrypt with the matching key before analysis.)

---

## 5. The offline-collector workflow — the safe triage pipeline

The single most valuable pattern Velociraptor gives DFIR is the **offline collector**: a standalone, **serverless, agentless** executable that collects a predefined artifact set and drops a single container — perfect for triaging a host you cannot (or must not) connect to a server, and for the malware-analysis loop this lab is built around.

The standard, safe pipeline:

1. **Simulate / detonate in an isolated VM.** Run the sample (or reproduce the intrusion) on a throwaway, network-isolated Windows VM — never on a production or analyst host.
2. **Build a Velociraptor offline collector.** Define which artifacts to collect (e.g. `Windows.KapeFiles.Targets` + `Windows.Forensics.Prefetch` + event logs) and produce a **single packaged collector `.exe`**:
   - from the GUI: the server's **"Build Collector"** page bundles your chosen artifacts into a self-contained executable;
   - from the command line: **`velociraptor.exe collector <spec.yaml>`** builds the same packaged single-exe collector from a YAML specification.
3. **Run the collector on the detonation VM.** Double-click (or run) the packaged exe; it collects, parses, and packages everything into one **collection zip** — the same container format you inspected in Step 4.
4. **Harvest ONLY inert artifacts.** Pull the collection off the VM and extract the **safe, non-executing** evidence — **`.evtx`**, **registry hives**, **`$MFT`**, **prefetch** — never the live malware.
5. **Analyze with the EZ tools / the rest of this lab.** Feed those inert artifacts into the analyzers you already know: prefetch → **PECmd (Module 01)**, `.evtx` → **EvtxECmd (Module 05)**, hives → **RegRipper (Module 16)**, `$MFT` → **filesystem timeline (Module 15)**, and merge it all in the **super timeline (Module 18)**.

> This is exactly why Velociraptor is the **harvest tool** the other modules assume: it is the front of the pipeline (*collect*), and the EZ tools/Volatility are the back (*analyze*). Because the lab-mode container is **unencrypted**, everything the collector gathered is fully inspectable — you can prove precisely what left the box.

---

## 6. Reading the output — suspicious vs. benign

| Query / artifact | What it shows | Suspicious when… | On a clean host |
|---|---|---|---|
| `pslist()` (`Name`,`Pid`,`Ppid`,`CommandLine`) | live process tree + arguments | odd parent→child, wrong-path/misspelled system name, encoded PowerShell | normal service tree; fully-pathed binaries |
| `pslist() WHERE Name =~ 'svchost'` | every host process by name | `svchost` with **no `-k`**, from Temp/user dir, parent ≠ `services.exe` | all `svchost.exe -k <group>` from System32 |
| `Windows.Forensics.Prefetch` collection | parsed execution evidence, packaged | prefetch for a binary in Temp/AppData; a renamed system tool | expected system + app run history |
| `unzip -l collection.zip` | container structure | missing/altered `collection_context.json` (chain-of-custody) | `results/*.json` + context + log, as expected |

**The through-line:** the same triage questions the earlier modules answered *after the fact from parsed artifacts*, Velociraptor answers **live and on demand** — and then **packages the raw artifacts** so those same analyzers can run. Live hunting and offline acquisition are the same tool, the same VQL.

---

## 7. Try-it-yourself exercises

1. **Write a VQL query.** Modify Step 1 to also return the on-disk path of each process — `SELECT Name, Pid, Exe, CommandLine FROM pslist() LIMIT 15`. Which column now lets you catch a system-name masquerade that `CommandLine` alone might hide?
2. **Filter differently.** Change the Step 2 regex to hunt PowerShell instead: `WHERE Name =~ 'powershell'`. Then extend it to flag *encoded* invocations by adding `AND CommandLine =~ '-enc'`. What ATT&CK technique (see Module 09) would a hit correspond to?
3. **Collect a different artifact.** Re-run Step 3 with a different built-in — e.g. `Windows.System.Services` or `Windows.Sys.StartupItems` — into a new `--output services.zip`. Inspect it with `unzip -l` and note how the `results/` filename tracks the artifact name.
4. **Read the manifest.** Extract and open `collection_context.json` from your `collection.zip`. Identify the host, the exact artifact(s) run, and the collection timestamp — the chain-of-custody fields you would cite in a report.
5. **Sort the hunt.** Combine what you know: write one query that lists only processes whose parent is `explorer.exe` (`WHERE Ppid = <explorer's pid>`), to see everything the interactive user launched.
6. **Explore the Exchange.** Browse the Artifact Exchange and find one `Windows.Detection.*` hunt relevant to a technique from an earlier module (credential theft, lateral movement). Read its VQL and describe, in one sentence, what host state it queries.

---

## 8. Key takeaways

- **Velociraptor is the acquisition/triage front-end of DFIR** — it *collects* and *hunts live*, where the EZ tools and Volatility *parse what you already have*. It is the **harvest tool** the rest of this lab assumes.
- **VQL is SQL for endpoints:** `SELECT cols FROM plugin() WHERE cond`. The "tables" are **plugins** computed from the live machine (`pslist()`, `glob()`, `parse_evtx()`), and **`=~`** is the regex filter.
- **`pslist()` with `Name`, `Ppid`, `CommandLine`** is core triage — lineage and arguments in one row expose odd parents, wrong paths, and encoded commands.
- **Artifacts are reusable VQL bundles.** `artifacts collect <Artifact> --output x.zip` **collects + parses + packages** in one command — the offline-collector pattern. `Windows.KapeFiles.Targets` harvests the whole KAPE triage set the same way.
- **The collection container is a chain-of-custody unit:** `results/*.json` (evidence) + `collection_context.json` (manifest) + `log.json` (run log). Lab-mode containers are unencrypted and fully inspectable.
- **The safe malware pipeline:** detonate in an isolated VM → build a Velociraptor offline collector (`collector <spec.yaml>` / GUI "Build Collector") → run it → harvest **only inert** artifacts (`.evtx`/registry/`$MFT`/prefetch) → analyze with the EZ tools / this lab.
- **The same VQL scales from one host to a fleet** — a standalone collector, a live query, or a server-wide hunt are all the same language and the same binary.

---

## 9. Sources & further reading

- **Velociraptor — official documentation** (VQL reference, **Offline Collections**, **Artifact Exchange**, Building an Offline Collector): <https://docs.velociraptor.app/>
- **Velociraptor Artifact Exchange** — community hunts, parsers, and detections (all readable VQL): <https://docs.velociraptor.app/exchange/>
- **Dr. Michael Cohen — "Velociraptor: Hunting Evil"** (author talk, PDF) — VQL hunting tradecraft from the tool's creator: <https://www.velocidex.com/resources/nzitf_velociraptor.pdf>.
- **Rapid7 — Velociraptor blog** — release notes, artifact deep-dives, and IR use-cases: <https://www.rapid7.com/blog/tag/velociraptor/>
- **Eric Capuano — "Live Incident Response with Velociraptor"** — a practical end-to-end deploy-hunt-collect walkthrough.
- **Velociraptor — source (AGPL), Rapid7 / Velocidex:** <https://github.com/Velocidex/velociraptor>
- **MITRE ATT&CK** (investigative context for the hunts): **T1059.001 (PowerShell)**, **T1021.003 (DCOM lateral movement)**, **T1543.003 (Windows Service persistence)** — the behaviors the `pslist()`/`svchost`/service queries surface: <https://attack.mitre.org/>.

---
*Previous: [Module 18 — The Super Timeline](../module-18-super-timeline). This module adds the **acquisition/triage** front-end that feeds every analyzer in the lab: harvest with Velociraptor (collect live artifacts), then parse with PECmd (Module 01), EvtxECmd (Module 05), RegRipper (Module 16), and the timeline (Modules 15/18).*


---

## Sources

- **Velociraptor official docs (VQL, offline collections, Build Collector, artifacts)** — [docs.velociraptor.app](https://docs.velociraptor.app/)
- **Velociraptor source (AGPL; Velocidex/Rapid7)** — [Velocidex/velociraptor (GitHub)](https://github.com/Velocidex/velociraptor)
- **Velociraptor Artifact Exchange (community VQL hunts/parsers/detections)** — [Velociraptor Artifact Exchange](https://docs.velociraptor.app/exchange/)
- **Rapid7 stewardship, release notes, IR use-cases** — [Rapid7 blog — Velociraptor tag](https://www.rapid7.com/blog/tag/velociraptor/)
- **Practical live-IR deploy/hunt/collect walkthrough** — [Eric Capuano — Live Incident Response with Velociraptor (blog.ecapuano.com)](https://blog.ecapuano.com/)
- **PowerShell execution (encoded command lines the pslist() hunt surfaces)** — [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Windows service persistence (service/svchost masquerade context)** — [MITRE ATT&CK T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/)
