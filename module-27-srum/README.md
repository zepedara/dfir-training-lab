# Module 27 — SRUM: the System Resource Usage Monitor (`SRUDB.dat`) with SrumECmd

**Goal:** answer a question the classic execution artifacts *cannot* — ***how much did this program do, and over the network, and when, day by day for the last month?*** Windows silently keeps ~30–60 days of **per-application resource accounting** in the **System Resource Usage Monitor** database, `C:\Windows\System32\sru\SRUDB.dat`: bytes sent and received per app per network, CPU/energy used, and which user ran it. You'll parse it with **SrumECmd** (Eric Zimmerman), turn one opaque ESE database into a stack of readable CSVs, and learn why SRUM is one of the most valuable — and most *anti-forensics-resilient* — artifacts on a modern Windows box.

> **Evidence note.** The `SRUDB.dat` in `data/` is **real SRUM telemetry generated on this lab VM's own routine operation** — booting, the built-in Windows services, our own tooling. It is **benign OS bookkeeping**: no PII, no credentials, no malware, no browsing of anything sensitive. It was acquired the correct forensic way — from a **Volume Shadow Copy**, because the live file is locked (see §3). We never alter evidence, so SrumECmd's output shows the database's real baked-in values.

---

## 1. Background — why this matters

### What SRUM is, and why it exists
The **System Resource Usage Monitor (SRUM)** arrived in **Windows 8** and is on every Windows 8/10/11 desktop since. Its day job is mundane: it powers the Settings pages that show "which apps used the most data / battery." To do that, a service samples, **roughly once an hour** (and at shutdown), how much each running application consumed — and writes it to a database. That housekeeping side-effect is a goldmine for a forensic investigator, because it means Windows is keeping a **rolling ~30-to-60-day ledger of program activity that nobody thinks to clean up.**

### What it actually records — and why it beats the "did it run?" artifacts
Prefetch, ShimCache, and Amcache (modules 01/02/03) answer *did this binary execute?* SRUM answers a **richer** question: *this executable, run by **this SID**, on **this day**, **sent 4.2 GB and received 180 MB** over **this network**, and burned this much CPU.* Concretely, SRUM keeps several tables, each fed by a provider:

- **Application Resource Usage** — per-app CPU cycles, foreground/background bytes read/written to disk, context switches. *The "what ran and how hard" ledger.*
- **Network Data Usage** — **bytes sent and bytes received, per application, per network interface, per hour.** *This is the crown jewel: a per-process data-transfer history.*
- **Network Connectivity Usage** — when an app was connected, to which interface, and for how long.
- **Energy Usage** — battery/charge accounting per app.
- **App Timeline / Push Notifications / vfuprov** — Windows-10 activity-timeline and notification bookkeeping.

### Three properties that make SRUM special for DFIR
1. **It survives the binary.** SRUM records the app's **path and its activity even after the executable is deleted from disk.** An attacker who drops a tool, exfiltrates, and wipes the binary still leaves a SRUM row showing *"this path sent 12 GB last Tuesday."* That ties SRUM directly to the anti-forensics track (modules 23–26): it is evidence that outlives the classic artifacts.
2. **It quantifies exfiltration.** Because Network Data Usage is **bytes-per-app**, it is often the single best host-side estimate of *how much data left the machine* and *through which program* — the question every data-breach investigation asks. No packet capture required; the OS counted it for you.
3. **It is retrospective.** One `SRUDB.dat` is a **month of history**, not a point-in-time snapshot. You can bracket an intrusion window and read what each app did each day across it.

### The one gotcha that catches everyone: the write cadence
SRUM does **not** write to `SRUDB.dat` in real time. A service (the **Diagnostic Policy Service**) buffers the current hour's counters — partly in memory, partly under the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions` — and **flushes to the database about once an hour and at clean shutdown.** Two consequences you must internalise:
- **The most recent ~hour of activity may not be in `SRUDB.dat` yet** — it can still be in the registry cache. On a live response, collect that key too.
- Because the flush is periodic, SRUM timestamps are **hourly buckets**, not to-the-second. Treat a SRUM time as "within this hour," and corroborate precise timing with EVTX/Prefetch.

---

## 2. What the tool does — SrumECmd

**SrumECmd** (Eric Zimmerman) reads the raw `SRUDB.dat` **ESE (Extensible Storage Engine / "JET Blue") database** offline and writes one tidy **CSV per provider table**. ESE is the same engine behind `NTUSER`-style stores and Exchange; you don't parse it by hand — SrumECmd walks the tables, decodes the timestamps and the interface/user maps, and emits columns you can open in Timeline Explorer or grep.

Two things it does that matter:
1. **Resolves the ID maps.** SRUM stores apps and users as integer IDs in an internal `SruDbIdMapTable`, and network interfaces as numeric LUIDs. Given the machine's **`SOFTWARE` registry hive** (the `-r` option), SrumECmd resolves those to friendly application strings and network profile/SSID names. **This is why you always acquire `SRUDB.dat` *and* the `SOFTWARE` hive together** — one without the other is half-blind. (This module ships only the database, so we run without `-r` and read the raw IDs; §5 shows exactly what `-r` would add.)
2. **Recovers a dirty database.** A `SRUDB.dat` pulled from a running system (or a shadow copy) is often in a "dirty" ESE state. SrumECmd performs the recovery to read it, so you don't need the matching `.log`/checkpoint files.

> **Plain-language summary:** SrumECmd turns Windows' hidden month-long "which app used how much CPU/network/battery" ledger into readable spreadsheets — one per category — so you can see what each program did, and how much data it moved, day by day.

---

## 3. Acquiring SRUM — why you can't just copy the file

`SRUDB.dat` is **held open (locked) by the Diagnostic Policy Service** on a live system, so a plain `copy` fails with a sharing violation. This is not an obstacle so much as a lesson in evidence acquisition, and it's how the evidence in this module was actually obtained:

- **Volume Shadow Copy (used here).** Create a shadow copy of the volume, then copy `SRUDB.dat` — and the `SOFTWARE` hive — out of the frozen snapshot, where nothing holds a lock. This is the cleanest live-acquisition method and needs administrator rights. (Triage tools like **KAPE** and **Velociraptor**, module 20, automate exactly this — a "SRUM" target uses VSS or raw-NTFS reads under the hood.)
- **Raw-NTFS / forensic image.** From a disk image or a raw-device reader you copy the file directly out of the file system, bypassing the lock entirely.
- **Always grab the pair.** Whatever the method, collect **`C:\Windows\System32\sru\SRUDB.dat` *and* `C:\Windows\System32\config\SOFTWARE` together** — you need the hive to resolve the app/network IDs (§2).

> **Anti-forensics angle.** An attacker who scrubs Prefetch, clears `$MFT`/`$UsnJrnl`, and deletes their tooling usually **never touches SRUM** — it's obscure, service-locked, and not in the usual "clear your tracks" playbooks. So on a host you *know* was busy but that looks suspiciously clean, SRUM is where the activity — and the exfil byte counts — often still lives. Pair this with modules 23–26.

---

## 4. Setup

The lab ships the database **gzip-compressed** (`data/SRUDB.dat.gz`, ~1 MB) to keep the repo small. Decompress it, then confirm the real ~7 MB ESE database is in place. SrumECmd is installed natively on the lab VM and already on your `PATH` as `SrumECmd.exe` — no container, no Docker — and the VM is kept **offline** so evidence never phones home.

```bash
cd module-27-srum/data
gzip -dkf SRUDB.dat.gz
ls -la SRUDB.dat
```

- **`gzip -dkf`** — **d**ecompress, **k**eep the original `.gz`, **f**orce-overwrite so the step is safe to re-run. You should see `SRUDB.dat` at ~7 MB.

---

## 5. Step-by-step walkthrough

### Step 1 — Parse the whole database
One command turns the ESE database into a CSV per provider table, written to the current folder:

```bash
SrumECmd.exe -f SRUDB.dat --csv .
```

**Read it:** SrumECmd prints its version, `Processing 'SRUDB.dat'...`, and `Processing complete!` with a sub-second runtime. You will also see a single benign line:

```
Error processing Push Notification info (...): No such table or object
```

That is **expected and harmless** — this Windows build simply doesn't populate the Push-Notification table, so SrumECmd notes it and moves on. Every other table is written normally, and the tool exits successfully. **A "no such table" for one optional provider is not a failure** — it's SRUM telling you that provider had nothing to give on this host.

### Step 2 — See what came out
```bash
ls -1 *_Output.csv
wc -l *_Output.csv
```

**Read it:** you get one `*_SrumECmd_<Provider>_Output.csv` per table. On this evidence the real counts are:

| CSV (provider) | Data rows | What it answers |
|---|---|---|
| `AppResourceUseInfo` | **3,570** | which apps ran and how hard (CPU, disk bytes) |
| `AppTimelineProvider` | **8,132** | Windows-10 activity timeline of app usage |
| `NetworkUsages` | **865** | **bytes sent/received per app per interface** ← the crown jewel |
| `NetworkConnections` | **62** | when/where each app was connected |
| `EnergyUsage` | **115** | per-app battery/charge accounting |
| `vfuprov` | **11** | app-timeline provider bookkeeping |
| `PushNotifications` | **0** | (empty on this build — see Step 1) |

*(Your exact counts depend on the database; the point is the **shape** — several categories, each a different lens on the same activity. Pre-parsed copies of all seven are in `../reference-output/` if you'd rather read than run.)*

### Step 3 — The crown jewel: per-application network bytes
The Network Data Usage table is what makes SRUM famous. Look at its columns first, then read it in a spreadsheet/Timeline Explorer:

```bash
head -1 *NetworkUsages_Output.csv | tr ',' '\n' | cat -n
```

**Read it:** note the columns **`AppId`**, **`BytesSent`**, **`BytesReceived`**, **`InterfaceLuid`**, and **`Timestamp`**. Each row is *"this app, on this interface, in this hourly bucket, moved this many bytes."* In a real case you **sort `BytesSent` descending** and ask: *is the top talker something that should be sending gigabytes?* A backup agent, yes; `rundll32.exe` or a random binary in `\Users\Public`, absolutely not — that's your exfiltration lead, quantified.

### Step 4 — Which apps ran, and as whom
```bash
head -1 *AppResourceUseInfo_Output.csv | tr ',' '\n' | cat -n
```

**Read it:** the **`ExeInfo`** column is the executable path SRUM recorded, and **`Sid`/`UserName`** attribute it to an account. This is the "execution + attribution" ledger — and remember, **`ExeInfo` persists even if that executable was later deleted from disk.** Cross-reference a suspicious `ExeInfo` here against Prefetch (01) and Amcache (03): SRUM adds *how much it did and for how long*, which the others cannot.

### Step 5 — What `-r` (the `SOFTWARE` hive) would add
This module ships only the database, so the runs above show **raw IDs** for some fields. In a real investigation you pass the machine's `SOFTWARE` hive to resolve them:

```
SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv .
```

With `-r`, SrumECmd resolves the internal app/user IDs to **friendly application names** and the numeric **`InterfaceLuid`** to the actual **network profile / SSID** — turning "interface 0x…07" into "*Corp-WiFi*" or "*Ethernet 2*." That interface-to-SSID resolution is often decisive: it tells you *which network* the exfil left over (the guest Wi-Fi? the VPN?). It's the single best reason to **always collect `SRUDB.dat` and `SOFTWARE` as a pair** (§3). *(We don't run this in-lab because correct resolution requires **this machine's own** `SOFTWARE` hive — another host's hive would mis-resolve the IDs — and shipping an 85 MB hive isn't worth it for the teaching point.)*

---

## 6. What you proved

- Windows keeps a **~30–60-day, per-application ledger** of CPU, disk, **network bytes**, and energy in `SRUDB.dat`, flushed hourly by the Diagnostic Policy Service.
- SRUM **quantifies** activity (bytes sent/received per app) and **attributes** it to a SID — and it **survives deletion of the executable**, making it anti-forensics-resilient and a prime exfiltration-sizing source.
- The database is **service-locked live**, so you acquire it (and the `SOFTWARE` hive) via **VSS / triage tooling / a forensic image** — never a naïve copy.
- **SrumECmd** parses the ESE database offline into one CSV per provider; `-r <SOFTWARE>` resolves app and **network-interface/SSID** names.

---

## References & further reading

- **SrumECmd (Eric Zimmerman)** — parser used here: <https://github.com/EricZimmerman/Srum> and the EZ Tools suite <https://ericzimmerman.github.io/>
- **SRUM forensics primer** — Microsoft's System Resource Usage Monitor internals and tables: <https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/>
- **SRUM structure / the SRUM-DUMP project** (Mark Baggett, SANS) — provider GUIDs and the SOFTWARE-hive ID map: <https://github.com/MarkBaggett/srum-dump>
- **KAPE / Velociraptor SRUM acquisition** (module 20) — VSS-based collection of `SRUDB.dat` + `SOFTWARE`.
- **MITRE ATT&CK** (investigative context): **T1041 — Exfiltration Over C2 Channel** and **T1030 — Data Transfer Size Limits** (SRUM's byte counts help size and spot both): <https://attack.mitre.org/>
