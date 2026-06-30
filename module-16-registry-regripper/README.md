# Module 16 — Registry Forensics with RegRipper

**Deck mapping:** *Intrusion Hunting Playbook* → "Evidence of Execution, Persistence & User Activity" / host-triage foundations.
**Goal:** learn to pull court-ready evidence — **persistence, program execution, user activity, accounts, and network/device history** — out of the **Windows Registry** using **RegRipper**, the plugin-driven hive parser. You will triage two machines from the same real intrusion and watch the registry give up the attacker's foothold from several angles at once.

---

## 1. Background — why this matters

### What the Windows Registry actually is
The **registry** is Windows' central configuration database. It is *not* one file — it is several on-disk **hive files** that Windows loads and stitches together into the tree you see in `regedit`. Each hive is a little binary database of:

- **keys** — folders (e.g. `…\CurrentVersion\Run`);
- **values** — a name + a type + data (e.g. `coreupdate = powershell …`);
- a **LastWrite timestamp on every key** — the last time that key was modified. This is one of the most important facts in registry forensics: a key's LastWrite often *is* the timestamp of the event you care about (when a service was installed, when a USB stick was plugged in, when a program was first run).

For an investigator the registry is a goldmine because Windows uses it to remember **what ran, what auto-starts, who logged on, what files a user opened, and what devices/networks the machine has seen** — most of which never appears in an event log.

### The hive files and what each one holds
You collect hives as **files** (from a triage tool, a `reg save`, a VSS snapshot, or carved out of a disk image with The Sleuth Kit — exactly how Module 15 carved the `$MFT`). The important ones:

| Hive (file on disk) | Where it lives | What an investigator gets from it |
|---|---|---|
| **SYSTEM** | `C:\Windows\System32\config\SYSTEM` | computer name, time zone, **services & drivers** (persistence!), **ShimCache**, USB device history, mounted devices, last shutdown. |
| **SOFTWARE** | `…\config\SOFTWARE` | installed programs, **Run/RunOnce autostart** (persistence!), OS build/install date, network profiles, last-logged-on user. |
| **SAM** | `…\config\SAM` | **local** user accounts, RIDs, group membership, login counts. |
| **SECURITY** | `…\config\SECURITY` | LSA secrets, audit policy. |
| **NTUSER.DAT** | `C:\Users\<name>\NTUSER.DAT` | **per-user** activity: **UserAssist** (GUI program execution + run counts), RecentDocs, RunMRU, TypedPaths, per-user Run keys. |
| **UsrClass.dat** | `…\AppData\Local\Microsoft\Windows\UsrClass.dat` | **per-user Shellbags** — every folder the user browsed in Explorer, including external/USB/deleted ones. |

There is **one `NTUSER.DAT` and one `UsrClass.dat` per user profile**, so on a multi-user box you triage each user's pair separately.

> **The catch (same as `.evtx` in Module 5):** hive files are **binary**. `cat SYSTEM` gives you garbage. And even with a hex viewer the data is encoded — UserAssist program names are **ROT13-scrambled**, timestamps are 64-bit **FILETIME** blobs, MRU lists store a separate ordering array. You need a parser that knows where each artifact lives and how to decode it. **That parser is RegRipper.**

### What an investigator proves with the registry
- **Persistence** — "how did the malware survive a reboot?" → Run keys (SOFTWARE/NTUSER), **Services** (SYSTEM).
- **Execution** — "did this program actually run, and who ran it?" → **UserAssist** (per user), ShimCache/Amcache (Modules 2-3).
- **User activity** — "what did the user open / type / browse?" → RecentDocs, RunMRU, **Shellbags**.
- **Accounts** — "what local users and admins exist?" → SAM.
- **Device & network history** — "was a USB stick plugged in? what network did it join?" → USBSTOR, MountedDevices, NetworkList.

---

## 2. What the tool does — RegRipper

**RegRipper** (by **Harlan Carvey**) is a free, open-source, **plugin-driven** registry parser. You point it at one hive file and tell it which **plugin** to run; the plugin knows the exact key path(s) for one artifact, decodes the values, and prints a clean report. It does three things that matter:

1. **Reads the raw hive offline** using the Perl `Parse::Win32Registry` library — no Windows, no mounting, **read-only and forensically sound**. It runs fine on the lab VM against an extracted hive.
2. **One plugin = one artifact.** `services` lists services, `userassist` decodes UserAssist, `usbstor` lists USB drives, `shellbags` rebuilds folder-browsing history. There are **~260 plugins** in this build; you don't have to remember a single key path.
3. **Decodes the ugly parts for you** — ROT13 UserAssist names, FILETIME timestamps, MRU ordering blobs — and prints each key's **LastWrite time** next to the data.

You can run a single plugin (`-p`), or a whole **profile** (`-f system`, `-f software`, `-f ntuser` …) that bundles every plugin for that hive type into one sweep.

> **Plain-language summary:** RegRipper turns an unreadable binary hive into a readable report, one artifact at a time, without you memorising hundreds of registry paths.

---

## 3. The scenario in this module's data

This module triages **two machines from the same real intrusion** — the public **DFIR-Madness "Stolen Szechuan Sauce" (Case 001)** dataset (see `data/README.md` for provenance and license). It is the same case the rest of the lab is built on: the malware is **`coreupdater.exe`**, the desktop is **`DESKTOP-SDN1RPT`** (regular user `mortysmith`), and here we add the **domain controller, `CITADEL-DC01`**.

The attacker got in over RDP, landed on the **server (`CITADEL-DC01`)** as the domain **Administrator**, planted `coreupdater` for persistence **two different ways**, and the same Administrator account ran `coreupdater.exe` on the **desktop**. The registry recorded all of it.

| Hive in `data/` | Host it came from | What it proves in this module |
|---|---|---|
| `SYSTEM` (+ `.LOG1/.LOG2`) | **CITADEL-DC01** (server) | computer name, time zone, **`coreupdater` installed as an auto-start service**, USB/mounted devices. |
| `SAM` | **CITADEL-DC01** | local accounts (Administrator, Guest) and group membership. |
| *(SOFTWARE — fetched via `data/get-data.sh`)* | **CITADEL-DC01** | **fileless `coreupdate` Run-key persistence**, installed apps, the `C137.local` domain, last-logged-on user. |
| `NTUSER.DAT` (+ logs) | **DESKTOP-SDN1RPT** \ `mortysmith` | a normal user's RecentDocs / UserAssist — the **benign baseline**. |
| `UsrClass.dat` (+ logs) | **DESKTOP-SDN1RPT** \ `mortysmith` | Shellbags (folder-browsing history). |
| `Administrator_NTUSER.DAT` (+ logs) | **DESKTOP-SDN1RPT** \ `Administrator` | **UserAssist proof the attacker ran `coreupdater.exe`** — execution evidence ShimCache *missed* (Module 2). |

> **Why two hosts?** Real intrusions span machines, and so does real triage. The machine-wide evidence (services, accounts, network) lives in the server's `SYSTEM`/`SOFTWARE`/`SAM`; the human-activity evidence (what a user ran, opened, browsed) lives in each user's `NTUSER.DAT`/`UsrClass.dat`. Together they tell one story. Every step below labels which host and hive it uses.

---

## 4. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-16-registry-regripper/data
```
- **Every command below is run from inside `data/`**, so hives are named with simple relative paths (`SYSTEM`, `NTUSER.DAT`, …).
- RegRipper is installed **natively on the lab VM and already on your `PATH`** as **`rip`** — you call it directly, no container, no Docker. The VM is kept **offline** so evidence never phones home.
- The large **`SOFTWARE`** hive (44 MB) is **not shipped** in the repo. Run `bash get-data.sh` to fetch it for the Step 7–9 SOFTWARE commands, **or** just read the captured results in `../reference-output/` — every command in this module has its real output saved there.

A quick sanity check (lists every installed plugin with a one-line description):
```bash
rip -l | head
```
- **`-l`** — **l**ist all plugins. Add **`-c`** (`rip -l -c`) to get the list as CSV (`name,version,hive,description`) you can grep. This is how you discover the exact plugin name for an artifact in *this* build (RegRipper 3.0).

---

## 5. Step-by-step walkthrough

Each step is one `rip` command. The anatomy is always the same:

```
rip -r <hive file> -p <plugin>
```
- **`-r <hive>`** — the **r**egistry hive file to read (**required**).
- **`-p <plugin>`** — run one **p**lugin. (Swap for **`-f <profile>`** to run *every* plugin for a hive type at once, e.g. `rip -r SYSTEM -f system > SYSTEM_report.txt`.)
- RegRipper writes its report to **standard output**, so add `> file.txt` to save it, or pipe into `grep`/`less`.

> **Note on the `.LOG` files.** Each hive ships with its transaction logs (`SYSTEM.LOG1`, `UsrClass.dat.LOG1`, …) — the not-yet-flushed most-recent changes. **RegRipper 3.0 does *not* replay them automatically** (it only warns if a hive is "dirty"). For this case the base hives already contain the evidence; when last-second precision matters, replay logs first with Eric Zimmerman's `rla.exe` or `yarp`/`registryFlush.py`, then re-run RegRipper. We collect the logs regardless, because you always collect them with the hive.

### Step 1 — Identify the machine: computer name (SYSTEM)
```bash
rip -r SYSTEM -p compname
```
**Output:**
```
ComputerName    = CITADEL-DC01
TCP/IP Hostname = CITADEL-DC01
```
**Read it:** always pin down *which host* a hive came from before you trust anything else in it. This `SYSTEM` hive is the **server `CITADEL-DC01`**, the domain controller — not the desktop. (`compname` reads `…\ControlSet001\Control\ComputerName\ComputerName`.)

### Step 2 — Anchor your clock: the time zone (SYSTEM)
```bash
rip -r SYSTEM -p timezone
```
**Output:**
```
TimeZoneInformation key
ControlSet001\Control\TimeZoneInformation
LastWrite Time 2020-09-17 17:56:13Z
  Bias            -> 480 (8 hours)
  TimeZoneKeyName -> Pacific Standard Time
```
**Read it:** the host ran in **Pacific Standard Time** (`Bias 480` = UTC-8). This matters constantly: some artifacts log local time and some log UTC, so you cannot build a correct timeline until you know the machine's offset. (Everything RegRipper prints with a `Z` is already UTC.)

### Step 3 — Find persistence #1: a malicious service (SYSTEM)
This is the headline. The `services` plugin lists every service/driver **sorted by key LastWrite time**, so the most recently installed — i.e. the attacker's — float to the top:
```bash
rip -r SYSTEM -p services
```
**Output (top entries, trimmed):**
```
Sat Sep 19 03:27:49 2020 Z
  Name      = coreupdater
  Display   =
  ImagePath = C:\Windows\System32\coreupdater.exe
  Type      = Own_Process
  Start     = Auto Start
  Group     =

Sat Sep 19 03:21:47 2020 Z
  Name      = terminpt
  ImagePath = \SystemRoot\System32\drivers\terminpt.sys   (Microsoft Remote Desktop Input Driver)
```
**Read it:** a service literally named **`coreupdater`** runs **`C:\Windows\System32\coreupdater.exe`** with **`Start = Auto Start`** — so it relaunches on every boot. That is textbook **persistence (MITRE T1543.003 — Create or Modify System Service)**. Three tells make it obvious: (1) an **empty Display name** (real Windows services have one), (2) an executable sitting loose in `System32` with a generic "update-y" name, (3) the **install time (03:27:49)** sits right inside the intrusion window. Notice the entry just below it: the **`terminpt`** *Remote Desktop Input Driver* was touched minutes earlier (03:21:47) — Windows loads it when someone uses an **RDP** session, corroborating how the attacker was driving the box.

> **Timezone note (for cross-referencing public write-ups).** RegRipper prints these LastWrite times in **UTC** (the trailing `Z`), so this hive puts the service install at **`03:27:49Z`**. Several public Case-001 write-ups list it as **`02:27:49`** — a **~1-hour offset** that traces to a known timezone/DST quirk in how the original Case-001 artifacts were recorded. We report the value **faithfully as it sits in the raw hive** (`03:27:49Z`); just be aware of the one-hour shift when you line our timeline up against external Case-001 references.

### Step 4 — Was a USB drive ever attached? (SYSTEM)
```bash
rip -r SYSTEM -p usbstor
```
**Output:**
```
ControlSet001\Enum\USBStor not found.
```
**Read it — a negative result is still evidence.** `USBStor` is where Windows records every **USB mass-storage** device ever connected. On this server it is **empty/absent**: no USB thumb-drive or external disk was ever plugged in. That lets you **rule out USB as the exfiltration path on this host** — a real and useful investigative conclusion, not a dead end. (On a workstation that *had* USB history you'd see vendor/product, serial number, and first/last-connected times here — the bread-and-butter of a data-theft case.)

To see what *was* on the USB bus, use the broader `usb` plugin:
```bash
rip -r SYSTEM -p usb
```
It lists the virtual hubs and a `VID_0E0F&PID_0003` device — the **VMware virtual USB pointing device**, i.e. this is a VM, consistent with the lab dataset. No removable storage among them.

### Step 5 — Mounted volumes and last shutdown (SYSTEM)
```bash
rip -r SYSTEM -p mountdev
rip -r SYSTEM -p shutdown
```
`mountdev` shows the drive letters and volume GUIDs the machine knew (here `C:` and a `D:` VMware **SATA CD-ROM**). `shutdown` reads the last clean shutdown time:
```
ShutdownTime  : 2020-09-18 23:10:53Z
```
**Read it:** these bracket your timeline — the box was last cleanly shut down on 2020-09-18, and the malicious service appeared the next morning (Step 3). Mounted-device GUIDs also let you tie a drive letter back to a specific volume when correlating with Shellbags or LNK files.

### Step 6 — Local accounts and admins (SAM)
```bash
rip -r SAM -p samparse
```
**Output (trimmed):**
```
Username        : Administrator [500]
  Account Created : Thu Sep 17 17:57:10 2020 Z
  Login Count     : 0
Username        : Guest [501]   --> Account Disabled

Group : Administrators [2]
  S-1-5-21-2620694702-3641965580-775306395-500   (built-in Administrator)
  S-1-5-21-2232410529-1445159330-2725690660-512   (a domain group)
```
**Read it:** `samparse` enumerates the **local** accounts and group membership. The RID **`500`** is always the built-in Administrator. On a domain controller the interesting admin activity is usually a **domain** account (we confirm that in Exercise 2), but you always check SAM first to catch attacker-created **local** accounts or backdoor admins — there are none new here, so the attacker used the existing Administrator, not a freshly minted local user.

### Step 7 — Persistence #2: a fileless Run key (SOFTWARE)
> Steps 7-9 read the **`SOFTWARE`** hive. If you haven't fetched it, run `bash get-data.sh` first, or read `../reference-output/09-software-run.txt`.

```bash
rip -r SOFTWARE -p run
```
**Output (the machine-wide Run key, trimmed):**
```
Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2020-09-19 03:30:01Z
  VMware VM3DService Process - "C:\Windows\system32\vm3dservice.exe" -u
  coreupdate - %COMSPEC% /b /c start /b /min powershell -nop -w hidden -c
       "iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(
        (Get-Item 'HKLM:Software\9sEoCawv').GetValue('45SVAG2o'))))"
  VMware User Process - "...\vmtoolsd.exe" -n vmusr
```
**Read it — this is the same attacker, a different persistence trick.** The value **`coreupdate`** auto-starts a **hidden PowerShell** (`-w hidden`, `-nop`) that:
1. reads a **base64 blob stored in another registry value** — `HKLM:\Software\9sEoCawv\45SVAG2o` (the random key/value names are deliberate camouflage),
2. base64-decodes it and **`iex`**-executes it (Invoke-Expression runs it in memory).

This is **fileless / registry-resident persistence (T1547.001 — Registry Run Key, plus T1059.001 — PowerShell)**: the actual payload never sits on disk as a file, it lives *inside the registry*, so a file-scanning AV walks right past it. Two independent footholds — the **service** (Step 3) and this **Run key** — is classic "belt and suspenders" attacker tradecraft so that killing one doesn't evict them.

### Step 8 — Installed programs (SOFTWARE)
```bash
rip -r SOFTWARE -p uninstall
```
Lists everything in the `Uninstall` keys (what Add/Remove Programs shows), each with the key's LastWrite time:
```
2020-09-17 17:56:12Z
  VMware Tools v.11.0.6.15940789
  Microsoft Visual C++ 2019 X64 ...
```
**Read it:** nothing malicious *installed itself* the polite way here (the attacker didn't run an MSI), but `uninstall` is where you'd catch attacker tooling that did — and the LastWrite times give you a rough software-install timeline.

### Step 9 — Network identity (SOFTWARE)
```bash
rip -r SOFTWARE -p networklist
```
**Output (trimmed):**
```
C137.local
  DateLastConnected: 2020-09-17 22:10:45
  DateCreated      : 2020-09-17 17:43:29
  DefaultGatewayMac: 00-0C-29-95-CD-21
  Type             : wired
```
**Read it:** the machine was joined to the **`C137.local`** network/domain, with the gateway's **MAC address** recorded (`00-0C-29-95-CD-21` — a VMware OUI). `networklist` is gold for placing a laptop on a specific Wi-Fi/SSID or a server in a specific subnet, with first- and last-seen dates.

### Step 10 — A normal user's activity: the benign baseline (NTUSER.DAT)
Now switch to the **desktop's** regular user, `mortysmith`. The `recentdocs` plugin reads the files this user recently opened, **in most-recently-used order**:
```bash
rip -r NTUSER.DAT -p recentdocs
```
**Output (trimmed):**
```
RecentDocs   LastWrite Time: 2020-09-18 23:07:44Z
  5 = Portal_gun.png
  4 = Pictures
  3 = Jessica.jpg
  2 = My Social Security Number.txt
  1 = Plans.txt
  0 = Thoughts.txt
```
**Read it:** this is an ordinary person opening personal files — pictures and text notes. There is nothing malicious here, and **that's the point**: this is your **baseline** for what *normal* user activity looks like, so the abnormal activity in Step 12 stands out. (`recentdocs` lives in `NTUSER.DAT`, so it is **per user** — `mortysmith`'s opened files, no one else's.)

Confirm the baseline two more ways:
```bash
rip -r NTUSER.DAT -p userassist     # GUI programs mortysmith ran: notepad, calc, mspaint, Snipping Tool
rip -r NTUSER.DAT -p run            # mortysmith's per-user autostart: just OneDrive (benign)
```
`userassist` shows only built-in Windows apps with small run counts, and the per-user `run` key holds only OneDrive — a clean profile.

### Step 11 — Folder-browsing history: Shellbags (UsrClass.dat)
```bash
rip -r UsrClass.dat -p shellbags
```
**Output (trimmed):**
```
MRU Time             | Resource
2020-09-18 23:07:39  | My Computer\{d3162b92-...} [Desktop\1\0\]
                     | My Games [Desktop\0\]
```
**Read it:** **Shellbags** record every folder a user *browsed in Explorer* — and they persist **even after the folder (or the USB stick, or the network share) is gone**, which is what makes them so valuable. They live in **`UsrClass.dat`**, not `NTUSER.DAT`. `mortysmith`'s bags are sparse (a lightly-used profile), but on a real exfil case this is where you'd see the attacker having browsed `E:\` or `\\server\share` — proof a location was opened by a human even if nothing else remains.

### Step 12 — The smoking gun: the attacker's UserAssist (Administrator NTUSER.DAT)
Finally, the **Administrator** profile on the desktop — the account the attacker used. `UserAssist` records **GUI program execution with a run count and last-run time**, per user, and the plugin **un-ROT13s** the names for you:
```bash
rip -r Administrator_NTUSER.DAT -p userassist
```
**Output (trimmed, most recent first):**
```
2020-09-19 03:41:06Z
  {1AC14E77-...}\cmd.exe (1)
2020-09-19 03:40:49Z
  {1AC14E77-...}\coreupdater.exe (1)
2020-09-19 03:39:02Z
  Microsoft.MicrosoftEdge ... (1)
```
**Read it — this is direct proof of execution.** The Administrator account **ran `coreupdater.exe` once, at 2020-09-19 03:40:49 UTC**, then opened `cmd.exe` seconds later. UserAssist only records things a **human launched through the GUI**, so this isn't a background service — *a person ran the malware*. The number in parentheses is the **run count**.

**Why this step matters for the whole course:** Module 2 showed `coreupdater.exe` was **missing from this same host's ShimCache** — a deliberate gap. Here the registry catches it anyway, from a *different* artifact in a *different* hive. That is the core lesson of execution forensics: **no single artifact is complete, so you corroborate across the "execution triad"** — ShimCache (Module 2), Amcache (Module 3), and UserAssist (this module).

---

## 6. Reading the output — suspicious vs. benign

| Artifact (plugin) | What it tells you | Suspicious when… |
|---|---|---|
| `services` | every service + install (LastWrite) time | a service with **empty Display name**, a binary loose in `System32`, generic "update" name, installed *during the incident window*, `Start = Auto Start`. |
| `run` (Run key) | machine/user autostart commands | a value launching **hidden PowerShell**, `iex`, base64, or reading a payload from **another registry value** (fileless). |
| `userassist` | per-user GUI execution + count + time | a **non-standard binary** (`coreupdater.exe`) run by an admin/service account, or anything run from `Temp`/`Downloads`. |
| `usbstor` | USB mass-storage history | a removable drive connected around the time data went missing (here it's **empty** → rules USB out). |
| `samparse` | local accounts & admins | a **new local account**, or an unexpected member of `Administrators`. |
| `recentdocs` / `shellbags` | files opened / folders browsed | a user (or attacker) opening exfil staging folders, external drives, or sensitive files they shouldn't. |

**Triaging false positives:** one auto-start entry or one service is not automatically evil — Windows is full of legitimate ones (VMware Tools, OneDrive above). What convicts here is the **cluster**: a service *and* a fileless Run key both tied to `coreupdater`, installed inside the incident window, plus an admin **interactively running `coreupdater.exe`** on a second host. Judge the *combination and the timing*, and always keep a **benign baseline** (Steps 10-11) to compare against.

---

## 7. Investigative narrative — the story the evidence tells

Stitching the registry artifacts into time order across both machines:

1. **2020-09-17/18 — normal life.** `mortysmith` uses the desktop ordinarily: opens notes and pictures (RecentDocs), runs notepad/paint (UserAssist). This is the baseline. The server `CITADEL-DC01` sits on the `C137.local` network (NetworkList).
2. **2020-09-19 ~03:21 — the attacker is on the server over RDP.** The **`terminpt` Remote Desktop Input Driver** is loaded (SYSTEM/services), and the **domain Administrator** is the active account (lastloggedon / profilelist — Exercise 2).
3. **~03:27 — persistence #1 on the server.** `coreupdater` is installed as an **auto-start service** pointing at `C:\Windows\System32\coreupdater.exe` (SYSTEM/services).
4. **~03:30 — persistence #2 on the server.** A **`coreupdate` Run key** is added that fires **hidden PowerShell** to `iex` a **base64 payload hidden inside another registry value** — fileless, on-disk-scanner-proof (SOFTWARE/run).
5. **~03:40 — execution on the desktop.** The **Administrator** account **runs `coreupdater.exe` by hand** (Administrator UserAssist), then opens `cmd.exe`. ShimCache on that host *missed* this — UserAssist did not.

One account, one malware family, **two persistence mechanisms and a confirmed hands-on-keyboard execution**, reconstructed entirely from registry hives — no event logs required. RegRipper gave you the ground truth from six hives across two machines. In the capstone you'll merge this with the EVTX, Prefetch, and timeline evidence into a single account of the intrusion.

---

## 8. Try-it-yourself exercises

1. **Whole-hive sweep.** Instead of one plugin, run the full profile: `rip -r SYSTEM -f system > SYSTEM_full.txt`. Open it and find *three* artifacts this walkthrough didn't call out. Which would you add to the timeline?
2. **Confirm the last-logged-on user.** Fetch `SOFTWARE` (`bash get-data.sh`) and run `rip -r SOFTWARE -p lastloggedon` and `rip -r SOFTWARE -p profilelist`. Which account was last at the console, and what is its SID? Tie that SID back to the Administrator who ran `coreupdater.exe` in Step 12.
3. **Decode the fileless payload's home.** In Step 7 the Run key reads `HKLM:\Software\9sEoCawv\45SVAG2o`. Explain in two sentences *why* storing the payload in the registry (instead of a `.ps1` file) defeats a file-based antivirus scan — and which artifact from Module 5 (event logs) would still catch the PowerShell when it runs.
4. **Baseline vs. attacker.** Diff `mortysmith`'s UserAssist against the `Administrator` UserAssist. List every program *only* the Administrator ran. Why is "an account that normally does nothing suddenly running `cmd.exe` and `coreupdater.exe`" a stronger signal than either fact alone?
5. **Plugin discovery.** Run `rip -l -c > plugins.csv`, open it, and find the plugin that would answer "what did this user *type* into the Run dialog (Win+R)?" Run it against `NTUSER.DAT` — is it populated here, and what does an empty result tell you?

---

## 9. Key takeaways

- Registry **hives are binary** and partly encoded; RegRipper parses them **offline, read-only**, one **plugin per artifact**, decoding ROT13/FILETIME/MRU for you and printing each key's **LastWrite time**.
- Know your hives: **SYSTEM** (services, USB, time zone), **SOFTWARE** (Run keys, installed apps, network, last logon), **SAM** (local accounts), **NTUSER.DAT** (per-user execution/activity), **UsrClass.dat** (Shellbags).
- Command anatomy: **`rip -r <hive> -p <plugin>`**; `-f <profile>` for a whole-hive sweep; `-l` / `-l -c` to discover plugin names.
- The registry exposes **persistence** (services + Run keys), **execution** (UserAssist), **accounts** (SAM), and **device/network history** from a single data source — often things the event logs never recorded.
- **Corroborate across artifacts.** ShimCache missed `coreupdater.exe`; UserAssist caught it. No artifact is complete — the case is built from the *cluster*, across hives and across hosts, with a **benign baseline** to measure against.

---

## 10. Sources & further reading

- RegRipper 3.0 — Harlan Carvey: <https://github.com/keydet89/RegRipper3.0>
- Harlan Carvey, *Windows Registry Forensics* (Syngress) — the authoritative text on hive structure and artifact locations.
- SANS FOR500 — Windows Registry artifact reference (UserAssist, Shellbags, USBSTOR, Run keys, ShimCache).
- MITRE ATT&CK — T1543.003 (Service), T1547.001 (Registry Run Key), T1059.001 (PowerShell): <https://attack.mitre.org/>
- 13Cubed — "Investigating the Windows Registry" / RegRipper episodes (YouTube).
- DFIR-Madness, "The Stolen Szechuan Sauce" (Case 001) — dataset provenance: <https://dfirmadness.com/the-stolen-szechuan-sauce/>

---
*Related modules: registry execution evidence also appears as [ShimCache (Module 2)](../module-02-shimcache-appcompatcache) and [Amcache (Module 3)](../module-03-amcache-amcacheparser); the persistence and logon story continues in [Event Logs (Module 5)](../module-05-evtx-evtxecmd) and [Lateral Movement (Module 8)](../module-08-lateral-movement). Research background: [`research/regripper.md`](../research/regripper.md).*
