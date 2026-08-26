# Module 17 — User Activity & Shell Artifacts: the Eric Zimmerman tools

**Deck mapping:** *Intrusion Hunting Playbook* → "Evidence of User Activity" — reconstructing the human at the keyboard from the traces Windows leaves behind.
**Goal:** answer the question every investigator eventually has to answer — ***what did this user actually touch?*** — by parsing the small metadata artifacts Windows writes as a side effect of normal use: the **files a user opened**, the **folders they browsed in Explorer**, the **programs they pinned**, the **external/USB drives they attached**, and the **files they deleted**. You'll do it with **Eric Zimmerman's (EZ) tools** — `JLECmd`, `LECmd`, `SBECmd`, `RBCmd` — running **natively on the lab VM**, and read the resulting CSVs the way a real triage analyst does.

> **Evidence note.** The artifacts in `data/artifacts/` are **Eric Zimmerman's own MIT-licensed test fixtures** — the very files his tools' unit tests parse: jump lists (`*.automaticDestinations-ms`), Windows shortcuts (`*.lnk`), and a real `UsrClass.dat` hive carrying shellbags. They contain **no user PII and no payload** — they are inert OS metadata, chosen precisely because they exercise every field the parsers decode. We never alter evidence, so the tool output shows the fixtures' real baked-in values (application IDs, machine IDs, volume serials, target paths).

---

## 1. Background — why this matters

Most of this lab hunts the attacker's tools: what executed (Prefetch, ShimCache, Amcache, UserAssist), what persisted (Run keys, services), what moved laterally. This module hunts the **human**. When a person uses a Windows desktop, the OS quietly records an astonishing amount about **what that person did** — not to spy on them, but to make Windows feel fast and helpful: jump lists so your taskbar remembers recent documents, `.lnk` shortcuts so "Recent Items" works, shellbags so a folder re-opens at the same size and sort order, Recycle Bin metadata so "Restore" can put a file back where it came from. Every one of those conveniences is a **forensic artifact**.

What makes these artifacts so valuable is a single shared property: **they are inert OS metadata, written by Explorer as bookkeeping.** Nothing here executes. There is no payload. A jump list is a structured list; a `.lnk` is a pointer; a shellbag is a saved view setting; an `$I` file is a deletion receipt. That means two things for the investigator:

- They are **safe to parse** — you are reading data structures, not detonating anything.
- They **outlive the thing they describe.** A shellbag survives the folder being deleted. A `.lnk` survives the target file being wiped. A Recycle-Bin `$I` record *is* the proof a file existed even after the `$R` data is gone. These artifacts are often the **only** surviving evidence that a file, folder, or device was ever on the machine.

### The four questions this module answers

| Question the investigator asks | Artifact that answers it | Tool |
|---|---|---|
| *What documents/apps did the user open, and in what order?* | **Jump Lists** (`*.automaticDestinations-ms`) | `JLECmd` |
| *What was the exact target of that shortcut — path, arguments, which drive, which machine?* | **LNK shortcuts** (`*.lnk`) | `LECmd` |
| *What folders did the user browse — including external drives and folders now deleted?* | **Shellbags** (`UsrClass.dat`) | `SBECmd` |
| *What files did the user delete, from where, and when?* | **Recycle Bin** (`$I` records) | `RBCmd` |

### The catch — everything here is binary

A jump list is an **OLE compound file** (the same structured-storage container as an old `.doc`) with **`SHLLINK`** streams inside. A `.lnk` is a binary **Shell Link** structure with layered `ItemID` and `ExtraData` blocks. A shellbag lives **inside a registry hive** (`UsrClass.dat`) as nested `BagMRU` keys holding raw shell-item bytes. `cat` gives you garbage. You need a parser that knows each structure's layout and decodes the timestamps (64-bit **FILETIME**), the MRU ordering arrays, the volume serials, and the embedded droid/machine IDs. **That is what the EZ tools do**, and they all emit the same thing: **CSV**, ready for **Timeline Explorer** (the unified EZ viewer) or for a quick `grep`/`head` at the command line.

> **Plain-language summary:** Windows keeps helpful little notes about what you opened, browsed, ran, and deleted. Those notes are binary and scattered. The EZ tools read each kind of note and turn it into a spreadsheet — and because the notes outlive what they describe, they often prove activity nothing else remembers.

---

## 2. What the tools do — the EZ user-activity family

**Eric Zimmerman**, a widely-recognised DFIR tool author, maintains a suite of free, open-source, forensically sound parsers — each one dedicated to a single artifact, each reading the artifact **read-only and offline** and emitting a rich CSV. The four you use here:

- **`JLECmd`** — **J**ump **L**ist parser. Reads `*.automaticDestinations-ms` (system-tracked, one per application) and `*.customDestinations-ms` (application-tracked). Cracks the OLE compound file, walks the `DestList` MRU stream, and decodes each embedded LNK.
- **`LECmd`** — **L**NK (shortcut) parser. Decodes a Shell Link end to end: target path, arguments, working directory, icon, the **target file's** MAC timestamps, the **volume serial + drive type** the target lived on, and the **machine ID / MAC address** baked into the tracker block.
- **`SBECmd`** — **S**hell**B**ag **E**xplorer command line. Parses the `BagMRU` shellbag tree out of `UsrClass.dat` (and `NTUSER.DAT`) into a flat list of every folder the user browsed in Explorer.
- **`RBCmd`** — **R**ecycle **B**in parser. Decodes the `$I` metadata records (Vista+) and legacy `INFO2` files into original-path / size / deletion-time rows.

They share a command grammar: **`-d <dir>`** to recurse a directory of artifacts (or **`-f <file>`** for one), **`--csv <out-dir>`** to write CSV, and **`--csvf <name>`** to name the file. Point them at a folder of collected artifacts and they parse everything they recognise.

---

## 3. The data in this module

`data/artifacts/` holds Eric Zimmerman's test fixtures — one small collection that exercises three of the four artifact types:

| Fixture in `artifacts/` | Artifact type | What the parser gets |
|---|---|---|
| `1b4dd67f29cb1962.automaticDestinations-ms` (+ 3 more) | **Jump Lists** | per-application MRU of opened/pinned items — **9 destination rows** across the four files |
| `Hyper-V Manager.lnk`, `IIS Client Manager.lnk`, `IIS6 Manager.lnk`, and the `$R*.lnk` set | **LNK shortcuts** | target paths, args, volume serials, target MAC times, machine ID — **8 rows** |
| `UsrClass.dat` | **Shellbags** | folders browsed in Explorer — **5 shellbags** |

> **No Recycle-Bin fixtures ship here.** The EZ test corpus doesn't include a `$I` sample in this collection, so `RBCmd` is covered in prose (Section 4d) rather than run — the technique matters even where we don't have a fixture to feed it. On a live-acquired system you'd point `RBCmd` at `C:\$Recycle.Bin` exactly as shown.

Notice the fixtures lean toward **server-administration tooling** (Hyper-V Manager, IIS Manager). That's incidental to the fixtures, but it's a realistic teaching shape: on a compromised admin box, the jump lists and shortcuts are exactly where you'd see *which management consoles the intruder opened.*

---

## 4. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-17-user-activity/data
```
- **Every command below runs from inside `data/`**, so artifacts are named with the simple relative path `artifacts`.
- The EZ tools are installed **natively on the lab VM and already on your `PATH`** as `.exe` — you call `JLECmd.exe`, `LECmd.exe`, `SBECmd.exe`, `RBCmd.exe` directly. No container, no Docker. The VM is kept **offline** so evidence never phones home. *(Tool-currency note: current EZ Tools ship as **.NET 9** builds — Eric Zimmerman migrated off .NET 6 after its Nov-2024 end-of-life — so a VM that refreshes these `.exe`s needs the .NET 9 runtime present.)*
- Each tool writes its CSV into an **`out/`** directory (created on first run). Open those CSVs in **Timeline Explorer**, or read them here with `head`/`grep`.

---

## 5. Step-by-step walkthrough

### 4a. Jump Lists — the per-application MRU (`JLECmd`)

**What it is.** A **jump list** is the list you see when you right-click an app on the taskbar: "Recent" and "Pinned" items. Windows keeps one **`AutomaticDestinations`** file per application, named by an **AppId** (a hash of the app's path) — e.g. `1b4dd67f29cb1962.automaticDestinations-ms`. Inside is an OLE compound file whose **`DestList`** stream is an **MRU-ordered list** of every document/folder that app recently touched, each entry an embedded LNK with its own target path and timestamps.

**Where it lives on a live system:**
```
%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms
%AppData%\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms
```
(i.e. `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\…`)

**Run it:**
```bash
JLECmd.exe -d artifacts --csv out --csvf jumplists.csv
```

**Read the CSV.** Each row is one destination entry. The columns that carry the case:
- **`AppId`** + **`AppIdDescription`** — JLECmd maps the hashed AppId back to the **application** (it ships a known-AppId list), so you learn *which program* opened the item without guessing.
- **`Path`** — the **target the user opened** (a document, a folder, a UNC share, an `E:\` path).
- **`EntryNumber` / `MRUPosition`** — **order of use**; position 0 is most-recent-used. This is how you reconstruct *the sequence* a user worked in.
- **`CreationTime` / `LastModified`** (of the DestList entry) and **`TargetCreated/Modified/Accessed`** — *when* the item was added and the target's own MAC times.
- **`InteractionCount`**, **`PinStatus`** — how many times it was opened, and whether the user deliberately **pinned** it (pinned = the user cared about it).
- **`Hostname` / `MacAddress` / `VolumeSerialNumber`** — machine and volume the target lived on.

> **Forensic value.** Jump lists are a **per-application history of what a user opened**, with order and counts, that survives the documents themselves being deleted. They're one of the cleanest ways to show *intent and sequence* — "the user opened this share, then this file, then pinned it" — and because each entry embeds an LNK, they carry the same volume/machine tells as standalone `.lnk` files (next section).

Pull the target paths straight out of the CSV:
```bash
head -1 out/jumplists_AutomaticDestinations.csv          # see the column headers
grep -i -E "\.exe|\.docx|\\\\" out/jumplists_AutomaticDestinations.csv   # opened binaries, docs, UNC paths
```

### 4b. LNK shortcuts — the shortcut that tracks the target (`LECmd`)

**What it is.** A **`.lnk`** is a Windows **Shell Link** — a pointer to a target. Windows creates them constantly and automatically: every time a user opens a file, a `.lnk` lands in **Recent Items**. The forensic gift is that a `.lnk` doesn't just store a path — it embeds a **snapshot of the target at the moment the shortcut was made**: the target's **MAC timestamps**, its **size**, the **volume serial number** and **drive type** it lived on, and — in the tracker `ExtraData` block — the **NetBIOS machine name and MAC address** of the machine where the target was located.

**Where it lives on a live system:**
```
%AppData%\Microsoft\Windows\Recent\*.lnk          (auto-created "Recent Items")
%AppData%\Microsoft\Windows\Start Menu\…\*.lnk    (Start-menu / pinned shortcuts)
C:\Users\<user>\Desktop\*.lnk
```

**Run it:**
```bash
LECmd.exe -d artifacts --csv out --csvf lnk.csv
```

**Read the CSV.** The columns that matter:
- **`SourceFile`** — which `.lnk` this row came from.
- **`LocalPath` / `TargetIDAbsolutePath` / `Arguments` / `WorkingDirectory`** — the **full target path, any command-line arguments, and working directory**. Arguments are gold: a shortcut whose target is `powershell.exe` with a base64 `-enc` argument is a launcher, not a convenience.
- **`TargetCreated` / `TargetModified` / `TargetAccessed`** — the **target's own MAC times** captured when the shortcut was made — a second, independent timestamp source you can cross-check against the filesystem.
- **`DriveType`** — `Fixed`, **`Removable`**, or `Network`. `Removable` immediately flags a **USB / external drive**.
- **`VolumeSerialNumber` / `VolumeLabel`** — identifies the *specific volume*; a serial that isn't the system disk means the file lived on **another drive**.
- **`MachineID` / `MachineMACAddress` / `TrackerCreatedOn`** — the **machine the target was on**. On a shortcut to a file on a *different* host, this is how you tie activity to a specific machine. The MAC address isn't stored as its own field — it's the **node bytes of the version-1 Droid / Birth-Droid GUIDs** in the LNK's DistributedLink Tracker (`TrackerDataBlock`): a v1 UUID embeds the originating NIC's MAC in its node component, which is *why* the shortcut attributes to the machine that created it. Treat it as an **attribution lead, not proof**: the MAC node is only meaningful for **version-1 (time-based) UUIDs**, and on some hosts it is randomized or zeroed. (Source: MS-SHLLINK `TrackerDataBlock` spec.)

> **Forensic value — USB and external-drive tracking.** `.lnk` files are the backbone of removable-media and cross-machine investigations. When a user opens a document off a USB stick, the resulting shortcut permanently records the stick's **volume serial**, a **`Removable` drive type**, and the **machine ID** — and it *stays behind on the host after the stick is unplugged and the file is gone*. Correlate the volume serial here with the `USBSTOR`/`MountedDevices` registry keys (Module 16) and you can put a specific device, holding a specific file, on this machine at a specific time — the core of a **data-theft (T1052)** case.

```bash
grep -i "Removable" out/lnk.csv        # anything opened off external media
head -1 out/lnk.csv                     # inspect the full column list
```

> **Expect no hits here — and that is the point.** The three `.lnk` fixtures that ship with this
> module are ordinary local shortcuts (`Hyper-V Manager.lnk` and friends), so `DriveType` is
> `Fixed` throughout and the grep returns **nothing**. That is a correct result, not a broken
> command: *absence of a Removable hit is evidence too.* On a real case the row you are hunting
> looks like this, and the two fields that matter are the last ones:
>
> ```
> ...,E:\exfil\Q3_customers.xlsx,...,Removable,1A2B-3C4D,MY_USB
>                                       ^drive     ^volume  ^label
> ```
>
> Take the **`VolumeSerialNumber`** from a row like that into Module 16's `USBSTOR` /
> `MountedDevices` keys and you have put a **specific device**, holding a **specific file**, on
> this machine at a **specific time** — the core of a data-theft (T1052) case.

### 4c. Shellbags — folders browsed, even after they're gone (`SBECmd`)

**What it is.** Every time a user opens a folder in Explorer, Windows saves that folder's **view preferences** (window size, sort order, icon layout) so it re-opens the same way. That preference record is a **shellbag**, stored as a tree of **`BagMRU`** keys inside the per-user **`UsrClass.dat`** hive. The catch — and the reason shellbags are a top-tier artifact — is that the record is keyed by the folder's **shell path**, and **it is never cleaned up.** The shellbag persists **after the folder is deleted, after the USB stick is removed, after the network share is unmounted.**

**Where it lives on a live system:**
```
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat   (BagMRU — the main shellbag store)
C:\Users\<user>\NTUSER.DAT                                     (older/secondary shellbag keys)
```

**Run it:**
```bash
SBECmd.exe -d artifacts --csv out
```
(`SBECmd` names its own CSV — look in `out/` for the `*_UsrClass.csv` / `*_Shellbags.csv` it writes.)

**Read the CSV.** Each row is one folder the user browsed:
- **`AbsolutePath`** — the **reconstructed folder path** (`SBECmd` walks the nested bag tree and rebuilds the full path), including `My Computer\…`, drive letters, **removable drives**, and **`\\server\share`** UNC paths.
- **`ShellType`** — what the node is (Directory, Drive letter, Network share, Zip, Mount point) — how you spot external vs. local vs. network.
- **`FirstInteracted` / `LastInteracted`** and **`CreatedOn` / `ModifiedOn` / `AccessedOn`** — when the folder was first and last browsed (decoded FILETIMEs), and the embedded shell-item MAC times.
>
> **Timestamp caveat — the MRU-0 trap.** Read shellbag times as *a window*, not *a moment*. A `BagMRU` key's registry last-write time is stamped onto whichever child folder is currently **MRU position 0** — so a single browsing action updates the parent's timestamp, and re-visiting a sibling later can re-point that stamp, meaning a folder's `LastInteracted` can reflect the last time *any* folder in that parent was touched, plus view-state changes (resize/re-sort) that aren't "the user opened this folder" at all. Report shellbags as **consistent with interactive access to a path within a time window**, and pin the actual moment against an independent source — the matching `.lnk`, jump-list entry, or `$MFT` record — rather than asserting the shellbag time *is* the open time.
- **`MFTEntry` / `MFTSequenceNumber`** — ties the shell item back to an `$MFT` record when you have the disk (cross-reference with Module 15).

> **Forensic value — the folder is gone, the proof is not.** Shellbags are the single best answer to *"did this user browse to `E:\exfil` / `\\dc01\c$` / a folder they later deleted?"* Because they survive the folder's deletion and the drive's removal, they routinely prove **interactive access to a location that no longer exists** — an attacker staging files in a temp folder they cleaned up, or browsing a share before copying data off it. Their existence also proves the folder was opened **in Explorer by a human**, not merely touched by a background process.

```bash
grep -i -E "Removable|\\\\\\\\|USB" out/*.csv   # external drives + UNC shares in the bags
```

> **Also expect no hits on the shipped `UsrClass.dat`** — it carries ordinary local browsing,
> so this grep returns nothing. Run the same search against a live-acquired `UsrClass.dat` and a
> bag for `E:\` or a `\\server\share` is exactly what betrays a folder the user opened and
> later deleted, or a drive they unplugged. **The empty result is the baseline you compare against.**

### 4d. Recycle Bin — the deletion receipt (`RBCmd`)

*(No `$I` fixture ships in this module — this section is prose so you know the technique; run it against `C:\$Recycle.Bin` on a live-acquired system.)*

**What it is.** When a user deletes a file to the Recycle Bin (Vista and later), Windows splits it into a **pair**:
- **`$R…`** — the file's **actual data**, renamed but intact (this is what "Restore" copies back).
- **`$I…`** — a small **metadata record**: the file's **original full path**, its **size**, and the **deletion timestamp**. The two share a suffix, so `$IAB12CD.docx` is the receipt for `$RAB12CD.docx`.

**Where it lives on a live system:**
```
C:\$Recycle.Bin\<user-SID>\$I******      (metadata: original path, size, deleted-on)
C:\$Recycle.Bin\<user-SID>\$R******      (the recovered file data)
```
Each user's deletions sit under **their own SID's** subfolder — so the SID tells you *which account* deleted the file.

**How you'd run it:**
```bash
RBCmd.exe -d 'artifacts/recyclebin' --csv out --csvf recyclebin.csv    # recurse a $Recycle.Bin tree
RBCmd.exe -f 'artifacts/$IAB12CD.docx' --csv out                        # or one $I record
```

**Read the CSV.** `RBCmd` emits: **`SourceName`** (the `$I` file), **`FileName`** (the **original full path** the file was deleted from), **`FileSize`**, and **`DeletedOn`** (the decoded deletion FILETIME).

> **Forensic value.** The `$I` record proves *a specific file, at a specific original path, was deleted by a specific user (SID) at a specific time* — even if the `$R` data was later purged, the receipt often remains. It's how you show an attacker deleted their tooling ("emptied the bin") and, paired with the surviving `$R`, how you **recover** the deleted file outright. Deletion staging and cleanup map to **T1070 (Indicator Removal)**.

---

## 6. Reading the output — what draws the eye

| Artifact (tool) | What it tells you | Worth a second look when… |
|---|---|---|
| Jump Lists (`JLECmd`) | per-app history of items opened, with order + pin status | an admin console (Hyper-V/IIS/PowerShell) or a document opened off a **UNC share** or **external drive**; a pinned item on a "clean" account. |
| LNK (`LECmd`) | exact target path, **arguments**, target MAC times, **volume serial + drive type**, machine ID | `DriveType = Removable`; arguments containing `-enc`/`iex`/`http`; a **volume serial that isn't the system disk**; a machine ID that isn't this host. |
| Shellbags (`SBECmd`) | every folder browsed in Explorer, **surviving deletion/removal** | a bag for a **removable drive**, a **`\\server\share`**, or a **folder that no longer exists** on disk. |
| Recycle Bin (`RBCmd`) | original path + size + deletion time, per user SID | a tool/archive deleted inside the incident window; a sensitive file deleted right before logoff. |

**Triaging false positives.** A single jump-list entry or a lone `.lnk` proves *convenience*, not *malice* — Windows manufactures these constantly. What convicts is the **cluster and the correlation**: a `Removable`-drive `.lnk` **whose volume serial also appears in `USBSTOR`** (Module 16), a **shellbag for that same external path**, and a **Recycle-Bin `$I`** showing the copied file was then deleted — the same device and the same file surfacing across three independent artifacts. Judge the *combination*, and always keep a **benign baseline** of what this user's normal activity looks like.

---

## 7. On a live-acquired system, also parse

The four artifacts above are collectable as loose files. Two more high-value user-activity sources need the same EZ treatment but aren't shipped as fixtures here because they're **large, per-machine databases that are locked while Windows runs** — you collect them **offline** (from an image or VSS copy), not by copying the live file:

- **SRUM — System Resource Usage Monitor** — parser **`SrumECmd`**.
  - **On disk:** `C:\Windows\System32\sru\SRUDB.dat` **+** the `SOFTWARE` hive (SRUM needs the hive to resolve app IDs and user SIDs).
  - **What it shows:** a ~30–60-day rolling record of **per-application resource use** — **bytes sent/received per app, per user**, CPU time, and which network each app used. This is a premier **exfil-volume** artifact: it can show *a specific process pushed hundreds of MB out over a specific interface*, long after the transfer.
  - **The live catch:** `SRUDB.dat` is an ESE database held open by Windows — you can't just copy it. Collect it offline, and if it's marked **dirty**, repair it first with `esentutl /r` (a "dirty" ESE shutdown-recovery) before `SrumECmd` will read it.
  - **The 60-minute lag:** SRUM doesn't write continuously — it commits roughly **once an hour** (and is *supposed* to flush on shutdown). Between commits the not-yet-written activity is buffered in the **`SOFTWARE` hive under `…\CurrentVersion\SRUM`** (a second reason to always grab that hive). The consequence for live response is blunt: **the most recent hour of network/app usage — often the exact exfil window — may not be in `SRUDB.dat` yet**, and because the shutdown flush is unreliable on Windows 10 2004+/Windows 11, a dirty image or power-pull can lose it. Treat a `SRUDB.dat` whose newest timestamp is up to an hour stale as normal, not as proof the transfer never happened.

- **Windows Timeline (Activities Cache)** — parser **`WxTCmd`**.
  - **On disk:** `C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\L.<user>\ActivitiesCache.db` (Windows 10 **1803+**).
  - **What it shows:** an application/file **activity timeline** — which app was in focus, which document it had open, start/end times and duration — reconstructing the user's session almost like a screen-recording index.
  - **Currency caveat:** that rich app/document-activity recording is a **Windows 10-era (1803–21H2)** behaviour; Microsoft **deprecated and then removed the Timeline feature across Windows 11 (2022–2024)**, so on a Win11 host the DB may still persist but typically holds only sparse system entries rather than the full activity history. (Sources: Microsoft — *Timeline retired in Windows 11* and activity-history upload deprecated in KB5034204; kacos2000 *WindowsTimeline*; Forensic Focus DFIR round-up, 27 Nov 2024 — all linked in Sources below.)

Both are the **natural extension** of this module: jump lists/LNK/shellbags tell you *what the user opened and browsed*; SRUM tells you *how much data an app moved*; Windows Timeline tells you *the minute-by-minute session*. Together they close the loop from "a file was touched" to "this much data left, in this session, by this account."

---

## 8. Investigative narrative — the story these artifacts tell

Stitch the user-activity artifacts together and they narrate a session the way a witness would:

1. **The user browsed here.** Shellbags (`SBECmd`) show which folders were opened in Explorer — including a **removable drive** or a **share** that may no longer be attached.
2. **The user opened these items, in this order.** Jump lists (`JLECmd`) give the per-application MRU — the sequence and counts, and which items were deliberately **pinned**.
3. **Each shortcut points at a real target on a real volume.** LNK (`LECmd`) resolves the exact **path + arguments**, and — via **volume serial, drive type, and machine ID** — ties a file to a **specific device or host**, which is how a USB or cross-machine transfer gets nailed down.
4. **Then the user deleted the evidence.** Recycle-Bin `$I` records (`RBCmd`) show the **original path, size, and deletion time** under the deleting user's **SID** — and the paired `$R` may let you recover the file outright.
5. **And on a live image, SRUM/Timeline quantify it** — how much data the app moved and the minute-by-minute session around it.

No single artifact carries the case. But the **same volume serial** in an LNK and in `USBSTOR`, the **same external path** in a shellbag, the **same file** as a Recycle-Bin receipt, and the **same account SID** throughout — that convergence *is* the proof. This is the human-activity half of the intrusion; the capstone merges it with the execution, persistence, and timeline evidence into one account.

---

## 9. Try-it-yourself exercises

1. **Resolve the AppIds.** Run `JLECmd.exe -d artifacts --csv out --csvf jumplists.csv`, open `out/jumplists_AutomaticDestinations.csv`, and list the distinct `AppIdDescription` values. Which *applications* generated these jump lists, and what does the mix (server-admin consoles) suggest about the role of the machine they came from?
2. **Hunt removable media.** Run `LECmd.exe -d artifacts --csv out --csvf lnk.csv`, then `grep -i "Removable" out/lnk.csv`. For any hit, record the **VolumeSerialNumber** and **MachineID** — and explain, in two sentences, how you'd confirm the same device in the `USBSTOR` registry key from Module 16.
3. **Find the folder that's gone.** Run `SBECmd.exe -d artifacts --csv out` and open the shellbag CSV. Pick the shellbag with the **oldest `FirstInteracted`** and the one with a **network/removable `ShellType`**. Why does a shellbag for a folder that no longer exists on disk still prove the user browsed there?
4. **Compare the two timestamp sources.** For one `.lnk`, compare its `TargetModified` (from `LECmd`) against what you'd expect from the filesystem `$MFT` (Module 15). If they disagreed, which would you trust, and what would a disagreement suggest?
5. **Plan the live collection.** You're handed a *running* suspect host. Write the three-line collection plan for SRUM: which two files you grab, why you can't just copy `SRUDB.dat` live, and the `esentutl` step you'd run before `SrumECmd`.
6. **Timeline Explorer.** Load all of this module's CSVs into **Timeline Explorer**, sort by timestamp, and build a single combined view of the user's activity. Which artifact contributes the *earliest* event, and which the *latest*?

---

## 10. Key takeaways

- **User-activity artifacts answer "what did this human touch?"** — files opened (jump lists, LNK), folders browsed (shellbags), and files deleted (Recycle Bin) — and they are **inert OS metadata**: no execution, no payload, safe to parse.
- **They outlive what they describe.** Shellbags survive folder deletion and drive removal; `.lnk` files survive the target being wiped; `$I` records survive the file's data. These are often the *only* surviving proof.
- **LNK is the removable-media workhorse:** target **MAC times + volume serial + drive type + machine ID** tie a file to a specific USB/host — correlate with `USBSTOR` (Module 16).
- **Everything is binary; the EZ tools decode it to CSV** with one grammar — `-d <dir> --csv <out>` — feeding **Timeline Explorer** or a quick `grep`/`head`.
- **On a live image, extend to SRUM (`SrumECmd`) and Windows Timeline (`WxTCmd`)** for data-volume and minute-by-minute session context — collected **offline**, dirty-repaired with `esentutl /r`.
- **The case is the convergence** — the same device, path, file, and SID surfacing across independent artifacts — never a single tell. Keep a benign baseline.

---

## 11. Sources & further reading

- **Eric Zimmerman's tools** — official hub, binaries and docs (JLECmd, LECmd, SBECmd, RBCmd, SrumECmd, WxTCmd, Timeline Explorer): <https://ericzimmerman.github.io/>
- **JLECmd — Jump List parser (source + docs)**: <https://github.com/EricZimmerman/JLECmd>
- **Jump List AppID lookup table** — the authoritative AppID->application map that resolves `AutomaticDestinations` filenames: <https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt>
- **Forensics Wiki — Jump Lists** (the CFB/OLE container, the hex `SHLLINK` streams, and the `DestList` MRU stream): <https://forensics.wiki/jump_lists/>
- **MS-SHLLINK — Shell Link (`.LNK`) Binary File Format** (LNK internals, and the `TrackerDataBlock` / Droid GUIDs behind MachineID/MAC): <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943>
- **Forensics Wiki — Shell Item** (the shellbag / `BagMRU` shell-item structure): <https://forensics.wiki/shell_item/>
- **kacos2000 — WindowsTimeline** (`ActivitiesCache.db` schema and ready SQL queries): <https://github.com/kacos2000/WindowsTimeline>
- **Microsoft — Get help with Timeline** (Timeline retired in Windows 11): <https://support.microsoft.com/en-us/windows/get-help-with-timeline-febc28db-034c-d2b0-3bbe-79aa0c501039>
- **Microsoft — Windows activity history and your privacy** (activity-history upload deprecated, KB5034204): <https://support.microsoft.com/en-us/windows/windows-activity-history-and-your-privacy-2b279964-44ec-8c2f-e0c2-6779b07d2cbd>
- **Microsoft — `esentutl`** (`/r` recovery for a dirty `SRUDB.dat` ESE database): <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/esentutl>
- **13Cubed — "Introduction to Windows Forensics"** (YouTube) — episodes on LNK & Jump Lists, Shellbags, and the Recycle Bin: <https://www.youtube.com/@13cubed>
- **MITRE ATT&CK** — **T1074 (Data Staged)**, **T1052 (Exfiltration Over Physical Medium)**, **T1070 (Indicator Removal)**: <https://attack.mitre.org/>


---
*Related modules: device/USB history and Shellbags also appear via the registry in [RegRipper (Module 16)](../module-16-registry-regripper); the `$MFT` cross-reference for LNK/shellbag MFT entries is [Filesystem Timeline (Module 15)](../module-15-filesystem-timeline); execution evidence for the programs these shortcuts launched is in [Prefetch (Module 1)](../module-01-prefetch-pecmd) and [Amcache (Module 3)](../module-03-amcache-amcacheparser). Timeline Explorer background: [`research/mftecmd-timeline.md`](../research/mftecmd-timeline.md).*


---

## Sources

- **Eric Zimmerman's tools (JLECmd, LECmd, SBECmd, RBCmd) — suite home** — [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
- **JLECmd — Automatic/Custom Destinations jump-list parser** — [EricZimmerman/JLECmd](https://github.com/EricZimmerman/JLECmd)
- **LECmd — LNK (Shell Link) parser** — [EricZimmerman/LECmd](https://github.com/EricZimmerman/LECmd)
- **LNK TrackerDataBlock — MachineID (NetBIOS) + MAC in Droid GUID node** — [MS-SHLLINK 2.5.10 TrackerDataBlock](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/df8e3748-fba5-4524-968a-f72be06d71fc)
- **Shellbags (SBECmd) — BagMRU in UsrClass.dat, survives folder/drive removal** — [SANS: Computer Forensic Artifacts — Windows 7 Shellbags (Tilbury)](https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags)
- **Recycle Bin (RBCmd) — $I/$R pair, original path / size / deletion time** — [Magnet Forensics: Recycle Bin artifact profile](https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/)
- **USB / external-media file-open evidence → data theft** — [MITRE ATT&CK T1052: Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052/)
- **Deletion / cleanup of tooling** — [MITRE ATT&CK T1070: Indicator Removal](https://attack.mitre.org/techniques/T1070/)
