# Research — The Sleuth Kit (Filesystem & Timeline Forensics)

> **Status in `dfir-aio:v2`:** PRESENT. `fls`, `mmls`, `icat`, `istat` (and the full TSK suite: `fsstat`, `img_stat`, `blkls`, `blkcat`, `ffind`, `ils`, `tsk_recover`, `mactime`, `tsk_gettimes`) on `PATH`. Version **4.11.1** (verified on rick 2026-06-29).

---

## 1. What it is and the forensic question it answers

**The Sleuth Kit (TSK)** by Brian Carrier is the foundational open-source **disk- and filesystem-forensics** toolkit (Autopsy is its GUI). It answers low-level questions directly from a **disk image** (raw `dd`, `E01`, split, VMDK with libewf support): **"What partitions exist? What files (including deleted ones) are on this filesystem? What are a file's exact MAC timestamps? Give me the raw bytes of this file/inode."** It works at the **metadata layer** (inodes/MFT records), so it sees **deleted and renamed** files that a normal file copy can't, and it never mounts the image (read-only, forensically sound).

TSK is organised in **layers**, and the tool names follow them:
- **Image layer** (`img_stat`, `img_cat`) — the container file itself.
- **Volume/partition layer** (`mmls`, `mmstat`) — the partition table.
- **Filesystem layer** (`fsstat`) — the filesystem superblock/boot record.
- **Metadata/inode layer** (`istat`, `ils`, `icat`, `ifind`) — per-file records (MFT entry on NTFS, inode on ext).
- **File-name layer** (`fls`, `ffind`) — directory entries that map names → inodes.
- **Data-unit/block layer** (`blkls`, `blkcat`, `blkstat`, `blkcalc`) — raw clusters/sectors.

---

## 2. How it works under the hood (plain language)

A disk image is just bytes. TSK parses the on-disk structures the same way the OS would, but **read-only and offline**:
1. `mmls` reads the **partition table** (MBR/GPT) and prints where each volume starts (in **sectors**). You need a volume's **starting offset** to analyse the filesystem inside it.
2. You pass that offset with `-o` to the filesystem tools, which then read that volume's NTFS/FAT/ext structures.
3. On NTFS, every file has an **MFT entry** (its "inode" number); `fls` walks the directory tree mapping names → MFT numbers, and `istat`/`icat` work on a given MFT number. Because the MFT keeps entries for **deleted** files until reused, TSK can list and recover them (`fls -d` shows deleted; `*` marks them).

The genius of TSK for IR is the **bodyfile → timeline** pipeline: `fls -m` (and `ils -m`) emit every file's metadata in a pipe-delimited **"bodyfile"** format, and `mactime` sorts those by time into a human-readable **timeline** of filesystem activity (the classic "MAC times": Modified, Accessed, Changed/Created).

---

## 3. The four headline tools (with the question each answers)

### 3.1 `mmls` — "what partitions are in this image?"
```bash
mmls disk.img
```
Output table: slot, **Start** sector, End, Length, Description (e.g. `NTFS / exFAT (0x07)`). **Note the Start sector of the partition you want** — that's your `-o` offset for everything else.
| Flag | Purpose |
|---|---|
| `-t TYPE` | force volume type (`dos`, `gpt`, `bsd`, `mac`, `sun`). |
| `-B` | also show partition sizes in bytes. |
| `-a` / `-A` | show only allocated / show unallocated too. |

### 3.2 `fls` — "list files (incl. deleted) in a directory/filesystem"
```bash
fls -o 2048 disk.img            # list root dir of the volume starting at sector 2048
fls -o 2048 disk.img 12345      # list contents of the directory at MFT/inode 12345
```
| Flag | Purpose |
|---|---|
| `-o N` | **partition offset in sectors** (from `mmls`) — almost always required. |
| `-r` | **recurse** into subdirectories. |
| `-p` | show **full paths** (with `-r`). |
| `-d` | show **only deleted** entries. |
| `-u` | show only undeleted. |
| `-l` | long format (sizes + MAC times inline). |
| `-m DIR` | **bodyfile** output, prefixing paths with `DIR` (feeds `mactime`). |
| `-z ZONE` | time zone for display. |
Output line: `r/r 12345-128-1:  Users/bob/evil.exe` → `r/r`=regular file (name-type/meta-type), `12345`=MFT entry, `-128-1`=attribute; a leading `*` and `(deleted)` mark recovered deletions.

### 3.3 `istat` — "tell me everything about one file's metadata"
```bash
istat -o 2048 disk.img 12345    # full metadata for MFT entry 12345
```
Prints the file's **allocation status, size, owner, all timestamps** (NTFS shows both **$STANDARD_INFORMATION** and **$FILE_NAME** sets — crucial for **timestomping** detection), and the **list of data clusters** it occupies. **Comparing $SI vs $FN times is the canonical anti-forensic / timestomp check.**

### 3.4 `icat` — "give me the file's raw content by inode"
```bash
icat -o 2048 disk.img 12345 > recovered_evil.exe
```
Streams the bytes of the file/inode to stdout — **works even for deleted files** whose clusters aren't yet overwritten. This is how you **carve out a recovered file** for hashing/YARA/capa.
| Flag | Purpose |
|---|---|
| `-r` | attempt **recovery** of a deleted file's content. |
| `-s` | include slack space. |
| `-o N` | partition offset. |

---

## 4. The timeline pipeline (the IR payoff)

```bash
# 1. Find the partition offset
mmls disk.img                     # say NTFS starts at sector 2048

# 2. Emit a bodyfile of EVERY file's metadata (recursive, full paths)
fls -r -m C: -o 2048 disk.img > bodyfile.txt
#   add ils for orphan/unallocated inodes:
# ils -m -o 2048 disk.img >> bodyfile.txt

# 3. Turn the bodyfile into a sorted, human timeline
mactime -b bodyfile.txt -d -z UTC 2026-01-01..2026-06-29 > timeline.csv
#   -b bodyfile, -d CSV output, -z timezone, optional date range
```
`mactime` produces a chronological list: each line is a timestamp and which file was **M**odified/**A**ccessed/**C**hanged/cr**B**orn at that instant. This is the filesystem half of a **super-timeline** (combine with $MFT/$J/$LogFile and EVTX — see the MFTECmd research doc and the lab's EVTX modules; tools like Plaso/`log2timeline` merge them all).

**Shortcut:** `tsk_gettimes disk.img > bodyfile.txt` runs the bodyfile step across all volumes in one go.

---

## 5. Other frequently-used TSK tools

| Tool | Use |
|---|---|
| `fsstat -o N img` | filesystem details (cluster size, MFT location, volume serial). Run after `mmls` to confirm the FS. |
| `img_stat img` | image-format details (raw/EWF, sector size). |
| `ffind -o N img 12345` | reverse lookup: **which file name** owns this inode. |
| `ifind -o N -n path img` | find the **inode** for a given path (or for a data block with `-d`). |
| `blkcat -o N img 5000` | dump a raw data **block/cluster** by number. |
| `blkls -o N img` | extract **unallocated** space (feed to `foremost`/`scalpel`/`bulk_extractor` for carving). |
| `tsk_recover -o N img out/` | bulk-**recover** allocated (or `-e` all) files to a directory. |

---

## 6. Reading the output / a realistic mini-case

```bash
mmls evidence.E01                                  # → NTFS at sector 2048
fls -r -p -o 2048 evidence.E01 | grep -i 'temp\|public\|downloads'   # find drop locations
fls -d -r -o 2048 evidence.E01 | grep -i '\.exe'   # deleted EXEs (cleanup attempts)
istat -o 2048 evidence.E01 56789                   # check timestomp on the suspect (compare $SI vs $FN)
icat -o 2048 evidence.E01 56789 > suspect.exe      # recover it
sha256sum suspect.exe; capa suspect.exe            # identify/triage
```
**$SI/$FN mismatch reading:** if `$STANDARD_INFORMATION` shows a 2019 creation date but `$FILE_NAME` shows last week, the file was **timestomped** (attacker backdated $SI to blend in) — a strong anti-forensic finding.

---

## 7. Common pitfalls

- **Forgetting `-o`.** Without the partition offset, the FS tools read the wrong bytes (or the partition table) and fail/garbage. Always `mmls` first.
- **Offset units:** TSK `-o` is in **sectors**, and assumes 512-byte sectors unless `-b` says otherwise — match `mmls`'s sector size.
- **E01/EWF support** must be compiled in (`libewf`). TSK 4.11.1 in this container supports `.E01`; for other formats convert or use `ewfmount`.
- **Deleted-file recovery is best-effort** — if clusters were reused, `icat -r` returns partial/garbage. Corroborate size and hash.
- **MFT entry reuse** means a deleted inode may now describe a different file; cross-check name with `ffind`.
- **Time zones:** bodyfile times are UTC internally; set `mactime -z` deliberately so your timeline lines up with EVTX.

---

## 8. Where it fits a DFIR investigation

TSK is the **disk-forensics backbone**: it provides the **filesystem timeline** that anchors a super-timeline, **recovers deleted artifacts** (malware, staged archives, attacker tooling) for downstream analysis, and **detects timestomping**. In this lab it underpins evidence-of-existence questions that complement the execution Triad: where a binary lived on disk, when it was created/deleted, and pulling the bytes back out to run through capa/FLOSS/YARA. Combined with $MFT/$UsnJrnl parsing (next doc) it gives the complete filesystem-history picture.

---

## 9. Sources
- The Sleuth Kit official site + wiki — https://www.sleuthkit.org/ and https://github.com/sleuthkit/sleuthkit/wiki (per-tool man pages: fls, mmls, icat, istat, mactime).
- Brian Carrier, *File System Forensic Analysis* (Addison-Wesley) — the definitive reference for the layers and NTFS/FAT/ext internals TSK parses.
- SANS FOR500/FOR508 — TSK bodyfile→mactime timelining methodology and $SI/$FN timestomp analysis.
- 13Cubed — "Linux/Disk forensics with The Sleuth Kit" walkthroughs.
- Plaso/log2timeline docs — for merging TSK output into a super-timeline.
