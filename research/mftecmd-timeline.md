# Research — MFTECmd & Building a Super-Timeline ($MFT, $J/UsnJrnl, $LogFile)

> **Status in `dfir-aio:v2`:** PRESENT. `MFTECmd` on `PATH` (`/opt/tools/bin/MFTECmd`). Version **2026.5.0** (Eric Zimmerman tool, .NET; verified on rick 2026-06-29). Companion timeline tools: TSK `mactime` and (if added) Plaso/`log2timeline` are the usual mergers — note Plaso availability if you build a full super-timeline.

---

## 1. What it is and the forensic question it answers

**MFTECmd** (Eric Zimmerman) parses the core **NTFS filesystem metadata files** and produces analysis-ready CSV/timeline output. It answers the deepest filesystem-history questions on a Windows host: **"What files existed, when were they created/modified/accessed/renamed/deleted — exactly — and was any of that timestamp evidence faked?"** It parses:

| NTFS file | What it records | Forensic value |
|---|---|---|
| **`$MFT`** | one ~1KB record per file/dir: name(s), size, **timestamps in $STANDARD_INFORMATION ($SI) and $FILE_NAME ($FN)**, parent, resident data. | the complete file inventory + the master timestamp source; **$SI vs $FN = timestomp detection**. |
| **`$J` (`$Extend\$UsnJrnl:$J`)** | the **USN Change Journal** — an append-only log of *every change* to *every file*: create, write, rename, delete, with reason codes + timestamp. | catches files that **were created and deleted between snapshots** — things gone from `$MFT` but recorded as having existed. |
| **`$LogFile`** | NTFS transaction log (lower-level, for crash recovery). | even finer-grained, very short-window changes; recover transactions $J missed. |
| **`$Boot`, `$SDS`** | boot sector / security descriptors. | cluster size, ownership/ACL history. |

The **super-timeline** idea: merge $MFT + $J + $LogFile (filesystem) with registry, EVTX, Prefetch, browser, etc. into **one time-sorted narrative** of everything that happened on the host.

---

## 2. How it works under the hood (plain language)

NTFS stores its own bookkeeping as ordinary (hidden) files. The **$MFT** is an array of fixed-size records; each file is a record holding **attributes** — `$STANDARD_INFORMATION` (the timestamps Explorer shows, and the ones attackers can change with `SetFileTime`), `$FILE_NAME` (a second timestamp set, harder to forge — updated by the kernel on file ops), `$DATA` (content or pointers to clusters). MFTECmd reads each record's attributes and flattens them to rows.

The **USN Journal ($J)** is a sparse, append-only stream: each entry = USN, file reference, parent reference, **reason flags** (`FileCreate`, `DataExtend`, `RenameOldName`, `RenameNewName`, `FileDelete`, `Close`…), and a UTC timestamp. Because it logs *changes* rather than *state*, it shows activity that no longer exists in $MFT — invaluable for proving an attacker dropped-then-deleted a tool.

MFTECmd decodes all of this **offline** from the extracted metadata files (pulled via TSK `icat`, a triage tool like KAPE, FTK, or `fls`/`tsk_recover`), and can also resolve full paths, decode timestomp, and (with both files) **cross-reference $J entries back to $MFT records**.

---

## 3. The CLI + most useful flags

```bash
MFTECmd --help
```
| Flag | Purpose |
|---|---|
| `-f FILE` | the metadata file to parse (`$MFT`, `$J`, `$LogFile`, `$Boot`, `$SDS`). MFTECmd **auto-detects** which one it is. |
| `--csv DIR` | write **CSV** to this directory (the normal output). |
| `--csvf NAME` | set the CSV filename. |
| `--json DIR` / `--jsonf` | JSON output. |
| `--body DIR` / `--bodyf NAME` | output a **TSK bodyfile** (feed straight into `mactime` for a combined timeline). |
| `--bdl LETTER` | drive letter to prefix in the bodyfile (e.g. `C`). |
| `-m PATH` | (with `$J`) provide the **$MFT** so journal entries resolve to **full paths**. |
| `--dt FORMAT` | datetime format string. |
| `--rs` | resolve/include shortnames; `--fl` include $FILE_NAME timestamps explicitly. |
| `--at` | include all timestamps/attributes. |
| `--dr` | dump resident data. |
| `--vss` | also process files from **Volume Shadow Copies** (historical states). |
| `--blf` | treat $LogFile little-endian (rare). |

### Realistic invocations
```bash
# 1. Parse the MFT to a rich CSV (with Timeline Explorer in mind)
MFTECmd -f /evidence/C/'$MFT' --csv ./out --csvf mft.csv

# 2. Parse the USN journal, resolving full paths via the MFT
MFTECmd -f /evidence/C/'$Extend/$UsnJrnl_$J' -m /evidence/C/'$MFT' --csv ./out --csvf usnj.csv

# 3. Parse $LogFile
MFTECmd -f /evidence/C/'$LogFile' --csv ./out --csvf logfile.csv

# 4. Produce a bodyfile for mactime (combine with TSK fls bodyfile → one filesystem timeline)
MFTECmd -f /evidence/C/'$MFT' --body ./out --bodyf mft.body --bdl C
mactime -b ./out/mft.body -d -z UTC > fs_timeline.csv
```

---

## 4. Reading the output / the timestomp check

MFTECmd's MFT CSV gives, per file: full path, in-use flag, size, parent, and **both timestamp sets**:
- **$SI** times: `Created0x10`, `LastModified0x10`, `LastAccess0x10`, `LastRecordChange0x10`.
- **$FN** times: `Created0x30`, `LastModified0x30`, `LastAccess0x30`, `LastRecordChange0x30`.

**Timestomp detection (the headline use):**
- If **$SI `Created` is *earlier* than $FN `Created`**, the $SI was backdated → **timestomping** (attacker ran `SetFileTime` to make a freshly-dropped tool look old). Real files have $SI ≥ $FN-ish, set together at creation.
- **Sub-second precision = 0** (whole-second timestamps like `...000`) in $SI while $FN keeps nanoseconds is another timestomp tell (many tools only set whole seconds).
- MFTECmd surfaces these so you can filter for them in **Timeline Explorer** (sort/colour on the $SI vs $FN columns).

**USN journal CSV** gives, per change: timestamp, full path (with `-m`), **Update Reasons** (e.g. `FileCreate|Close`, `RenameOldName`→`RenameNewName`, `FileDelete|Close`). Reading a sequence reconstructs an attacker's **drop → execute → rename → delete** of a tool even though the file is gone from $MFT.

---

## 5. Building the super-timeline (where this fits)

A **super-timeline** merges every time-stamped artifact into one sorted CSV so you can read an intrusion minute-by-minute:

1. **Filesystem:** MFTECmd ($MFT, $J, $LogFile) + TSK `fls -m`/`mactime` → bodyfile/CSV.
2. **Registry:** RegRipper (LastWrite times, ShimCache, UserAssist) and EZ's `RECmd`.
3. **Execution:** Prefetch (`PECmd`, module 1), Amcache (module 3).
4. **Event logs:** `EvtxECmd` (module 5) — logons, services, PowerShell.
5. **Merge & view:** either feed everything to **Plaso/`log2timeline`** (it ingests $MFT/$J/EVTX/registry natively and outputs a single timeline DB → `psort`), or normalise each tool's CSV and load into **Timeline Explorer** (EZ) sorted by time.

> In `dfir-aio:v2`, MFTECmd + TSK `mactime` cover the filesystem layer, but **Plaso (`log2timeline.py`/`psort.py`) is confirmed NOT installed** (verified on rick 2026-06-29). Until it's added, build the timeline per-layer (MFTECmd CSV + EvtxECmd CSV + RegRipper, etc.) and merge/sort in **Timeline Explorer**. Plaso is the standard one-shot merger and is a recommended container addition.

The output is **the** deliverable of a host investigation: a chronological story — maldoc opened (EVTX) → PowerShell downloader (4104) → dropper written to `\Temp` (USN `FileCreate`) → executed (Prefetch/Amcache) → renamed and timestomped ($SI vs $FN) → deleted (USN `FileDelete`) → lateral movement (service 7045, module 8).

---

## 6. Common pitfalls

- **$J path resolution needs the $MFT.** Without `-m`, USN entries show only file-reference numbers, not paths. Always pass `-m $MFT`.
- **Extracting the metadata files:** they're locked on a live system — pull them from an image (TSK `icat` the known MFT entry, or `fls`/`tsk_recover`), from VSS, or with KAPE/FTK. MFTECmd parses the *extracted* file.
- **$UsnJrnl is sparse/large;** the `:$J` data stream is what you want (not `$Max`). It wraps/ages out — older history may be gone.
- **Time zones:** all EZ output is UTC. Keep every timeline source in UTC before merging or events will mis-order.
- **$SI/$FN nuance:** not every whole-second timestamp is malicious (some legit installers do it); use it as a *lead* with corroboration, and remember $FN is only updated on certain ops.
- **.NET dependency:** MFTECmd is a .NET app; in the Linux container it runs under the bundled .NET runtime — if it ever fails to launch, that's the thing to check.
- **Huge MFTs** → large CSVs; analyse in Timeline Explorer or `csvgrep`, not a text editor.

---

## 7. Where it fits a DFIR investigation

MFTECmd + the super-timeline is the **synthesis stage** — where single artifacts become a coherent intrusion narrative with precise timing, and where **anti-forensics (timestomping, file wiping) is exposed**. It both stands alone (deep NTFS history, deleted-tool recovery via $J) and serves as the spine onto which every other artifact in this lab (Prefetch, ShimCache, Amcache, EVTX, registry) is hung in time. For an analyst, "build the super-timeline" is often the final, decisive step that pins down patient-zero, dwell time, and scope.

---

## 8. Sources
- MFTECmd — Eric Zimmerman tools, https://ericzimmerman.github.io/ and https://github.com/EricZimmerman/MFTECmd (usage, CSV fields).
- Eric Zimmerman, "Introducing MFTECmd" and Timeline Explorer docs.
- 13Cubed — "MFTECmd" and "NTFS Timestamps / Timestomping" episodes (the $SI vs $FN and sub-second-precision detection).
- SANS FOR508 / FOR500 — NTFS $MFT/$UsnJrnl/$LogFile analysis and super-timeline (Plaso) methodology.
- Plaso/log2timeline docs — https://plaso.readthedocs.io/ (super-timeline creation, `psort`).
- Microsoft Learn — NTFS Master File Table, $STANDARD_INFORMATION/$FILE_NAME attributes, USN Change Journal reason codes.
