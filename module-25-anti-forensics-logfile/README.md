# Module 25 — Anti-Forensics: `$LogFile` Transaction Analysis

> **Track:** Anti-Forensics (FOR508.5). **Prereqs:** Module 15 (NTFS internals, `$MFT`, `$UsnJrnl:$J`). **Tool:** LogFileParser (Joakim Schicht) — its output ships pre-parsed; see §3.
> **You'll learn:** how to read NTFS's low-level **transaction journal** (`$LogFile`, `$MFT` record 2) to reconstruct exactly *what operation* the filesystem performed — create, rename, ADS-write, delete — from the **redo/undo opcodes**, at a finer grain than `$UsnJrnl` and often when nothing else survives.

---

## 1. Two journals, two altitudes

Module 15 introduced NTFS's two journals. This module lives in the deeper one.

- **`$UsnJrnl:$J`** (Module 15) is the **high-level change journal**: one summary record per change — *"file X was renamed"* — with a reason code. It keeps **days** of history.
- **`$LogFile`** (this module) is the **low-level transaction journal**. NTFS is a *recoverable* filesystem: before it commits any metadata change to disk, it writes a transaction with a **redo** operation (roll the change forward) and an **undo** (roll it back), so a crash mid-write can be repaired. Because it operates at the very bottom, **one logical action becomes several `$LogFile` opcodes** touching the `$MFT`, the directory index (`$I30`), and the `$Bitmap`. It is **circular and small** (64 MB default) so it **wraps in minutes-to-hours** — but while in window, it is the **most authoritative, operation-level** reconstruction of recent activity that NTFS holds.

> **Why an examiner cares.** The `$UsnJrnl` tells you *that* a file was renamed; the `$LogFile` shows you the exact index and MFT operations that performed it — which lets you separate a **rename** from a **move** from a **new-file-with-old-name**, reconstruct the **name and datarun** of a file whose `$MFT` record was already reused, and catch anti-forensic activity in the seconds before it wrapped. The opcode grammar is the point.
>
> **ATT&CK:** deletion/anti-forensics maps to **T1070.004 (Indicator Removal: File Deletion)** — the `$LogFile` is the *forensic counter* to it, not an ATT&CK-listed log source.

---

## 2. The opcode → action grammar

Every filesystem action decomposes into a fixed set of `$LogFile` **redo opcodes**. The four you must know:

| Action | `$LogFile` redo opcodes | `$UsnJrnl` reason it corresponds to |
|---|---|---|
| **Create a file** | `InitializeFileRecordSegment` (new `$MFT` record) + `AddIndexEntryRoot`/`AddIndexEntryAllocation` (name into parent index) | `FileCreate` |
| **Rename** | `DeleteIndexEntryRoot` (old name) + `CreateAttribute`/`UpdateFileNameRoot` + `AddIndexEntryRoot` (new name) — **same MFT entry** | `RenameOldName` + `RenameNewName` |
| **Create an ADS** | `CreateAttribute` (a second, named `$DATA` attribute) | `StreamChange` / `NamedDataExtend` |
| **Delete a file** | `DeleteIndexEntryRoot` (or `…Allocation` for a large directory — name out of parent) + `DeallocateFileRecordSegment` (release the `$MFT` record) | `FileDelete` |

Data writes appear as `UpdateResidentValue` / `UpdateNonResidentValue`. (Opcode *names* come from Schicht's reverse-engineered decoder, the community standard — they are not Microsoft-documented.)

---

## 3. The evidence in this module

Everything in `data/` is **inert** — generated on an isolated scratch NTFS volume driven through one clean narrative (create three files → rename one → add an ADS → delete one), with **marker strings only, no code**. See `data/README.md` for provenance. What ships:

- **`LogFile_FileNames.csv`** — the filename history LogFileParser rebuilt from the transactions (name ↔ `$MFT` reference).
- **`LogFile_transactions.csv`** — the decoded transactions (redo/undo opcode per row), filtered to the narrative files. **Pipe-`|`-delimited** (LogFileParser's default): field 2 = MFT reference, field 10 = redo operation, field 13 = filename.
- **`LogFile.bin`** — the raw carved `$LogFile` stream, so you can re-run the parser yourself (see below).
- **`MFT`** — the `$MFT` from the same volume, for cross-reference.

> **How the CSVs were produced (reference — not run by the validator).** The raw `$LogFile` was parsed with Joakim Schicht's **LogFileParser** in command-line mode:
> ```
> LogFileParser64.exe /LogFileFile:LogFile.bin /OutputPath:out /CleanUp:1
> ```
> which emits `out\LogFile_<timestamp>\LogFile.csv`, `LogFile_FileNames.csv`, and ~20 companion tables. We ship the decoded output so the analysis below is tool-independent; advanced students can install LogFileParser (<https://github.com/jschicht/LogFileParser>) and reproduce it from `LogFile.bin`.

---

## 4. Setup

```bash
cd module-25-anti-forensics-logfile/data
```

---

## 5. Step-by-step walkthrough

### Step 1 — Read the filename history: spot the rename

```bash
cat LogFile_FileNames.csv
```

**Read it:** each row is a filename LogFileParser recovered from a transaction, with its **`$MFT` reference**. Note that **`report.txt` and `report_final.txt` share the same MFT reference (39)** — that is the signature of a **rename**: one file record, two names over its life. `notes.txt` (40) and `temp.log` (41) each appear once.

### Step 2 — See the opcodes behind each operation

Print MFT-reference, redo-opcode, and filename for the narrative files (fields 2, 10, 13):

```bash
cut -d'|' -f2,10,13 LogFile_transactions.csv | grep -iE 'report|notes|temp' | head -25
```

**Read it — the create.** `report.txt`, `notes.txt`, and `temp.log` each show **`InitializeFileRecordSegment`** (a fresh `$MFT` record is born) followed by **`AddIndexEntryRoot`** (its name is inserted into the `case` directory's index) and `UpdateResidentValue` (its small content written *resident* inside the record). That triple **is** "a file was created."

### Step 3 — Dissect the rename

Still in that output, follow **MFT entry 39**: after the create, you see **`DeleteIndexEntryRoot` (report.txt)** → **`CreateAttribute` / `AddIndexEntryRoot` (report_final.txt)**. The old name is removed from the directory index and the new name added, **against the same MFT record** — no new file is created. That opcode pair distinguishes a **rename** (same MFT ref, new name) from a **move** (same, plus a changed parent reference) from a genuinely new file (`InitializeFileRecordSegment`).

### Step 4 — Catch the Alternate Data Stream

```bash
grep -i CreateAttribute LogFile_transactions.csv | cut -d'|' -f2,10,13 | head
```

**Read it:** entry **40 (`notes.txt`)** carries a **`CreateAttribute`** transaction — that is the **`:hidden` ADS** being attached as a second named `$DATA` attribute (Module 15's hiding/execution vector). The `$LogFile` recorded the stream's creation even though Explorer never shows it. Note `CreateAttribute` **also** fires for the Step-3 rename (it rewrote entry 39's `$FILE_NAME`), so this filter returns entry 39 as well — the ADS is the **entry-40** row.

### Step 5 — Prove the deletion

```bash
grep -iE 'DeallocateFileRecordSegment|DeleteIndexEntryRoot' LogFile_transactions.csv | cut -d'|' -f2,10,13 | head
```

**Read it:** entry **41 (`temp.log`)** shows **`DeleteIndexEntryRoot`** (name pulled from the parent index) then **`DeallocateFileRecordSegment`** (the `$MFT` record marked free). That is a deletion captured at the transaction level — and because the record includes the filename and the redo/undo data, the deletion is reconstructable even after the `$MFT` slot is later reused.

### Step 6 — The whole story at a glance

```bash
cut -d'|' -f10 LogFile_transactions.csv | tail -n +2 | sort | uniq -c | sort -rn | head
```

**Read it:** the opcode census — `InitializeFileRecordSegment` (creates), `AddIndexEntryRoot`/`DeleteIndexEntryRoot` (index churn from creates/renames/deletes), `CreateAttribute` (ADS + rename), `DeallocateFileRecordSegment` (the delete). From opcodes alone you can narrate every filesystem event on this volume in the log's window.

---

## 6. Try it yourself

1. **Rename vs new file.** Using `LogFile_FileNames.csv`, explain the single piece of evidence that proves `report_final.txt` is a *rename* of `report.txt` and not a new file that happens to share a name.
2. **Name the opcode.** Which redo opcode marks the *birth* of a new `$MFT` record, and which marks its *release* on deletion?
3. **Find the ADS.** Write the command that isolates the ADS-creation transaction, and state which file it was attached to.
4. **Correlate up a level.** For each opcode in Step 6, name the `$UsnJrnl` reason code (Module 15) it corresponds to. Why does the `$LogFile` show *more* rows per action than `$UsnJrnl`?

---

## 7. Key takeaways

- **`$LogFile` is NTFS's transaction journal** — redo/undo opcodes written *before* every metadata change, so a crash can be repaired. It wraps in **minutes-to-hours**: perishable, so collect it early.
- **One action = several opcodes.** Create = `InitializeFileRecordSegment` + `AddIndexEntryRoot`; rename = `DeleteIndexEntryRoot` + `AddIndexEntryRoot` on the *same* MFT entry; ADS = `CreateAttribute`; delete = `DeallocateFileRecordSegment`.
- **It defeats anti-forensics** the `$UsnJrnl` can't: it separates rename/move/new-file, recovers names and dataruns after `$MFT` reuse, and is far harder to forge *consistently*.
- **The skill is reading the opcode grammar** — the tool (LogFileParser) just decodes; you interpret.

---

## 8. Sources

- Joakim Schicht — **LogFileParser** (the `$LogFile` decoder; redo/undo opcodes, `/ReconstructDataruns`): <https://github.com/jschicht/LogFileParser>
- ntfs.com — *NTFS $LogFile / transaction journal* (redo/undo, recoverable filesystem): <http://ntfs.com/transaction.htm>
- dfir.ru — *How the $LogFile works* (opcode patterns in practice): <https://dfir.ru/2019/02/16/how-the-logfile-works/>
- Microsoft — `USN_RECORD_V2` reason codes (the `$UsnJrnl` half of the correlation): <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2>
- MITRE ATT&CK — **T1070.004 Indicator Removal: File Deletion**: <https://attack.mitre.org/techniques/T1070/004/>
- **MFTECmd** — Eric Zimmerman (`$MFT` cross-reference): <https://github.com/EricZimmerman/MFTECmd>
