# Module 25 data — provenance

**Inert technique-demonstration dataset.** Generated on an **isolated 64 MB scratch NTFS VHD** driven through one clean narrative — **no code, marker strings only.**

## The narrative (build time)
1. Created `case\report.txt`, `case\notes.txt`, `case\temp.log` (each a plain marker string).
2. Renamed `report.txt` → `report_final.txt`.
3. Added an Alternate Data Stream `notes.txt:hidden` (marker string).
4. Deleted `temp.log`.
5. Detached the VHD; carved the **`$LogFile`** (`$MFT` inode 2) and **`$MFT`** (inode 0) with The Sleuth Kit (`icat -o 128 …`).
6. Decoded the `$LogFile` with **LogFileParser** (Joakim Schicht) at build time.

## Files shipped
- **`LogFile.bin`** — the raw carved `$LogFile` stream (2 MB). Lets you re-run LogFileParser yourself.
- **`LogFile_FileNames.csv`** — filename↔MFT-reference history LogFileParser rebuilt.
- **`LogFile_transactions.csv`** — decoded redo/undo transactions (pipe-`|`-delimited), filtered to the narrative files so the lesson stays focused.
- **`MFT`** — the `$MFT` from the same volume for cross-reference.

Everything is **filesystem metadata** — names, timestamps, and transaction opcodes. Nothing executes. The generation script `build-logfile-narrative.ps1` accompanies the module. LogFileParser is GPL (<https://github.com/jschicht/LogFileParser>); we ship only its CSV output plus the inert `$LogFile` it parsed.
