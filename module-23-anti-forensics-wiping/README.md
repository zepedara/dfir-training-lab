# Module 23 — Anti-Forensics: File-Wiping Tool Marks

> **Track:** Anti-Forensics (FOR508.5). **Prereqns:** Module 15 (NTFS internals, `$MFT`, `$UsnJrnl:$J`). **Tool:** `MFTECmd`.
> **You'll learn:** why *secure-deletion* tools are loud, not quiet — how **SDelete**, **cipher /w**, **Eraser**, and **BCWipe** each leave a distinctive fingerprint in the NTFS change journal and the `$MFT`, and how to **recover the name of a file that was securely wiped** even though its contents are gone.

---

## 1. Why wiping tools betray themselves

An attacker who *deletes* a file leaves the data sitting in unallocated clusters (Module 15 recovered exactly that). So a careful adversary reaches for a **secure-deletion / wiping tool** that *overwrites* the data before releasing it. That destroys the file **contents** — but it does **not** destroy the **record of the act**.

The reason is structural. To overwrite and remove a file, a wiper must *rename it, overwrite it, and delete it* — and every one of those operations is a filesystem transaction that NTFS dutifully records in the **`$UsnJrnl:$J` change journal** and the **`$LogFile`**, **before** and **independently of** the data being destroyed. The journal record carries the **name, the parent directory, the timestamp, and the reason** for each change. Worse for the attacker, each wiper performs its overwrite in a *characteristic pattern* — a fixed number of renames, a signature temp folder — that acts as a **tool-mark**: not just "a file was wiped here," but "**this specific tool** wiped it, at this time, and here is its original name."

> **The lesson of this module:** wiping destroys *content*, not *evidence of wiping*. The journal outlives the file. Absence of the file is not absence of the story.
>
> **ATT&CK:** file wiping maps to **T1070.004 (Indicator Removal: File Deletion)** — SDelete is catalogued as software **S0195** — and, at scale, **T1485 (Data Destruction)**.

---

## 2. The four wipers and their fingerprints

| Tool | Availability | The tell you look for |
|---|---|---|
| **SDelete** (Sysinternals) | free, Microsoft-signed | **renames the target 26 times** — `AAA.AAA` → `BBB.BBB` → … → `ZZZ.ZZZ` — then overwrites and deletes. The **first rename still carries the original name.** |
| **cipher /w** (built-in Windows) | built in | wipes **free space**; creates a temp folder **`EFSTMPWP`** at the volume root filled with **`fil<hex>.tmp`** and **`<n>.E`** files. The folder can persist as a durable IOC. |
| **Eraser** (open source) | free | **7 renames by default**; zeroes timestamps to **1601-01-01**; frequently leaves the `Zone.Identifier` ADS and `$I30` slack intact. |
| **BCWipe** (Jetico) | licensed | hidden **`~BCWipe.tmp`**, **`SECRET.txt!!!`** fill files, a **`BCW-DIR-NODES`** folder — yet the **original name still leaks** into `$UsnJrnl`/`$LogFile`. |

This module gives you **real, inert artifacts** from an **SDelete + cipher /w** run so you can find those marks yourself; Eraser and BCWipe are covered as **recognition** cases (their signatures are listed above and in §6 so you know them on sight).

> **Sources.** SDelete's 26-rename `AAA.AAA` behaviour and one-pass default are documented by Microsoft (<https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete>); the `$J` reason-code chain and name recovery are from inversecos (<https://www.inversecos.com/2022/09/forensic-detection-of-files-deleted-via.html>). `cipher /w` free-space semantics are Microsoft-documented (<https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher>); the `EFSTMPWP` / `fil*.tmp` IOC is corroborated by DFIR practitioners (<https://www.cyberengage.org/post/every-forensic-investigator-should-know-these-common-antiforensic-wipers>). Eraser and BCWipe marks from the same DFIR roundup. ATT&CK **T1070.004** (<https://attack.mitre.org/techniques/T1070/004/>), **T1485** (<https://attack.mitre.org/techniques/T1485/>).

---

## 3. The evidence in this module

Everything in `data/` was generated on an **isolated scratch NTFS volume** and is **completely inert** — the decoy files held only benign marker strings (no code), and what ships is pure filesystem **metadata**. See `data/README.md` for the exact provenance. Two artifacts:

- **`UsnJrnl_J`** — the raw `$J` change-journal stream carved from the scratch volume with `icat` (the same technique you used for the `$MFT` in Module 15). It captured the full wipe: a file secure-deleted with **SDelete**, then a **cipher /w** free-space wipe.
- **`MFT`** — the `$MFT` from the same volume, so you can see the surviving directory records for the wiped artifacts.

You analyse both with **MFTECmd**, exactly as in Module 15 — no new tool to learn.

---

## 4. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-23-anti-forensics-wiping/data
```

(Every command runs **offline**, from inside this `data/` folder. `MFTECmd` is native and already on your `PATH`.)

---

## 5. Step-by-step walkthrough

### Step 1 — Parse the change journal

```bash
MFTECmd -f UsnJrnl_J --csv . --csvf usn.csv
```

MFTECmd auto-detects the `$J` stream and flattens every USN record into `usn.csv`: one row per change, each with a **Name**, **EntryNumber** (the file's `$MFT` record), **ParentEntryNumber**, **UpdateTimestamp**, and a **UpdateReasons** set (`FileCreate`, `RenameOldName`, `RenameNewName`, `DataOverwrite`, `FileDelete`, `Close`, …).

### Step 2 — Spot the SDelete signature: 26 renames

A normal file rename is **one** `RenameOldName`+`RenameNewName` pair. SDelete renames the target **26 times in a row**. Count the rename records:

```bash
grep -c RenameOldName usn.csv
```

**26** — one rename for every letter of the alphabet. A single file renamed 26 times is not normal user or program activity; it is the SDelete overwrite-the-name loop. (Each rename also emits a `RenameNewName` and a closing `RenameNewName|Close`, so `grep -c RenameNewName` shows ~52 records for the same 26 operations — the `RenameOldName` count is the clean signature.) Now look at the **sequence** of names (column 1 = Name, column 10 = UpdateReasons):

```bash
cut -d, -f1,10 usn.csv | grep -i rename | head -20
```

**Read it:** the names climb `AAAAAAAAAAAA.AAA` → `BBBBBBBBBBBB.BBB` → `CCC…` — each character of the filename replaced by the next letter of the alphabet, all the way to `ZZZ…ZZZ`. That monotonic alphabetic march is the **SDelete tool-mark**: no human or normal program renames a file 26 times through the alphabet.

### Step 3 — Recover the wiped file's original name

SDelete overwrites the *content* and the *name in the directory*, but the journal already recorded the name **before** the first rename. The very first `RenameOldName` still holds it:

```bash
cut -d, -f1,10 usn.csv | grep RenameOldName | head -1
```

**Read it:** the original name is **`secret_plans.txt`** — recovered in full from a file whose data no longer exists on disk. That is the payoff: *you can tell an examiner what the attacker destroyed, by name.*

### Step 4 — Spot the cipher /w signature: the EFSTMPWP folder

`cipher /w` doesn't target one file — it fills **free space** to overwrite previously-deleted data. To do that it creates a temp folder at the volume root and floods it with fill files. Surface them in the journal:

```bash
grep -iE 'EFSTMPWP|fil.*\.tmp|[0-9]\.E' usn.csv | cut -d, -f1,10 | head -20
```

**Read it:** an **`EFSTMPWP`** folder is created, then filled with **`fil<hex>.tmp`** files and **`<n>.E`** files (`0.E`, `1.E`, …). That folder name is a reliable **cipher /w** indicator — and because it is left at the volume root, it frequently **persists on disk** as a standing IOC long after the wipe.

### Step 5 — Confirm on-disk in the `$MFT`

The journal shows the *actions*; the `$MFT` shows the *surviving records*. Parse it and look for the fill folder:

```bash
MFTECmd -f MFT --csv . --csvf mft.csv
```

```bash
grep -iE 'EFSTMPWP|fil.*\.tmp|[0-9]\.E' mft.csv | cut -d, -f3,6,7 | head -20
```

**Read it:** the columns are **`InUse`, `ParentPath`, `FileName`**. The **`EFSTMPWP`** directory (`InUse=True`, sitting at the volume root `.`) and its fill files (`fil<hex>.tmp` and `<n>.E`, parented under `.\EFSTMPWP`) all appear as `$MFT` records — the fill files marked **`InUse=False`** because they were deleted at the end of the wipe, but their **records survive** with names and timestamps, pinning **when** the `cipher /w` ran. Even after the tool "cleaned up," the metadata remained.

---

## 6. Recognising Eraser and BCWipe (no hands-on)

You won't always face SDelete. Two more you must recognise on sight:

- **Eraser** (open source): renames the file **7 times** by default, then overwrites its `$SI`/`$FN` timestamps to the NTFS epoch **`1601-01-01`** (a giant red flag in any timeline). It is *sloppier* than SDelete — it often fails to clear the **`$I30` directory-index slack** (so the deleted name survives there — Module 15's recovery still works) and leaves the **`Zone.Identifier`** ADS intact, leaking where the wiped file was downloaded from.
- **BCWipe** (licensed): scrubs metadata aggressively — a hidden **`~BCWipe.tmp`** folder, **`SECRET.txt!!!`** fill files, and a **`BCW-DIR-NODES`** folder of renamed `dir1`/`dir2` nodes to overwrite the parent index — yet, like every wiper, the **raw original name still leaks** into `$UsnJrnl:$J` and `$LogFile` before the scrub, and residual markers (`LOGFILEWIPER`, `SWP_INSBCB.tmp`) remain.

The through-line: **every wiper must transact through NTFS to do its job, and NTFS journals the transaction before the data dies.**

---

## 7. Defensive countermeasures

- **Enlarge and forward the journals.** Grow `$UsnJrnl` from its 32 MB default (`fsutil usn createjournal m=... a=...`) so the wipe record survives days-to-weeks, and forward filesystem-audit / Sysmon **FileDelete (event 23/26)** telemetry off-host so it outlives a local wipe.
- **Alert on wiper tool-marks.** A burst of ≥26 renames on one `EntryNumber`, an `EFSTMPWP` folder, `~BCWipe.tmp`, or `1601-01-01` timestamps are all high-fidelity detections.
- **Watch for the tools themselves.** SDelete/cipher/Eraser leave prefetch, `$MFT` create records, and (for downloaded wipers) a `Zone.Identifier` MotW stream — hunt the wiper's *own* footprint, not just its output.

---

## 8. Try it yourself

1. **Prove the count.** How many `RenameOldName` records does the SDelete wipe produce, and why is that number (not 25 or 27) the signature? (Hint: A–Z.)
2. **Name the victim.** Using only `usn.csv`, write the one command that recovers the wiped file's original name, and explain *why* the journal still has it after a secure delete.
3. **Two tools, one journal.** The journal contains **both** an SDelete run and a `cipher /w` run. Give the single most distinctive marker of each, and state which one wiped a *named file* versus *free space*.
4. **Timeline the wipe.** From `mft.csv`, find the `EFSTMPWP` records and state what their timestamps tell you about *when* the anti-forensics happened relative to the intrusion.

---

## 9. Key takeaways

- **Secure-deletion tools destroy content, not the record of deletion.** The `$UsnJrnl:$J` and `$LogFile` capture the rename/overwrite/delete transactions *before* the data dies — and the records **outlive the file**.
- **Each wiper has a tool-mark.** SDelete = **26 alphabetic renames**; cipher /w = the **`EFSTMPWP`** folder + `fil*.tmp`/`*.E`; Eraser = **7 renames + 1601 timestamps**; BCWipe = **`~BCWipe.tmp`/`BCW-DIR-NODES`**.
- **You can recover the wiped file's name** from the first `RenameOldName` even when its contents are unrecoverable.
- **Analysis is just Module 15's toolkit** — `MFTECmd` on `$J` and `$MFT` — pointed at an anti-forensic act.

---

## 10. Sources

- Microsoft / Sysinternals — **SDelete** (26-rename `AAA.AAA` behaviour, one-pass default, DoD 5220.22-M): <https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete>
- Microsoft — **cipher** (`/w` free-space wipe): <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher>
- inversecos — *Forensic detection of files deleted with SDelete* (the `$J` reason-code chain + name recovery): <https://www.inversecos.com/2022/09/forensic-detection-of-files-deleted-via.html>
- cyberengage.org — *Common anti-forensic wipers* (EFSTMPWP, Eraser 7-rename/1601, BCWipe marks): <https://www.cyberengage.org/post/every-forensic-investigator-should-know-these-common-antiforensic-wipers>
- MITRE ATT&CK — **T1070.004 Indicator Removal: File Deletion** (SDelete = S0195): <https://attack.mitre.org/techniques/T1070/004/> · **T1485 Data Destruction**: <https://attack.mitre.org/techniques/T1485/>
- **MFTECmd** — Eric Zimmerman (`$MFT`/`$J` parser): <https://github.com/EricZimmerman/MFTECmd>
