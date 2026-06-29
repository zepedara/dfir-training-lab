# Module 3 — Amcache with AmcacheParser

**Deck mapping:** *Windows Execution Forensics* → "Amcache.hve: The System Inventory" / "Inside the Amcache Hive" / "Extraction with AmcacheParser."
**Goal:** get a rich **inventory** of programs that existed on a host — crucially **with SHA1 hashes** — so you can establish a binary's **identity** and pivot on it (threat-intel lookups, hunting the same file across other machines).

> **Where this fits:** Prefetch said *"it ran"* (Module 1). ShimCache said *"the OS saw it"* (Module 2). Amcache says *"here is exactly what it is"* — the fingerprint that lets you chase one specific file everywhere else.

---

## 1. Background — what Amcache is and why Windows creates it

### The everyday purpose
Windows keeps a background **inventory** of the programs and drivers on a machine — partly for the same application-compatibility system behind ShimCache, partly for telemetry and "Programs & Features"–style bookkeeping. A scheduled task (the **Microsoft Compatibility Appraiser**, `CompatTelRunner.exe`) periodically walks the disk and records metadata about executables it finds. That inventory is stored in a dedicated registry hive:

```
C:\Windows\appcompat\Programs\Amcache.hve
```

A *hive* is a standalone registry-database file. `Amcache.hve` is the **richest** of the three execution artifacts because, unlike ShimCache (path + modify-time only), it records *deep metadata* per file.

### What it stores (the good stuff)
The key subkey is **`InventoryApplicationFile`** — one entry per executable Windows has inventoried. For each, Amcache can hold:

- **Full path** and **file name**.
- **SHA1 hash** of the file (Amcache calls this the **FileID**) — the single most valuable field. A SHA1 is a 40-hex-character fingerprint of the file's exact bytes; two files with the same SHA1 are the same file.
- **File size** (in bytes).
- **LinkDate** — the **compile timestamp** baked into the program's PE header by whoever built it (PE = "Portable Executable", the Windows .exe/.dll format).
- **FileKeyLastWriteTimestamp** — when Amcache last wrote this entry (a rough "first inventoried / first seen" time).
- **ProductName, Version, Description, OriginalFileName, BinaryType** (32- vs 64-bit), **IsOsComponent**, **IsPeFile**, and more.

### Why investigators love it (what you can prove)
Amcache is the **"identity / attribution"** corner of the Triad. The **SHA1** is the prize:

- Drop it into threat intelligence (VirusTotal, internal IOC lists) to confirm a known-bad — *offline-deferred* in this lab, since the lab VM is kept offline (no network).
- **Stack the same SHA1 across every host's Amcache** to find every machine that holds that exact file (the cross-host hunt of Module 4).
- Combine SHA1 + path + size + metadata to spot a binary masquerading as a system file.

### How it works under the hood (and the limits)
1. The **Compatibility Appraiser** task runs on a schedule (and on certain events) and inventories executables into `Amcache.hve`.
2. Because inventorying is **scheduled**, Amcache is **not a real-time execution log.** A file can appear in Amcache because it merely *exists* on disk — **"inventoried" does not mean "executed."** Use Prefetch for the execution claim; use Amcache for *identity and presence*.
3. **The raw SHA1 carries four padding zeros** in the hive (the stored FileID looks like `0000` + the real 40-hex SHA1). **AmcacheParser strips those leading zeros for you**, so the CSV shows a clean, lookup-ready 40-character SHA1. (Good to know if you ever read the raw hive by hand.)
4. **LinkDate is attacker-controllable and often nonsense.** It's whatever value the compiler wrote (or the author faked). In our real data you'll see genuine Microsoft binaries with absurd LinkDates (years like 2049, 2077, 2090) right alongside the malware's fake **2010** date — so **never treat an odd LinkDate alone as suspicious.** It's one weak signal among several.
5. Like other hives, `Amcache.hve` can be **dirty** and ships with **`.LOG1/.LOG2`** transaction logs that the parser replays (same lesson as Module 2: collect the logs).

---

## 2. What the tool does — AmcacheParser

**AmcacheParser** (Eric Zimmerman, an EZ Tool; on the Windows VM at `C:\DFIR\tools`) opens `Amcache.hve`, replays its transaction logs, decodes every subkey, and writes **several CSVs** — one per data category. The ones you care about most:

- **`*_UnassociatedFileEntries.csv`** — inventoried executables **not** tied to an installed program (where lone droppers like `coreupdater.exe` live). **SHA1 lives here.**
- **`*_AssociatedFileEntries.csv`** — executables linked to a known installed program.
- **`*_ProgramEntries.csv`** — installed programs (the "Programs & Features" view).
- Plus device/driver CSVs (`DevicePnps`, `DriveBinaries`, `DriverPackages`, `DeviceContainers`, `ShortCuts`).

The `-i` flag adds the *file entries that are associated with Programs entries* to the output; the **Unassociated** file entries (with SHA1) are produced either way.

**Data for this module (multiple files):**
- `Amcache.hve`, `Amcache.hve.LOG1`, `Amcache.hve.LOG2` — the **real** Amcache hive (+ transaction logs) from **DFIR Madness Case 001** desktop `DESKTOP-SDN1RPT`.
- The **pre-parsed CSV set** is committed too (`amcache_UnassociatedFileEntries.csv`, `amcache_AssociatedFileEntries.csv`, `amcache_ProgramEntries.csv`, and the device CSVs) so you can read the results without running the parser yourself. See `data/README.md` for provenance/licensing. That's one hive + 2 logs + 8 output CSVs — plenty to run multiple commands across.

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-03-amcache-amcacheparser/data        # Amcache.hve, .LOG1, .LOG2, + parsed CSVs
```
(Every command in this module is run **from inside this `data/` folder**; all forensic tools are installed natively and already on your `PATH`, so you call them directly by name — no container, no Docker. See Module 1 §3.)

---

## 4. Step-by-step walkthrough

### Step 1 — Parse the Amcache hive
```bash
AmcacheParser -f Amcache.hve --csv . --csvf amcache.csv -i
```
- `AmcacheParser` — the tool.
- `-f Amcache.hve` — input hive (`.LOG1/.LOG2` beside it are auto-replayed).
- `--csv .` — folder to write the CSVs into.
- `--csvf amcache.csv` — a base name; the tool appends the category to each file (e.g. `amcache_UnassociatedFileEntries.csv`).
- `-i` — **i**nclude file entries associated with Programs entries (richer output). The Unassociated file entries with SHA1 appear regardless.

**Expected output (real, Case 001):**
```
Two transaction logs found. Determining primary log...
At least one transaction log was applied. Sequence numbers have been updated...
Total file entries found: 98
Found 15 unassociated file entry and 83 program file entries (across 85 program entries)
```
**Reading it:** the logs were replayed (dirty hive); **98** executables were inventoried — **15 unassociated** (lone files — our hunting ground) and **83** tied to installed programs.

> **Useful flags:** `--mp` shows higher-precision timestamps; `-b <file>` / `-w <file>` let you *include only* or *exclude* specific SHA1 lists (handy for whitelisting known-good hashes at scale); `--nl` ignores the transaction logs (normally leave it off so they're replayed).

### Step 2 — Pull every executable's identity (name, SHA1, size, path)
The SHA1 lives in the Unassociated CSV. Columns of interest: `SHA1` (4), `FullPath` (6), `Name` (7), `LinkDate` (9), `ProductName` (10), `Size` (11).
```bash
awk -F, 'NR>1{printf "%-22s sha1=%s size=%-8s prod=%s\n", $7, $4, $11, $10}' \
  amcache_UnassociatedFileEntries.csv
```
- `-F,` — split on commas. `NR>1` — skip the header row.
- `printf "%-22s ..."` — print Name, SHA1, Size, ProductName in aligned columns.

**Expected (real, Case 001) — abbreviated:**
```
compattelrunner.exe    sha1=992aaab7...  size=172184   prod=microsoft® windows® operating system
coreupdater.exe        sha1=fd153c66386ca93ec9993d66a84d6f0d129a3a5c  size=7168  prod=
csrss.exe              sha1=69a1dcf6...  size=17592    prod=microsoft® windows® operating system
FTK Imager.exe         sha1=32756b3a...  size=22566752 prod=accessdata® ftk® imager
...
```
**Reading the rows:**
- **SHA1** — the fingerprint. `coreupdater.exe` → `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`. **This is your pivot key** for the rest of the case.
- **ProductName** — genuine Microsoft binaries carry *"Microsoft® Windows® Operating System"*. `coreupdater.exe` has an **empty** ProductName — a dropped binary with no version resources.
- **Size** — `coreupdater.exe` is **7,168 bytes**: tiny for anything claiming to be a System32 program.
- **FTK Imager.exe** on `E:\` — note this is the **examiner's own tool** (a forensic imager run from a USB/evidence drive). Recognising responder activity so you don't chase your own team is a real skill.

### Step 3 — Isolate the suspect and read its full record
```bash
grep -i coreupdater amcache_UnassociatedFileEntries.csv
```
**Expected (real, Case 001):**
```
Unassociated,0006485495bded616c6d407985279849903e0000ffff,2020-09-19 03:40:45,fd153c66386ca93ec9993d66a84d6f0d129a3a5c,False,c:\windows\system32\coreupdater.exe,coreupdater.exe,.exe,2010-04-14 22:06:53,,7168,,,coreupdater.exe|4b283e5048abd88b,pe64_amd64,True,...
```
**Decode it field by field:**
- `FileKeyLastWriteTimestamp = 2020-09-19 03:40:45` — when Amcache inventoried it. **This lines up with the Prefetch run time from Module 1** — the OS noticed it right around when it executed. Strong corroboration.
- `SHA1 = fd153c66386ca93ec9993d66a84d6f0d129a3a5c` — clean 40-hex (the parser stripped the padding zeros).
- `IsOsComponent = False` — Windows itself does **not** consider this an OS file, yet it's sitting in `System32`. Red flag.
- `FullPath = c:\windows\system32\coreupdater.exe` — a System32 location, lending it false legitimacy.
- `LinkDate = 2010-04-14 22:06:53` — a faked-old compile date. (Remember §1.4: by itself weak — genuine MS files here have crazier dates — but combined with everything else it fits a planted binary.)
- `ProductName / Version = (empty)` — no version resources, unlike every real System32 binary.
- `Size = 7168`, `BinaryType = pe64_amd64`, `IsPeFile = True` — a tiny 64-bit PE.

**The case against `coreupdater.exe`** isn't any one field — it's the **stack of them**: System32 path + `IsOsComponent=False` + empty ProductName/Version + 7 KB size + inventory time matching its execution. That convergence is what makes it the malware.

### Step 4 — Extract all SHA1s for the cross-host hunt
```bash
awk -F, 'NR>1 && $4!="" {print $4"  "$7}' amcache_UnassociatedFileEntries.csv | sort
```
- Prints `SHA1  Name` for every entry that has a hash, sorted. This is the list you'd carry into threat-intel and into Module 4's multi-host stacking. In a real case you'd feed `fd153c66…` to your IOC platform and to every other host's Amcache.

### Step 5 — Glance at the installed-programs view (context)
```bash
awk -F, 'NR>1{print $3" | "$5}' amcache_ProgramEntries.csv | head
```
- Columns here are different (this is `ProgramEntries.csv`): `Name` (3) and `Publisher` (5). This shows the machine's installed-software picture — useful context for "what is this box and who used it," and for spotting software that shouldn't be there.

---

## 5. Reading the output — benign vs suspicious

| Field | Means | Benign | Suspicious |
|---|---|---|---|
| **SHA1** | file fingerprint | matches known-good MS hashes | matches a known-bad list / appears on very few hosts |
| **FullPath + IsOsComponent** | location + "is this an OS file?" | System32 file with `IsOsComponent=True` | System32 path but `IsOsComponent=False` (masquerade) |
| **ProductName / Version** | version resources | filled, consistent vendor strings | empty on something posing as a system tool |
| **Size** | bytes | plausible for the program | implausibly tiny/large for what it claims to be |
| **LinkDate** | PE compile time | — | *weak* signal alone; meaningful only with the others |
| **FileKeyLastWriteTimestamp** | inventory/first-seen time | matches install/patch windows | lands exactly in the incident window |

---

## 6. The Triad together (the deck's whole point)

| Question | Tool | Module | `coreupdater.exe` |
|---|---|---|---|
| Did it **run**? when? | Prefetch | 1 | **Yes** — ran on 2020-09-19 |
| Was it **present / seen** by the OS? | ShimCache | 2 | **Absent** — the gap |
| **What is it** (SHA1, metadata)? | Amcache | 3 | **SHA1 `fd153c66…`**, 7 KB, System32, not an OS component |

Each artifact covers the others' blind spots. `coreupdater.exe` is in **Amcache (identity)** and **Prefetch (execution)** but **not ShimCache** — proving that you reach a confident conclusion by *correlating* the Triad, never by trusting one source.

---

## 7. Try-it-yourself exercises

1. **Build the identity card.** Run Step 3 and write a 5-line summary of `coreupdater.exe` (path, SHA1, size, ProductName, inventory time) and list *every* reason it's suspicious. Which single field would you put in a threat-intel lookup?
2. **Spot the responder's tool.** Find `FTK Imager.exe` in the Unassociated CSV. Where is it run from, and why does its presence *not* indicate compromise?
3. **LinkDate humility.** Compare `coreupdater.exe`'s LinkDate to those of `MoUsoCoreWorker.exe`, `SIHClient.exe`, and `winlogon.exe` (Step 2 / the CSV). Are the genuine files' dates sane? What does this teach about using LinkDate as evidence?
4. **Corroborate timing.** Match `coreupdater.exe`'s `FileKeyLastWriteTimestamp` here against its Prefetch last-run time (Module 1). Do they agree? What does agreement add to your confidence?
5. **Prep the hunt.** Run Step 4 to dump all SHA1s. Write the one-sentence hypothesis you'd take into Module 4's cross-host stacking.

---

## 8. Key takeaways

- **Amcache = identity/inventory.** Its **SHA1 (FileID)** is the pivot that lets you confirm known-bad and hunt the same file everywhere.
- **Inventoried ≠ executed.** A scheduled appraiser populates it, so use Prefetch for the execution claim and Amcache for *what the file is* and *that it was present*.
- The raw SHA1 has **4 padding zeros**; AmcacheParser strips them. **LinkDate is fakeable** and often garbage — weight it lightly.
- The verdict on `coreupdater.exe` comes from **converging fields** (System32 path + not-an-OS-component + empty metadata + 7 KB + incident-window inventory), and from its **Triad fingerprint** (Amcache + Prefetch, no ShimCache).

## Sources & further reading
- **AmcacheParser / EZ Tools** (official tool + AboutDFIR manual): https://github.com/EricZimmerman/AmcacheParser and https://aboutdfir.com/toolsandartifacts/windows/eric-zimmermans-tools/
- **The definitive Amcache.hve forensic reference** (every key/value/timestamp): https://www.amcacheparser.com/en/blog/amcache-hve-reference
- **Securelist (Kaspersky) — "AmCache artifact: forensic value and a tool for data extraction"**: https://securelist.com/amcache-forensic-artifact/117622/
- **Yogesh Khatri — "Amcache.hve in Windows 8 — Goldmine for malware hunters"** (origins + the SHA1 detail): https://www.swiftforensics.com/2013/12/amcachehve-in-windows-8-goldmine-for.html
- **Magnet Forensics — "ShimCache vs AmCache"** (how identity vs existence pair up): https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/
- **13Cubed — "ShimCache and AmCache"** (free video): https://www.youtube.com/c/13cubed
- **DFIR Madness — Case 001** (dataset provenance): https://dfirmadness.com/the-stolen-szechuan-sauce/

## Pivot
- The SHA1 → **Module 4 (Scaling)**: stack that hash across many hosts with AppCompatProcessor to find every infected box.

---
*Next: [Module 4 — Scaling the Hunt](../module-04-scaling-appcompatprocessor).*
