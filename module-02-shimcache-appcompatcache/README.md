# Module 2 — ShimCache with AppCompatCacheParser

**Deck mapping:** *Windows Execution Forensics* → "ShimCache: The Compatibility Trace" / "The Volatility of ShimCache" / "Parsing ShimCache."
**Goal:** recover evidence that an executable was **present and seen by the operating system** — even if it never actually ran, and even if it has since been deleted.

> **Reading order:** Module 1 (Prefetch) answered *"did it run?"*. ShimCache answers a different, sometimes more useful question: *"did Windows ever lay eyes on this file at all?"* The two together are stronger than either alone.

---

## 1. Background — what ShimCache is and why Windows creates it

### The everyday purpose
Old programs sometimes break on new versions of Windows. To keep them working, Microsoft built the **Application Compatibility** system: a set of small fixes ("**shims**") that sit between an old program and the OS and quietly translate the things the program expects. A *shim* is just a compatibility patch applied at load time — think of a power-plug adapter for software.

To decide *whether* a given program needs a shim, Windows keeps a small lookup table of executables it has encountered: the **Application Compatibility Cache**, universally nicknamed **ShimCache** (also written **AppCompatCache**). For each executable it notes a few cheap-to-grab facts so it doesn't have to re-evaluate the same file every time.

### Where it lives and what it stores
ShimCache is **not a file** — it lives **inside the Windows registry**, in the `SYSTEM` hive (the registry "hive" is the on-disk database file the registry is built from). The exact key is:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
```

(*HKLM* = "HKEY_LOCAL_MACHINE", the machine-wide branch of the registry. *CurrentControlSet* is a pointer to whichever `ControlSet00x` the machine last booted with.) For each executable it records, in a packed binary blob:

- **Full path** of the executable (e.g. `C:\Windows\System32\wscript.exe`).
- **Last-modified time** of that file — specifically the file's `$StandardInformation` modified timestamp from the filesystem, *not* a run time. (Renaming or recompiling a file changes this; merely running it does not.)
- On older Windows (7/8), an **"executed" flag**; on Windows 10/11 that flag exists in the data but is **unreliable** (see below).

### Why investigators love it (what you can prove)
ShimCache is the **"existence"** corner of the Triad. Its superpower: Windows adds an entry when it merely **evaluates** a file — which can happen when the file is **browsed in Explorer, scanned, or otherwise touched**, not only when it's run. So ShimCache can preserve a record of a malicious tool that:

- was **dropped but never executed**, or
- ran once and was then **deleted** (the registry entry survives the file).

That makes it a favourite for catching staging activity and anti-forensics.

### How it works under the hood (and the three big gotchas)
1. **It builds up in memory while Windows runs**, and is **only written ("flushed") to the `SYSTEM` hive on a clean shutdown/reboot.** Consequence: if you grab a `SYSTEM` hive from a *live* machine, recent activity may not be in it yet. (This is "The Volatility of ShimCache" from the deck.)
2. **The Windows 10/11 "executed" flag is not trustworthy.** On Win7 it meaningfully meant "this ran"; on Win10 it commonly reads `No` even for things that clearly ran (you'll see this in our data — *every* row says `Executed: No`). **Treat ShimCache as proof of *existence/awareness*, never as proof of execution.** Use Prefetch/Amcache for the "did it run" claim.
3. **The cache is ordered roughly most-recent-first and capped** (around **1024** entries on modern Windows). So **CacheEntryPosition 0 = most recently inserted**, giving you a rough relative timeline; and old entries eventually fall off the end (absence ≠ never present).

### The transaction-log detail (don't skip this)
A registry hive that was copied while Windows was still using it is **"dirty"** — some of its most recent changes live in side files called **transaction logs** (`SYSTEM.LOG1`, `SYSTEM.LOG2`) rather than in the main `SYSTEM` file yet. A good parser **replays** those logs to reconstruct the true, latest state. That is why this module ships the `.LOG1/.LOG2` files next to `SYSTEM` — and it's a real lesson: **always collect a hive's `.LOG` files with it.**

---

## 2. What the tool does — AppCompatCacheParser

**AppCompatCacheParser** (Eric Zimmerman, an EZ Tool — on the Windows VM at `C:\DFIR\tools`) reads a `SYSTEM` hive, finds the `AppCompatCache` blob, decodes its binary format (which differs by Windows version), automatically replays the transaction logs if the hive is dirty, and writes a clean CSV: one row per cached executable with its path, last-modified time, cache position, and the (Win10-unreliable) executed flag. It runs identically in the container and on Windows.

**Data for this module (multiple files):**
- `SYSTEM`, `SYSTEM.LOG1`, `SYSTEM.LOG2` — the **real** `SYSTEM` hive (+ its two transaction logs) from the **DFIR Madness Case 001** desktop `DESKTOP-SDN1RPT`. That's already four input files working together (hive + 2 logs), and the hive holds **266** cached executables to triage.
- `shimcache.csv` — a **pre-parsed copy** of the output, committed so you can read/sort the results even without running the container. See `data/README.md` for provenance/licensing.

---

## 3. Setup

```bash
cd module-02-shimcache-appcompatcache/data     # SYSTEM, SYSTEM.LOG1, SYSTEM.LOG2, shimcache.csv
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```
(For what each `docker run` flag means — `-it`, `--rm`, `--network none`, `-v` — see Module 1 §3. Short version: interactive shell, throwaway container, no network, and your `data` folder mounted at `/data`.)

---

## 4. Step-by-step walkthrough

### Step 1 — Parse the ShimCache out of the hive
```bash
AppCompatCacheParser -f /data/SYSTEM --csv /data --csvf shimcache.csv
```
- `AppCompatCacheParser` — the tool.
- `-f /data/SYSTEM` — the input **f**ile: the `SYSTEM` hive. (The tool finds `SYSTEM.LOG1/.LOG2` automatically because they sit beside it.)
- `--csv /data` — the **folder** to drop the CSV report into (here, back into `/data` so it appears in your host folder).
- `--csvf shimcache.csv` — the CSV **f**ilename to use.

**Expected output (real, Case 001):**
```
Two transaction logs found. Determining primary log...
At least one transaction log was applied. Sequence numbers have been updated...
Found 266 cache entries for Windows10C_11 in ControlSet001
```
**Reading it:**
- *"Two transaction logs found … applied"* — the hive was dirty and the tool replayed the `.LOG` files. (If the logs were missing, you'd risk an incomplete or aborted parse — hence we always collect them.)
- *"Found 266 cache entries … Windows10C_11"* — 266 executables were cached; `Windows10C_11` is the detected cache format (Windows 10 Creators+ / 11). Each control set is a saved hardware/driver configuration; the live one is `ControlSet001` here.

> **Handy flags:** add `-t` to sort entries by last-modified time (newest first) instead of cache position, and `-c <n>` to parse only one control set. `--nl` tells the tool to *ignore* transaction logs (use only if you deliberately want the on-disk state) — normally you want the default, which replays them.

### Step 2 — Look at the top of the cache (the recency timeline)
The CSV columns are: `ControlSet, CacheEntryPosition, Path, LastModifiedTimeUTC, Executed, Duplicate, SourceFile`.

```bash
head -13 /data/shimcache.csv | awk -F, '{printf "%-3s %-58s %-20s %s\n",$2,$3,$4,$5}'
```
- `head -13` — first 13 lines (header + the 12 most-recent entries).
- `awk -F, '{printf ...}'` — print the four key columns (cache position, path, last-modified time, executed flag) in aligned fields. (`-F,` sets the comma as the field separator. This container image has no `column` utility, so we format with `awk`.)

**Expected (real, Case 001) — the first few rows:**
```
CacheEntryPosition Path                                                       LastModifiedTimeUTC  Executed
0   C:\Windows\System32\WScript.exe                            2019-12-07 09:09:07  No
1   C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2009.2-0\MpCmdRun.exe 2020-09-18 22:52:47  No
2   C:\Windows\System32\PickerHost.exe                         2019-12-07 09:08:21  No
3   C:\Windows\system32\RAServer.exe                           2019-12-07 09:10:32  No
4   C:\Windows\system32\AppHostRegistrationVerifier.exe        2019-12-07 09:08:21  No
5   C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2009.2-0\NisSrv.exe 2020-09-18 22:52:47  No
6   C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2009.2-0\MsMpEng.exe 2020-09-18 22:52:47  No
7   C:\Windows\TEMP\94A2D383-2409-448F-9E98-6B888EB7D248\MpSigStub.exe 2020-09-18 22:52:47  No
```
**Reading every column:**
- **CacheEntryPosition** — `0` is the **most recently inserted**. Lower number = more recent. This is your relative timeline.
- **Path** — the full path Windows saw. **This is the field you hunt in.** Note `WScript.exe` (the Windows Script Host — a LOLBin) sitting at position 0.
- **LastModifiedTimeUTC** — the file's last-modified time, **not** when it ran. Useful for correlation (does it match Amcache/MFT?), but never read it as an execution time.
- **Executed** — on this Win10 hive it's `No` for **every** row. That is the unreliability in action: do **not** conclude these never ran. (On a Win7 hive this column is meaningful — see the contrast box below.)
- **Duplicate / SourceFile** — whether the entry repeats, and which hive it came from. (These are columns 6-7 of the CSV; the trimmed `awk` view above shows only the four key columns.)

### Step 3 — Hunt for staging-location paths
Attacker tools often live outside the usual `System32`/`Program Files`. Sweep the cache for the classic staging directory names:
```bash
grep -iE 'Temp|AppData|ProgramData|Public|PerfLogs' /data/shimcache.csv | awk -F, '{printf "%-3s %-58s %-20s %s\n",$2,$3,$4,$5}'
```
- `grep -iE` — search, **i**gnoring case, with **E**xtended regex so `|` means "or".
- The pattern matches any path that mentions `Temp`, `AppData`, `ProgramData`, `Public`, or `PerfLogs` — the folders malware tends to stage in. (We match the folder *name* rather than `\Temp\` with backslashes, because a literal backslash in a shell regex is fiddly to type; the trade-off is you may catch the word inside a longer name, which is fine for a first-pass sweep.)

**Read it:** in this real hive the hits are **benign-but-instructive** — e.g. `C:\Windows\TEMP\...\MpSigStub.exe` and `...\Windows Defender\platform\...` (Microsoft Defender updating itself) and a user's `AppData\...\OneDrive\FileSyncConfig.exe`. **This teaches the most important ShimCache skill: a staging *path* is a lead, not a verdict.** You must then check the binary's name, metadata, and whether it shows up in Prefetch/Amcache. Legitimate software uses these folders constantly; you're looking for the *odd* tenant, not every tenant.

### Step 4 — The Triad gap: find what ShimCache *didn't* catch
Here's the teaching payoff. The Case 001 malware is `coreupdater.exe`. Ask whether ShimCache saw it:
```bash
grep -i coreupdater /data/shimcache.csv ; echo "exit=$? (1 = no match)"
```
- `grep -i coreupdater` — case-insensitive search for the name.
- `echo "exit=$?"` — print grep's exit status; `$?` is the last command's result. `1` means **no match found**.

**Result: nothing — `coreupdater.exe` is NOT in ShimCache.** Yet you proved in Module 1 that it **ran** (Prefetch), and in Module 3 you'll find its **SHA1** (Amcache). A binary that ran and was inventoried but never landed in ShimCache is a textbook **Triad gap**: each artifact has blind spots, which is exactly why you correlate all three. (Mechanism: ShimCache only records files Windows *evaluated for compatibility*; a binary dropped straight into System32 and executed may never trigger that evaluation before the next shutdown flush.)

### Step 5 — (Optional) compare against a Win7-style cache to see the "Executed" flag work
On a **Windows 7** `SYSTEM` hive, the same tool fills the **Executed** column with real `Yes`/`No` values, because Win7's ShimCache format reliably recorded execution. That is the difference the deck calls out: *trust the flag on Win7-era systems, distrust it on Win10/11.* If you ever parse a Win7 hive you'll see rows like `...\TrustedInstaller.exe ... Yes` — on our Win10 hive that same column is uniformly `No`. Always check the detected format line (`Windows10C_11` vs `Windows7x86`) before you trust the flag.

---

## 5. Reading the output — benign vs suspicious

| Column | Means | Benign | Suspicious |
|---|---|---|---|
| **CacheEntryPosition** | recency (0 = newest) | system files near the top after a reboot | an unknown binary near position 0, right after the incident |
| **Path** | where Windows saw the file | `System32`, `Program Files`, known app folders | random-named exe in `Temp`/`Public`/`ProgramData`, or a System32 name in the wrong folder |
| **LastModifiedTimeUTC** | file's modify time (NOT run time) | matches install/patch dates | a "system" binary with a brand-new or future-dated modify time (possible timestomp) |
| **Executed** | Win7: reliable; Win10: ignore | — | only meaningful on Win7-era hives |

**Cross-artifact instinct:** path in ShimCache but **also** in Prefetch (Module 1) = seen *and* ran. In ShimCache but **not** Prefetch = seen, maybe never run (dropped/staged). In Prefetch/Amcache but **not** ShimCache (like `coreupdater`) = the gap that proves you must use all three.

---

## 6. Investigative narrative (Case 001)

The desktop `DESKTOP-SDN1RPT` (users `mortysmith` and `administrator` — the case is *Rick-and-Morty* themed) shows a normal Windows footprint in ShimCache: Defender components, OneDrive, Windows Update staging in `Temp`. The instructive twist is what's **absent**: the malware `coreupdater.exe` ran on this box (Prefetch) and is inventoried with a SHA1 (Amcache), yet **left no ShimCache entry**. ShimCache's lesson here is humility — it's powerful for proving *a file existed and was seen even if deleted*, but its silence about `coreupdater` shows why you never rely on one artifact. It is the **"existence"** corner that fills Prefetch's and Amcache's gaps — and sometimes has gaps of its own.

---

## 7. Try-it-yourself exercises

1. **Top of the cache.** Run Step 2. List the 10 most recently inserted executables. Which is a LOLBin (hint: a script host sits at position 0)? Why might it be near the top?
2. **Staging sweep.** Run Step 3. For each `Temp`/`AppData` hit, decide benign vs suspicious and say *why* (who owns the folder, what's the file name, is it a known Microsoft component?).
3. **Prove the gap.** Run Step 4. Confirm `coreupdater.exe` is absent here, then state — in one sentence using the Triad idea — what its absence from ShimCache does and doesn't tell you.
4. **Cross-check a modify time.** Pick any entry's `LastModifiedTimeUTC` and compare it to the same binary's time in Amcache (Module 3). Do they agree? What would a mismatch suggest?
5. **Why the logs matter.** Re-run Step 1 with `--nl` added (ignore transaction logs). Does the entry count change? Explain what `--nl` did and why the default (replaying logs) is usually what you want.

---

## 8. Key takeaways

- **ShimCache = existence/awareness, not execution.** Windows caches files it *evaluates for compatibility*, which can include files merely browsed — and the Win10 "executed" flag is unreliable.
- It lives **in the `SYSTEM` registry hive** and is **flushed only on shutdown**; a live grab can lag. **Always collect `SYSTEM.LOG1/.LOG2`** so the parser can replay them.
- **CacheEntryPosition 0 = most recent**; the cache is capped (~1024), so absence can mean "aged out."
- It can preserve a record of a **deleted** tool — great for staging/anti-forensics hunts — but it also has gaps (`coreupdater` isn't here), which is the whole argument for the Triad.

## Sources & further reading
- **AppCompatCacheParser / EZ Tools** (official tool + AboutDFIR manual): https://github.com/EricZimmerman/AppCompatCacheParser and https://aboutdfir.com/toolsandartifacts/windows/eric-zimmermans-tools/
- **Mandiant — "Caching Out: The Value of Shimcache for Investigators"** (the foundational paper on ShimCache forensics): https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-value-of-shimcache-for-investigators/
- **Magnet Forensics — "ShimCache vs AmCache: Key Windows Forensic Artifacts"** (how the two differ and pair): https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/
- **SANS DFIR — Windows Forensic Analysis poster** (where ShimCache sits among execution artifacts): https://www.sans.org/posters/windows-forensic-analysis/
- **13Cubed — "ShimCache and AmCache" episode** (free video walkthrough): https://www.youtube.com/c/13cubed
- **DFIR Madness — Case 001** (dataset provenance): https://dfirmadness.com/the-stolen-szechuan-sauce/

## Pivot
- A suspicious path here → **Module 1** (did it run?) and **Module 3** (what's its SHA1?). To hunt one binary across many hosts → **Module 4**.

---
*Next: [Module 3 — Amcache](../module-03-amcache-amcacheparser).*
