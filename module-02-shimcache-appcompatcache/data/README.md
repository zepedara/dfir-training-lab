# Module 2 — data provenance

## Files
- `SYSTEM` — the real Windows `SYSTEM` registry hive (contains the ShimCache / AppCompatCache).
- `SYSTEM.LOG1`, `SYSTEM.LOG2` — the hive's registry **transaction logs**. They hold the most-recent, not-yet-flushed changes; the parser replays them so a "dirty" hive is read correctly. (Always collect these alongside a hive.)
- `shimcache.csv` — a **pre-parsed copy** of the ShimCache (AppCompatCacheParser output: `ControlSet, CacheEntryPosition, Path, LastModifiedTimeUTC, Executed, Duplicate, SourceFile`), committed so the module can be read/sorted without running the container. 266 entries.

## Origin / scenario
From the desktop **`DESKTOP-SDN1RPT`** of the **DFIR Madness "Case 001 — The Stolen Szechuan Sauce"** dataset (users `mortysmith`, `administrator`). The same host worked in Modules 1, 3, and 4. Teaching point in this hive: the Win10 `Executed` column reads `No` for every row (unreliable on Win10/11), and the case malware `coreupdater.exe` is **absent** from ShimCache — a deliberate Triad-gap lesson.

## Source / license
- DFIR Madness, "The Stolen Szechuan Sauce" (Case 001): https://dfirmadness.com/the-stolen-szechuan-sauce/
- Education/defensive use only; respect the original author's terms.

## How it was produced
`shimcache.csv` was generated in the lab with:
`AppCompatCacheParser -f /data/SYSTEM --csv /data --csvf shimcache.csv`
(the tool auto-replays `SYSTEM.LOG1/.LOG2`).
