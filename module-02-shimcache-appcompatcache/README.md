# Module 2 — ShimCache with AppCompatCacheParser

**Deck mapping:** *Windows Execution Forensics* → "ShimCache: The Compatibility Trace" / "The Volatility of ShimCache" / "Parsing ShimCache."
**Goal:** recover evidence that an executable was **present/seen by the OS** — even if it never ran and even if it's now deleted.

---

## Concept (from the deck)
The Application Compatibility Cache (**ShimCache**, a.k.a. AppCompatCache) lives in the **`SYSTEM`** registry hive. Windows records executables it evaluates for compatibility, storing the **full path** and **file's last-modified time**. Key deck points:
- It's **existence**, not proof of execution (on Win10 the "executed" flag is unreliable — *"The Volatility of ShimCache"*).
- **It only flushes to the hive on shutdown** — so a live-triage `SYSTEM` may lag; the transaction logs help.
- Order in the cache is roughly most-recent-first → useful relative timeline.

**Data:** the real `SYSTEM` hive (+ its `.LOG1/.LOG2` transaction logs) from Case 001.

---

## Setup
```bash
cd module-02-shimcache-appcompatcache/data     # SYSTEM, SYSTEM.LOG1, SYSTEM.LOG2
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

## Step — Parse ShimCache
```bash
AppCompatCacheParser -f /data/SYSTEM --csv /data --csvf shimcache.csv
```
**Expected output (real, Case 001):**
```
Found 266 cache entries for Windows10C_11 in ControlSet001
```
> The tool **auto-replays the transaction logs** (you'll see *"Two transaction logs found"*) — that's why we extracted `SYSTEM.LOG1/.LOG2` alongside the hive. Without them a *dirty* hive aborts. (This is itself a lesson: always grab the `.LOG` files with a hive.)

## Read it
Open `shimcache.csv`: columns `CacheEntryPosition`, `Path`, `LastModifiedTimeUTC`. 
- **Position 0** = most recently inserted.
- Scan **`Path`** for executables in `Temp`, `AppData`, `PerfLogs`, `ProgramData`, or with random names — classic staging locations.
- A path that exists in ShimCache but **not** in Prefetch (Module 1) = *seen but maybe never run* — still meaningful (dropped, staged).

## Exercises
1. Sort by `CacheEntryPosition` — what are the 10 most recently seen executables?
2. Find any path under `\Temp\` or `\AppData\` — cross-check against Module 1 (did it also run?).
3. Compare a binary's ShimCache `LastModifiedTimeUTC` with its Amcache time (Module 3) — do they agree?

## Pivot
- A suspicious path here → **Module 1** (did it run?) and **Module 3** (what's its SHA1?).

---
*Next: [Module 3 — Amcache](../module-03-amcache-amcacheparser).*
