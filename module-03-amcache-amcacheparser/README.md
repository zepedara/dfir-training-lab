# Module 3 — Amcache with AmcacheParser

**Deck mapping:** *Windows Execution Forensics* → "Amcache.hve: The System Inventory" / "Inside the Amcache Hive" / "Extraction with AmcacheParser."
**Goal:** get a rich **inventory** of programs that existed on the host — crucially **with SHA1 hashes** — for identity and threat-intel pivoting.

---

## Concept (from the deck)
**`Amcache.hve`** (`C:\Windows\appcompat\Programs\Amcache.hve`) is the richest of the triad: per executable it can store **full path, SHA1 hash, file size, compile time, and first-seen time**. The deck's angle: this is the **identity/attribution** corner of the triad — the SHA1 lets you confirm a known-bad and hunt the same binary across every host.

**Data:** the real `Amcache.hve` (+ `.LOG1/.LOG2`) from Case 001.

---

## Setup
```bash
cd module-03-amcache-amcacheparser/data        # Amcache.hve, Amcache.hve.LOG1, .LOG2
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

## Step — Parse Amcache
```bash
AmcacheParser -f /data/Amcache.hve --csv /data --csvf amcache.csv -i
```
> `-i` includes the *file entries* (the part with the hashes). The tool replays the transaction logs automatically.

**Expected output (real, Case 001):**
```
Two transaction logs found. Determining primary log...
Total file entries found: 98
```

## Read it
Open the `*_UnassociatedFileEntries.csv` (and associated). Key columns: `FullPath`, `SHA1`, `FileSize`, `FileKeyLastWriteTimestamp`. 
- **SHA1** → drop it into your threat-intel / look it up later; hunt the same hash in other hosts' Amcache.
- **FullPath** → same staging-location instinct as ShimCache.
- A binary present in Amcache **and** Prefetch (ran) **and** ShimCache (seen) with a path in `Temp` = a strong lead.

## The Triad together (the deck's whole point)
| Question | Tool | Module |
|---|---|---|
| Did it **run**? when? | Prefetch | 1 |
| Was it **present/seen**? | ShimCache | 2 |
| **What is it** (SHA1)? | Amcache | 3 |
Each covers the others' blind spots. A binary that's in Amcache (hash) + ShimCache (path) but **not** Prefetch may have been **staged but not yet run** — or run on an OS that doesn't keep Prefetch.

## Exercises
1. Extract all **SHA1**s from `amcache.csv` — pick one and note how you'd pivot (VirusTotal offline-deferred / hunt across hosts).
2. Find an executable whose `FullPath` is in `\Temp\` or `\Users\Public\`.
3. Build the triad table for ONE suspicious binary: its Prefetch run time, ShimCache position, and Amcache SHA1.

## Pivot
- The SHA1 → **Module 4 (Scaling)**: hunt that hash across many hosts with AppCompatProcessor.

---
*Next: [Module 4 — Scaling the Hunt](../module-04-scaling-appcompatprocessor).*
