# Module 3 — data provenance

## Files
- `Amcache.hve` — the real Windows Amcache inventory hive.
- `Amcache.hve.LOG1`, `Amcache.hve.LOG2` — its registry **transaction logs** (replayed automatically by the parser; always collect them with the hive).
- `amcache_UnassociatedFileEntries.csv` — pre-parsed: inventoried executables not tied to an installed program (**SHA1 lives here**), incl. the malware `coreupdater.exe`.
- `amcache_AssociatedFileEntries.csv`, `amcache_ProgramEntries.csv`, `amcache_DeviceContainers.csv`, `amcache_DevicePnps.csv`, `amcache_DriveBinaries.csv`, `amcache_DriverPackages.csv`, `amcache_ShortCuts.csv` — the rest of the AmcacheParser CSV set, committed so the module can be read without running the container.

## Origin / scenario
From the desktop **`DESKTOP-SDN1RPT`** of the **DFIR Madness "Case 001 — The Stolen Szechuan Sauce"** dataset. 98 file entries (15 unassociated + 83 associated). Teaching highlights: the malware `coreupdater.exe` (SHA1 `fd153c66386ca93ec9993d66a84d6f0d129a3a5c`, 7,168 bytes, `IsOsComponent=False`, empty ProductName) and the responder's own `FTK Imager.exe` run from `E:\`.

## Source / license
- DFIR Madness, "The Stolen Szechuan Sauce" (Case 001): https://dfirmadness.com/the-stolen-szechuan-sauce/
- Education/defensive use only; respect the original author's terms.

## How it was produced
The CSV set was generated in the lab with:
`AmcacheParser -f /data/Amcache.hve --csv /data --csvf amcache.csv -i`
(the tool auto-replays `Amcache.hve.LOG1/.LOG2`).
