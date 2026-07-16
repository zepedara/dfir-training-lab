# Module 23 data — provenance

**This is a technique-demonstration dataset, and it is completely inert.**

- **`UsnJrnl_J`** — the raw `$UsnJrnl:$J` change-journal stream from a throwaway scratch NTFS volume.
- **`MFT`** — the `$MFT` from the same scratch volume.

## How it was made (and why it is safe)

Generated on an **isolated 96 MB scratch NTFS VHD** (never a real system volume), driven through a benign wiping scenario:

1. Three decoy files were created — `secret_plans.txt`, `payroll.csv`, `creds.txt` — each containing **only a plain-text marker string** (e.g. `MARKER-SECRETPLANS-0001`). **No executable content, no code, no payload.**
2. **SDelete** (Microsoft-signed Sysinternals, one pass) securely deleted `secret_plans.txt` — producing the 26-rename chain.
3. **`cipher /w`** (built-in Windows) wiped the volume's free space — producing the `EFSTMPWP` fill folder.
4. The `$MFT` (inode 0) and `$UsnJrnl:$J` (`icat -o 128 … 38-128-3`) were carved from the detached VHD with The Sleuth Kit — the same `icat`-by-inode technique Module 15 uses.

What ships is **pure filesystem metadata** — file names, timestamps, and change-journal reason codes. There is no malware, no live tool, and nothing to execute. The wipers were run **only** against the scratch volume at build time; the student never runs them.

> Regeneration script: `build-wipe-marks.ps1` (kept with the module tooling). SDelete's rename behaviour and `cipher /w` semantics are Microsoft-documented; see the module `README.md` §10 for all sources.
