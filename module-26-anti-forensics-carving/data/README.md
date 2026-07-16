# Module 26 data — provenance

**Inert technique-demonstration image.** `disk-carve-lab.raw.gz` is a gzip-compressed 20 MB raw NTFS disk image (compresses to ~180 KB because the volume is almost all zeroes). Unpack it with the module's first command (`gzip -dkf disk-carve-lab.raw.gz`).

## How it was made (and why it is safe)
Built on an **isolated scratch NTFS volume** (never a real system):
1. Three benign decoy files were created under `\case\` — each padded past 1 KB so it is **non-resident** (its data lands in real clusters, not the `$MFT` record):
   - `bitlocker_backup.txt` — a **fake** BitLocker recovery key in the correct 8×6-digit *format* (`247183-556031-…`) — **not a real key**, plus `MARKER-BLKEY-9001`.
   - `exfil_manifest.txt` — `MARKER-EXFIL-9002`.
   - `passwords.txt` — `MARKER-CREDS-9003` (no real secrets).
2. The volume cache was **flushed** so the data was physically written to disk, then all three files were **deleted** (their content now survives in unallocated space).
3. The VHD was detached and captured as a raw image.

There is **no code, no malware, no real credential** anywhere — only marker strings and a fake-format key. Everything the module recovers is inert lab decoy content. Generation script: `build-carve-lab.ps1`.
