# Module 26 — Anti-Forensics: Carving Evidence from Unallocated Space

> **Track:** Anti-Forensics (FOR508.5). **Prereqs:** Module 15 (NTFS internals, deleted-file recovery). **Tools:** The Sleuth Kit (`mmls`/`fls`/`icat`/`blkls`) + `grep`.
> **You'll learn:** the two ways to get a deleted file back — **metadata recovery** (the `$MFT` record still points at the data) and **carving** (search the raw unallocated bytes when the metadata is gone) — and how to **recover a deleted BitLocker recovery key** an attacker thought was destroyed.

---

## 1. Two roads to a deleted file

When Windows "deletes" a file it does **not** erase the data. It flips two bits: the file's `$MFT` record is marked free, and its clusters are marked free in the `$Bitmap`. The **name, the metadata, and the bytes all remain** until something reuses them. That gives an examiner two independent recovery paths:

- **Metadata recovery.** If the file's `$MFT` record is still intact, it still lists the file's name and the exact clusters that held its data. You read them straight out — this is what `fls`/`icat` did in Module 15. Fast, exact, gives you the **name**.
- **Carving.** If the `$MFT` record has been **reused or wiped** (an attacker's goal — see Modules 23 & 25), the pointer is gone, but the **data may still be sitting in unallocated clusters**. You extract that raw free space and search it for known content or signatures. Slower, no filename, but it works **when metadata recovery fails**.

> **The lesson:** anti-forensics attacks the *metadata* — wiping `$MFT` records, clearing the journals. Carving sidesteps that entirely by reading the **raw bytes** the attacker forgot to overwrite. Two roads; when the attacker blocks one, take the other.
>
> **ATT&CK:** recovery counters **T1070.004 (Indicator Removal: File Deletion)**; a recovered credential/key relates to **T1005 (Data from Local System)**.

---

## 2. The evidence in this module

`data/` ships one small **inert** disk image, `disk-carve-lab.raw.gz` (gzip-compressed — the volume is mostly empty, so it's tiny). It was built on an isolated scratch NTFS volume where three benign decoys — a fake **BitLocker recovery-key backup**, an "exfil manifest," and a "passwords" file (all **marker strings only, no real secrets**) — were written, then **deleted**. Their content survives in unallocated space. See `data/README.md` for provenance.

---

## 3. Setup

```bash
cd module-26-anti-forensics-carving/data
```

Unpack the image (kept compressed in the repo because it's almost all zeroes):

```bash
gzip -dkf disk-carve-lab.raw.gz
```

---

## 4. Step-by-step walkthrough

### Step 1 — Find the partition

```bash
mmls disk-carve-lab.raw
```

**Read it:** one **NTFS** partition starting at sector **128**. Every Sleuth Kit command below takes `-o 128` to seek to it (exactly as in Module 15).

### Step 2 — Road one: metadata recovery of the deleted files

List the volume **including deleted** entries (`-d`), recursively (`-r`):

```bash
fls -o 128 -rd disk-carve-lab.raw
```

**Read it:** three deleted files surface — `case/bitlocker_backup.txt`, `case/exfil_manifest.txt`, `case/passwords.txt` — each marked `*` (deleted) with its `$MFT` entry number (e.g. `39-128-3`). The records **survived the delete**, so you can read them straight back. Recover the BitLocker backup by its entry number:

```bash
icat -o 128 disk-carve-lab.raw 39
```

**Read it:** the file's full content prints — including the line **`Recovery Key: 247183-556031-…`**. Because the `$MFT` record was intact, metadata recovery handed you the file *by name and in full*.

### Step 3 — Road two: carve the raw unallocated space

Metadata recovery only works while the `$MFT` record survives — and defeating that is exactly what a wiper (Module 23) or a busy filesystem does. The durable fallback: pull **only the unallocated clusters** out of the image with `blkls` and search the raw bytes.

```bash
blkls -o 128 disk-carve-lab.raw > unalloc.raw
```

`unalloc.raw` is every free cluster concatenated — the graveyard of deleted data, with no filesystem structure. Now carve it. First, hunt your case markers:

```bash
grep -aoE 'MARKER-[A-Z]+-[0-9]+' unalloc.raw | sort -u
```

**Read it:** `MARKER-BLKEY-9001`, `MARKER-CREDS-9003`, `MARKER-EXFIL-9002` — the content of all three deleted files, recovered from raw free space **with no `$MFT` record required**. `grep -a` treats the binary blob as text; `-o` prints just the match.

### Step 4 — Carve the BitLocker recovery key

The highest-value string in a lot of real cases is a **BitLocker recovery key** — 48 digits in eight groups of six. It ends up in unallocated space when a user saves it to a text file (or prints-to-file) and later deletes it. Its rigid format makes it perfect to carve by regex:

```bash
grep -aoE '([0-9]{6}-){7}[0-9]{6}' unalloc.raw | sort -u
```

**Read it:** the key **`247183-556031-118924-330756-490217-661508-772349-883160`** falls straight out of the free space — recovered from a file the user deleted. That key would unlock an otherwise-encrypted volume; finding it in unallocated is often the difference between reading a suspect's disk and not.

> **The purpose-built tool.** `grep -a` carves fine, but Eric Zimmerman's **`bstrings`** is built for exactly this: bit-for-bit string search over a raw image or unallocated blob with **pre-loaded regex patterns** — including a ready-made `bitlocker` pattern (`bstrings.exe -f unalloc.raw --lr bitlocker`). It also handles UTF-16 strings and is far faster on large images. The `grep` above teaches the mechanic; `bstrings` is what you'd reach for on a real 1 TB disk. (<https://github.com/EricZimmerman/bstrings>)

---

## 5. Try it yourself

1. **Two roads.** For `case/exfil_manifest.txt`, recover it (a) by metadata with `icat` and (b) by carving with `grep`. Which one still works if the attacker wiped the `$MFT` record, and why?
2. **Why `blkls`?** You could `grep` the whole `disk-carve-lab.raw`. What does running it against `unalloc.raw` (the `blkls` output) instead buy you on a real, mostly-full disk?
3. **The key.** Write the regex that carves a BitLocker recovery key, and explain what about the key's *format* makes it reliably carvable when arbitrary text is not.
4. **When carving fails.** Name one thing an attacker (or normal disk activity) could do that would defeat **both** roads — metadata recovery *and* carving.

---

## 6. Key takeaways

- **Delete erases pointers, not data.** Name, metadata, and bytes all persist until reused — giving you two independent recovery roads.
- **Metadata recovery** (`fls -rd` → `icat`) is fast and gives the **filename**, but needs the `$MFT` record intact.
- **Carving** (`blkls` → `grep`/`bstrings`) reads the **raw unallocated bytes**, so it works **after** anti-forensics has destroyed the metadata — the whole point of this track.
- **BitLocker recovery keys** carve cleanly by their fixed 8×6-digit format — a high-value, low-effort hunt in any unallocated space.

---

## 7. Sources

- The Sleuth Kit — `blkls` (extract unallocated) & `icat`/`fls` (metadata recovery): <https://sleuthkit.org/sleuthkit/man/blkls.html>
- Eric Zimmerman — **`bstrings`** (raw string search, BitLocker-key regex): <https://github.com/EricZimmerman/bstrings>
- Microsoft — BitLocker recovery key (48-digit format): <https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview>
- MITRE ATT&CK — **T1070.004 Indicator Removal: File Deletion**: <https://attack.mitre.org/techniques/T1070/004/> · **T1005 Data from Local System**: <https://attack.mitre.org/techniques/T1005/>
- **MFTECmd** / Module 15 cross-reference (metadata-based recovery): <https://github.com/EricZimmerman/MFTECmd>
