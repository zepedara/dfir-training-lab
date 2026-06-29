# Module 16 — sample data

Real Windows **registry hives** from the public **DFIR-Madness "The Stolen Szechuan Sauce" (Case 001)** intrusion dataset — the same case the rest of this lab is built on. Two machines are represented:

- **`CITADEL-DC01`** — the domain controller (server). Its machine-wide config hives.
- **`DESKTOP-SDN1RPT`** — the workstation (users `mortysmith`, `Administrator`). Its per-user hives.

> **Defensive/training use only.** These are real hives from a published teaching dataset; respect the original author's terms and do not redistribute non-educationally. They are configuration databases, not malware — but they *reference* the case malware `coreupdater.exe`, so they live behind the lab's normal evidence handling.

## Files (committed)

| File | Host \ profile | Size | Hive type / key evidence |
|---|---|---|---|
| `SYSTEM`, `SYSTEM.LOG1`, `SYSTEM.LOG2` | CITADEL-DC01 (machine) | ~13 MB | SYSTEM — computer name, time zone, **services** (`coreupdater` auto-start), USB, mounted devices, last shutdown. |
| `SAM` | CITADEL-DC01 (machine) | 256 KB | SAM — local accounts (Administrator/Guest) + group membership. |
| `NTUSER.DAT`, `ntuser.dat.LOG1` | DESKTOP-SDN1RPT \ `mortysmith` | 1 MB | NTUSER — UserAssist, **RecentDocs**, per-user Run (benign baseline). |
| `UsrClass.dat`, `UsrClass.dat.LOG1` | DESKTOP-SDN1RPT \ `mortysmith` | 3.4 MB | UsrClass — **Shellbags** (folder-browsing history). |
| `Administrator_NTUSER.DAT`, `Administrator_ntuser.dat.LOG1` | DESKTOP-SDN1RPT \ `Administrator` | 786 KB | NTUSER — **UserAssist proof `coreupdater.exe` was run** by the attacker. |

The `*.LOG1/.LOG2` files are the hives' **transaction logs** (most-recent, not-yet-flushed changes). Always collected with a hive. Note: **RegRipper 3.0 does not replay logs automatically** — it reads the base hive. For maximum completeness, replay logs first with Eric Zimmerman's `rla.exe` or `yarp`/`registryFlush.py`. The evidence used in this module is all present in the base hives.

## Fetched separately (not committed)

| File | Host | Size | Why not committed |
|---|---|---|---|
| `SOFTWARE` | CITADEL-DC01 (machine) | ~44 MB | Too large to ship in-repo. Needed for Steps 7-9 (Run-key persistence, installed apps, NetworkList). Run **`bash get-data.sh`** for instructions to obtain it from the case dataset. Every SOFTWARE command's real output is already saved in `../reference-output/`. |

## Renaming note
Hive *contents are unmodified*. Two `NTUSER.DAT` files would collide in one folder, so the attacker's copy is shipped as **`Administrator_NTUSER.DAT`** (and its log as `Administrator_ntuser.dat.LOG1`). RegRipper selects the hive purely by the `-r <path>` you give it — the filename is just a label — so `rip -r Administrator_NTUSER.DAT -p userassist` works exactly as if it were named `NTUSER.DAT`.

## Origin / how these were produced
- **Source:** DFIR-Madness, "The Stolen Szechuan Sauce" (Case 001) — <https://dfirmadness.com/the-stolen-szechuan-sauce/>. Multi-host Windows intrusion published for education.
- **Machine hives** (`SYSTEM`, `SOFTWARE`, `SAM`) are the `C:\Windows\System32\config\` hives of the case's **server `CITADEL-DC01`**.
- **User hives** (`NTUSER.DAT`, `UsrClass.dat`) were **carved from the case's desktop disk image** (`DESKTOP-SDN1RPT`, the NTFS partition at sector offset 239616) with The Sleuth Kit — the same `icat` workflow Module 15 uses, e.g.:
  ```bash
  icat -o 239616 <DESKTOP-SDN1RPT.E01> <inode> > NTUSER.DAT
  ```
- All `rip` output shown in the module README was generated against these exact hives; the captures live in `../reference-output/`.

## Source / license
- DFIR-Madness Case 001: <https://dfirmadness.com/the-stolen-szechuan-sauce/> — education/defensive use only; respect the author's terms.
