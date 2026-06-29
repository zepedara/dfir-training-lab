# research/ — Deep tool research for future lab modules

Command-rich, cited research docs for DFIR tools not yet covered by the numbered modules. Each is meant to become a future module. Every tool was **verified in the `dfir-aio:v2` container on rick** (2026-06-29) — availability, version, and a sample `--help`/version run.

## Docs
| Doc | Tool | Forensic question | In `dfir-aio:v2`? |
|---|---|---|---|
| [volatility3.md](volatility3.md) | Volatility 3 | memory: what was running/injected/talking to C2? | **YES** — `vol`, v2.28.0, Windows symbols bundled |
| [capa.md](capa.md) | capa | what can this binary *do*? (capabilities → ATT&CK) | **YES** — `capa`, v9.4.0 |
| [floss.md](floss.md) | FLOSS | what strings/IOCs does it *hide*? | **YES** — `floss`, v3.1.1 |
| [yara.md](yara.md) | YARA | *which* known-bad does this match? | **YES** — `yara`, v4.2.3 (no rulesets bundled — bring your own) |
| [oletools.md](oletools.md) | oletools | is this Office doc weaponised? | **YES** — `olevba`/`oleid`/`rtfobj`, v0.60.1 |
| [sleuthkit.md](sleuthkit.md) | The Sleuth Kit | filesystem/timeline, deleted files, timestomp | **YES** — `fls`/`mmls`/`icat`/`istat`, v4.11.1 |
| [regripper.md](regripper.md) | RegRipper | registry: execution/persistence/user activity | **YES** — `regripper`, Rip v3.0, 266 plugins |
| [didier-stevens-suite.md](didier-stevens-suite.md) | Didier Stevens suite | PDF/OLE/ZIP surgery | **YES** — `pdfid`/`pdf-parser`/`oledump`/`zipdump` (no `.py` suffix) |
| [appcompatprocessor.md](appcompatprocessor.md) | AppCompatProcessor | ShimCache/Amcache across *many* hosts | **PARTIAL** — present at `/opt/appcompatprocessor`, **Python 2 only, not on PATH** |
| [mftecmd-timeline.md](mftecmd-timeline.md) | MFTECmd / super-timeline | $MFT/$J/$LogFile, timestomp, timeline | **YES** — `MFTECmd`, v2026.5.0 |

## Container gaps / fixes to consider
- **AppCompatProcessor**: works only under `python2` (`/usr/local/bin/python2`), and has **no PATH wrapper**. Recommend adding a `regripper`-style wrapper that `exec python2 …`, and `pip2 install termcolor python-Levenshtein psutil` so `leven`/colour/memory-governor features work.
- **YARA**: engine present but **no rule sets bundled**. A future module should ship/clone `Neo23x0/signature-base` into the module `data/`.
- **Volatility symbols**: `windows.zip` ISF pack is bundled (offline OK); a *brand-new* Windows build with no matching ISF would need its symbol added.
- **Super-timeline merger (Plaso / `log2timeline.py`/`psort.py`)**: **confirmed MISSING** from the container (only TSK `mactime` is present). Add Plaso for one-shot super-timelines; until then, build the timeline per-layer with MFTECmd + TSK `mactime` and merge in Timeline Explorer.
