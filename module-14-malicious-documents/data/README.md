# Module 14 data — provenance, license & build steps

**All three samples are self-built, benign teaching files.** They contain realistic *indicators* (auto-exec triggers, a PowerShell downloader string, PDF JavaScript / `/Launch` / `/URI` actions) but **no working payload and no real malware**:

- The only "callback" host is **`example.test`**, an **RFC-6761 reserved, non-routable** domain that can never resolve to a real server.
- The `/Launch` action targets **`calc.exe`** — the long-standing harmless stand-in used in PDF-action demos.
- Nothing is ever executed: every tool in this module is a **static parser** (it reads and decodes bytes; it does not run the macro or the JavaScript).

> **No live, weaponised malware is committed to this repository.** These files exist solely to produce realistic *tool output* for training.

| File | Origin | License | Tools it teaches |
|---|---|---|---|
| `Invoice_2024_0042.doc` | self-built (`build/build_maldoc.py`) | CC0 / public domain (lab-authored) | `oleid`, `olevba`, `oledump` |
| `Statement_Q4.docm` | self-built (`build/build_docm.py`, wraps the `.doc`'s VBA project) | CC0 / public domain (lab-authored) | `zipdump`, `oledump`, `olevba` (OOXML path) |
| `Invoice_2024_0042.pdf` | self-built (`build/build_pdf.py`) | CC0 / public domain (lab-authored) | `pdfid`, `pdf-parser` |

### SHA-256
```
30a4da23eeff570fa00abf244d232bcf4198301467b047d55607c31516e4b935  Invoice_2024_0042.doc
f7e3e282f4330267c97ce3c1381a68788232b121526a20c7953d335ed5645144  Statement_Q4.docm
1af13238846e95d6270e421937d8d49dae0ab0e86c8b734cf7338a08ae03c17f  Invoice_2024_0042.pdf
```

---

## How each sample was built (fully reproducible)

The generators are in `build/` and use only the Python standard library (`struct`, `zlib`, `zipfile`). Re-create the samples on any host:

```bash
cd module-14-malicious-documents/data
python3 build/build_maldoc.py Invoice_2024_0042.doc                 # legacy OLE2 + VBA
python3 build/build_pdf.py    Invoice_2024_0042.pdf                 # malicious-looking PDF
python3 build/build_docm.py   Invoice_2024_0042.doc Statement_Q4.docm   # wrap the VBA project as OOXML
```

### `build_maldoc.py` — `Invoice_2024_0042.doc` (legacy OLE2 macro doc)
Writes a minimal but **spec-valid OLE2 Compound File** ([MS-CFB]) from scratch — header, FAT, **mini-FAT** for the small streams, and a directory red-black tree — containing a real **VBA project** ([MS-OVBA]): a `VBA/dir` stream (full `PROJECTINFORMATION` + a `MODULE` record) and a `VBA/Module1` stream whose source is **MS-OVBA compressed** with literal-token chunks (the exact form `oledump` keys on, `\x00Attribut\x00e `). The VBA is an *invoice-viewer* lure with `AutoOpen`/`Document_Open` → a PowerShell `DownloadString` one-liner, obfuscated with `Chr()`, `StrReverse`, and string concatenation, plus a `URLDownloadToFileA` backup. It is a minimal OLE2 *VBA carrier* (no `WordDocument` stream), which is why `oleid` labels the format "Generic OLE file" — the macro analysis is identical to a full Word doc.

### `build_pdf.py` — `Invoice_2024_0042.pdf` (malicious PDF)
Hand-writes a small PDF with a correct cross-reference table and these (inert) indicators: a Catalog `/OpenAction` → a `/JavaScript` action whose script lives in a **`FlateDecode`-compressed** stream (so the lab must use `pdf-parser -f` to read it); a `/Names /JavaScript` entry; a page `/AA /O` → a `/Launch` action (`calc.exe`); and a link annotation with a `/URI`. The JavaScript only calls `app.alert` and `app.launchURL` to `example.test`.

### `build_docm.py` — `Statement_Q4.docm` (modern OOXML macro doc)
Zips a minimal OOXML skeleton (`[Content_Types].xml`, `_rels/.rels`, `word/document.xml`, `word/_rels/document.xml.rels`) **plus the `.doc` above stored as `word/vbaProject.bin`** — i.e. the *same* VBA project in a modern ZIP container. This is what makes the `zipdump → oledump` pipe in Part B work.

> Everything was generated and verified in the `dfir-aio:v2` container; analysis runs offline (`--network none`). Keep these files inert: do not "weaponise" them by repointing the URLs at a live host or swapping `calc.exe` for a real payload.
