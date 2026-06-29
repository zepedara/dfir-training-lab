# Research — oletools (Malicious Office Document Analysis)

> **Status in `dfir-aio:v2`:** PRESENT. `olevba`, `oleid`, `rtfobj` (plus `olemeta`, `oleobj`, `mraptor`, `oledump`-style tools) on `PATH`. Version **0.60.1** (verified on rick 2026-06-29). Pure-Python, fully offline.

---

## 1. What it is and the forensic question it answers

**oletools** (by Philippe Lagadec / decalage) is a Python toolkit for analysing **Microsoft Office documents** — the #1 phishing-payload delivery vector for years. It answers: **"Is this Office document weaponised, and what does it do?"** It safely **statically** dissects `.doc/.docm/.xls/.xlsm/.ppt`, the newer OOXML `.docx/.xlsx`, and `.rtf` files to surface **VBA macros, auto-execution triggers, suspicious API calls, embedded objects/payloads, and obfuscated content** — **without opening the document in Office** (so nothing detonates).

Office malware hides in:
- **VBA macros** (legacy `.doc`/`.xls` and macro-enabled `.docm`/`.xlsm`) with `AutoOpen`/`Document_Open` triggers.
- **Embedded OLE objects** (a packaged `.exe`/`.lnk`/script the user is lured to double-click).
- **RTF objects** (often exploiting Equation Editor, CVE-2017-11882, via `\objdata` blobs).
- **Excel 4.0 (XLM) macros**, DDE, and template-injection / remote-template URLs.

---

## 2. The component tools and what each does

`oletools` is a *suite*; the four most investigation-relevant:

| Tool | Purpose |
|---|---|
| **`oleid`** | quick **triage/risk** report — flags VBA macros, encryption, Flash/embedded objects, and overall indicators with a risk level. Run it first. |
| **`olevba`** | **extract and analyse VBA macro source** — dumps the macro code, then runs a keyword/IOC scanner that flags auto-exec triggers, suspicious Win32 API calls, and obfuscation; can also **deobfuscate** common encodings. The workhorse. |
| **`rtfobj`** | parse **RTF** files, list/extract embedded **OLE objects** (the Equation-Editor exploit carrier), and dump them for further analysis. |
| **`oleobj`** | extract embedded objects from OLE/OOXML and detect **remote-template injection** / external relationship URLs. |
| (also) **`olemeta`** | dump document metadata (author, timestamps, company) — useful for attribution/clustering. |
| (also) **`mraptor`** | a fast macro-malware *detector* (verdict: SUSPICIOUS/clean) for bulk triage. |

> oletools' `olevba` also bundles a re-implementation of Didier Stevens' `oledump` concept; for raw OLE stream surgery the standalone **`oledump`** (see the Didier Stevens research doc) is complementary.

---

## 3. How it works under the hood (plain language)

Office binary formats (`.doc`, `.xls`) are **OLE2 Compound File Binary** — a little FAT-like filesystem of "storages" (folders) and "streams" (files) inside one document. VBA macros live in a stream called `VBA/…`, **compressed** and tokenised. The newer `.docx`/`.xlsm` are **ZIP archives of XML** (OOXML); a macro-enabled one contains a `vbaProject.bin` (itself an OLE2 blob) inside the ZIP. RTF is a text format where binary objects are stored as **hex-encoded `\object`/`\objdata`** groups.

oletools:
1. Detects the container type, walks the OLE/ZIP structure, and locates macro/object streams.
2. **Decompresses** the VBA (`olevba` implements the VBA compression and the *p-code/source* extraction — it can even recover macros that were "stomped," where source is removed but p-code remains).
3. Runs the extracted code/bytes through **pattern scanners** for auto-exec keywords, suspicious APIs (`Shell`, `CreateObject`, `URLDownloadToFile`, `WScript`, `PowerShell`, `Environ`), and IOC regexes (URLs, IPs, file paths, base64).
4. For RTF/embedded objects, carves and hex-decodes the `\objdata`/OLE payload so you can hash and analyse it.

All static — it reads bytes, it never runs the macro.

---

## 4. The most useful commands + flags

### `oleid` — triage first
```bash
oleid suspicious.doc
```
Prints a table of indicators (VBA Macros: Yes/No, encrypted, Flash objects, etc.) with severity. Decide whether to go deeper.

### `olevba` — the macro workhorse
```bash
olevba suspicious.docm
```
| Flag | Purpose |
|---|---|
| `-c` / `--code` | print **only the VBA source code** (no analysis table). |
| `-a` / `--analysis` | print **only the analysis** (IOCs/keywords) table. |
| `--decode` | attempt to **deobfuscate** detected encodings (Hex/Base64/StrReverse/Dridex). |
| `--deobf` | aggressive deobfuscation pass. |
| `--reveal` | show the macro with obfuscated strings **replaced inline** by their decoded values (very readable). |
| `--json` / `-j` | JSON output. |
| `-r` | **recursive** — scan a folder of documents. |
| `-z PASSWORD` | open password-protected ZIP/OOXML. |
| `--show-pcode` | disassemble the VBA **p-code** (catches **VBA stomping**, where source ≠ what actually runs). |

```bash
olevba --reveal suspicious.docm          # cleanest way to read what the macro really does
olevba -a -j suspicious.xlsm > olevba.json
olevba -r /evidence/maldocs/             # triage a whole folder
olevba --show-pcode suspicious.doc       # detect/handle VBA stomping
```

### `rtfobj` — RTF object extraction
```bash
rtfobj suspicious.rtf                     # list embedded objects + classify (e.g. Equation.3 = exploit)
rtfobj -s all -d ./out suspicious.rtf     # -s all = save all objects to ./out (-d = output dir)
rtfobj -s 0 suspicious.rtf                # save object index 0
```
A reported **`Equation.3`** / OLE class with an oversized `\objdata` is the classic CVE-2017-11882/Equation-Editor exploit signature. Dump it and analyse the shellcode.

### `oleobj` — embedded objects + remote templates
```bash
oleobj suspicious.docx                    # extracts embedded files, flags external/remote-template URLs
```

---

## 5. Reading the output

- **`olevba` analysis table** has columns *Type | Keyword | Description*. Watch for:
  - **AutoExec**: `AutoOpen`, `Document_Open`, `Workbook_Open`, `Auto_Close` — runs without user action.
  - **Suspicious**: `Shell`, `CreateObject`, `WScript.Shell`, `URLDownloadToFile`, `PowerShell`, `Run`, `ProcessStartInfo`, `Environ`, `Chr`/`StrReverse` (obfuscation), `VirtualAlloc`/`CallByName` (shellcode/injection).
  - **IOC**: URLs/IPs/paths it would contact or drop.
  - **VBA stomping** note from `--show-pcode` — means the readable source is a decoy; trust the p-code.
- The combination *AutoExec + Shell/PowerShell + a URL* = a downloader maldoc. That URL/dropped path becomes an IOC to sweep.
- **`rtfobj`**: each listed object shows class name, size, and (with `-s`) a saved file you then hash/scan with YARA/capa.

---

## 6. Common pitfalls

- **Static analysis won't fully unroll heavy multi-stage obfuscation.** `--reveal`/`--deobf` handle the common cases; truly nasty samples may need manual decoding or a sandbox.
- **VBA stomping**: if source looks benign but the doc is flagged, run `--show-pcode` — attackers strip source and leave malicious p-code.
- **OOXML password/encryption**: encrypted docs need `-z`/the password; a flagged "encrypted" doc that you can't read is itself suspicious (common evasion).
- **Excel 4.0 (XLM) macros and DDE** live outside VBA; `olevba` detects XLM, but very old XLM tricks may need `XLMMacroDeobfuscator`/other tools — note if you hit this.
- **Always handle on the offline container** (`--network none`) — even though oletools doesn't execute the macro, you'll be carving live payloads.

---

## 7. Where it fits a DFIR investigation

oletools is the **initial-access / phishing** analysis station. When a case starts from a suspicious email attachment (or you find a maldoc in a user's Downloads/Temp via the disk modules), oletools tells you whether it's weaponised, **what it would execute**, and **what it would fetch** — handing you the next-stage URL/dropper to pivot on. Those IOCs feed the EVTX/PowerShell modules (did the macro's PowerShell actually run? check 4104) and the YARA/capa/FLOSS flow for the dropped payload. It's the front door of most intrusions.

---

## 8. Sources
- oletools official docs + wiki — https://github.com/decalage2/oletools/wiki (per-tool usage: olevba, oleid, rtfobj, oleobj).
- decalage.info — Philippe Lagadec's tool pages and maldoc-analysis write-ups.
- SANS / 13Cubed maldoc-analysis walkthroughs (olevba `--reveal`, RTF/Equation-Editor exploitation).
- MITRE ATT&CK T1566.001 (Spearphishing Attachment), T1204.002 (Malicious File), T1137 (Office template/macro persistence).
- CVE-2017-11882 (Equation Editor) — context for `rtfobj` Equation.3 findings.
