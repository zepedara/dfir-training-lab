# Research — Didier Stevens Suite (pdfid, pdf-parser, oledump, zipdump)

> **Status in `dfir-aio:v2`:** PRESENT. `pdfid`, `pdf-parser`, `oledump`, `zipdump` on `PATH` (`/opt/tools/bin/…`, wrappers to the scripts in `/opt/didierstevens/*.py`). Note the **command names have no `.py`** in this container (use `pdfid`, not `pdfid.py`). Pure-Python, fully offline. Verified on rick 2026-06-29.

---

## 1. What the suite is and the questions it answers

Didier Stevens' tools are the de-facto standard for **manually dissecting suspicious documents and containers** — PDFs, OLE/Office files, and ZIP-based formats (including OOXML `.docx`/`.xlsm`, JAR, APK, nested archives). Where `oletools` automates Office-macro triage, the Didier Stevens suite gives you **surgical, byte-level control** to follow a malicious object through its structure. Four core tools:

| Tool | Format | Question it answers |
|---|---|---|
| **`pdfid`** | PDF | "Does this PDF contain risky elements (JavaScript, auto-actions, embedded files)?" — fast **triage**. |
| **`pdf-parser`** | PDF | "Show me the actual objects/streams — extract and decode the JavaScript/payload." — **deep dive**. |
| **`oledump`** | OLE2 (Office `.doc/.xls`, MSG, `vbaProject.bin`) | "List the streams; dump/decompress the VBA macro or embedded object from a chosen stream." |
| **`zipdump`** | ZIP (incl. OOXML, JAR, nested) | "List/inspect/extract members of a ZIP without unzipping to disk; pipe a member into another tool." |

These four **compose** with Didier's plugin/`-s`/cut conventions to peel a multi-layer sample apart safely (no execution).

---

## 2. How they work + the most useful commands

### 2.1 `pdfid` — PDF triage (counts risky keywords)
A PDF is a set of **objects**; certain keywords signal danger: `/JavaScript`, `/JS` (scripts), `/OpenAction`, `/AA` (run on open), `/Launch` (run a program), `/EmbeddedFile`, `/URI`, `/AcroForm`, `/RichMedia`. `pdfid` scans and **counts** them.
```bash
pdfid suspicious.pdf
```
Output is a table of keyword → count. **Any non-zero `/JS`, `/JavaScript`, `/OpenAction`, `/AA`, or `/Launch` = investigate with `pdf-parser`.**
| Flag | Purpose |
|---|---|
| `-e` | show **extra/all** keywords (entropy, more names). |
| `-f` | force (parse even if not recognised as PDF). |
| `-n` | hide zero-count keywords (cleaner). |
| `-o` / plugins | with the `pdfid` plugin system, score documents (e.g. `nameobfuscation`). |

### 2.2 `pdf-parser` — extract & decode PDF objects
Walks the PDF object tree; lets you target a specific object, follow references, and **decompress/decode streams** (FlateDecode etc.) to get the embedded JavaScript or payload.
```bash
pdf-parser suspicious.pdf                 # overview of all objects
pdf-parser -a suspicious.pdf              # stats: object/stream types & counts
pdf-parser -s JavaScript suspicious.pdf   # find objects with /JavaScript
pdf-parser -o 12 suspicious.pdf           # show object 12
pdf-parser -o 12 -f -d obj12.bin suspicious.pdf   # -f apply filters(decode), -d dump to file
```
| Flag | Purpose |
|---|---|
| `-s KEYWORD` | search objects containing a name/keyword (e.g. `JavaScript`, `OpenAction`). |
| `-o ID` | show a specific **object** by number. |
| `-r REF` | show objects **referencing** a given object (follow the chain). |
| `-f` | **apply stream filters** (decode FlateDecode/ASCIIHex etc. → readable payload). |
| `-d FILE` | **dump** the (decoded) stream to a file. |
| `-w` | raw output. |
| `-c` | show stream content without parsing. |
| `--objstm` | also parse **object streams** (compressed object containers — malware hides here). |
Typical hunt: `pdfid` flags `/OpenAction` → `pdf-parser -s OpenAction` → it references an object with `/JavaScript` → `pdf-parser -o N -f` to read the deobfuscated script → extract the dropped URL/shellcode.

### 2.3 `oledump` — OLE stream surgery (VBA macros)
Lists the **streams** inside an OLE2 file; each is indexed. A stream containing a macro is flagged with **`M`** (has VBA) or **`m`** (has VBA, no actual code/attribute only). You then dump that stream.
```bash
oledump suspicious.doc                     # list streams; look for 'M' = macro
oledump -s 3 -v suspicious.doc             # -s 3 select stream 3, -v decompress VBA → source
oledump -s 3 -d suspicious.doc > stream3.bin   # -d dump raw bytes of the stream
oledump -s a -v suspicious.doc             # -s a = ALL streams
```
| Flag | Purpose |
|---|---|
| `-s N` / `-s a` | **select** stream N (or `a`=all). |
| `-v` | **decompress** VBA macro source (the readable code). |
| `-d` | dump raw stream bytes (to extract embedded objects/payloads). |
| `-p PLUGIN` | run a **plugin** (e.g. `plugin_http_heuristics`, `plugin_vba_dco`) to auto-spot indicators. |
| `--vbadecompresscorrupt` | recover **VBA-stomped**/corrupt macro source. |
| `-i` | show extra info (incl. macro indicators). |
Stream-index letters like `A3` mean storage A, stream 3.

### 2.4 `zipdump` — inspect ZIP/OOXML members without extracting
OOXML (`.docx`,`.xlsm`,`.pptx`), JARs, APKs, and ordinary ZIPs are containers. `zipdump` lists members, shows metadata, and **pipes a member's content into the next tool** — so you never write malware to disk.
```bash
zipdump suspicious.xlsm                     # list members (index, name, size, timestamps)
zipdump -s 5 -d suspicious.xlsm             # dump member 5's bytes to stdout
zipdump -s 5 -d suspicious.xlsm | oledump   # pipe vbaProject.bin straight into oledump
zipdump --headers suspicious.docx           # show member metadata
```
| Flag | Purpose |
|---|---|
| `-s N` / `-s a` | select member N (or all). |
| `-d` | dump member bytes to stdout (pipe-friendly). |
| `-e` | extended info (hashes, magic, entropy per member). |
| `-D` | dump as raw, `-p PLUGIN` for plugins. |
Classic combo: `zipdump -s vbaProject.bin -d doc.xlsm | oledump -s a -v -` to read macros out of an OOXML file without ever unzipping it.

---

## 3. Didier's shared conventions (worth knowing once)
- **`-s` select + `-d` dump + `-v` decompress** recur across the tools — once you know them you can pivot fast.
- Most tools accept **`-`** as a filename meaning **stdin**, so they **pipe** into each other (`zipdump … -d | oledump - …`).
- Many support a **cut expression** (`-c`) to slice bytes out of a stream, and a **`--decoders`/`-p` plugin** mechanism for heuristics.
- They are **static** — they parse and decode, never execute.

---

## 4. Reading the output / a realistic chain

```bash
# A phishing .docx (it's really a ZIP)
zipdump phish.docx                          # see word/vbaProject.bin present? macros likely
zipdump -s word/vbaProject.bin -d phish.docx | oledump -                # list macro streams
zipdump -s word/vbaProject.bin -d phish.docx | oledump -s a -v -        # read the macro source
# A malicious PDF
pdfid -n invoice.pdf                         # /OpenAction 1, /JavaScript 1  → bad
pdf-parser -s OpenAction invoice.pdf         # → object 8 triggers object 9
pdf-parser -o 9 -f invoice.pdf               # decoded JS reveals a downloader URL
```
**What you're looking for:** in PDFs, auto-action → JavaScript → a heap-spray/`util.printf`/`exportDataObject` or a `/Launch`/URL. In Office, a macro stream with `AutoOpen`+`Shell`/`PowerShell` and an embedded URL/dropped path. Each extracted payload (URL, EXE, shellcode) becomes an IOC and feeds capa/FLOSS/YARA.

---

## 5. Common pitfalls
- **Command names differ from docs.** Upstream uses `pdfid.py`/`oledump.py`; **this container exposes them without `.py`** (`pdfid`, `oledump`, …). The `.py` originals are in `/opt/didierstevens/`.
- **`pdf-parser` won't decode unless you ask:** add **`-f`** to apply stream filters, or you'll see compressed gibberish. Use `--objstm` for object-stream-hidden content.
- **`oledump` needs `-v` for readable macros**; raw `-d` gives compressed bytes. For stomped macros use `--vbadecompresscorrupt`.
- **OOXML ≠ OLE:** a `.docx` is a ZIP → use `zipdump` to reach `vbaProject.bin`, *then* `oledump`. Don't point `oledump` at the `.docx` directly.
- **Obfuscation:** heavy JS/VBA obfuscation may need manual decoding or the tools' plugins; static tools won't always fully resolve runtime-built strings.
- **Handle on the offline container** — you'll be dumping live payloads.

---

## 6. Where it fits a DFIR investigation
This suite is the **manual deep-dive** companion to `oletools` for **initial-access** analysis. When automated triage flags a maldoc/PDF (or you recover one from a user's mailbox/Downloads via the disk modules), these tools let you **prove exactly what the document does and extract the next stage** — surgically and reproducibly, which matters for reporting and courtroom defensibility. Extracted payloads/URLs pivot into the EVTX/PowerShell modules and the capa/FLOSS/YARA flow.

---

## 7. Sources
- Didier Stevens' blog + tool pages — https://blog.didierstevens.com/ and https://github.com/DidierStevens/DidierStevensSuite (pdfid, pdf-parser, oledump, zipdump usage and plugins).
- SANS ISC diaries by Didier Stevens — numerous real maldoc/PDF walkthroughs using these exact commands.
- 13Cubed / SANS FOR610 (Reverse-Engineering Malware) — document-analysis methodology with the Didier Stevens suite.
- Adobe PDF reference / OLE2 Compound File spec — the formats the tools parse.
