# Module 1 — Prefetch with PECmd (the Execution Gold Standard)

**Deck mapping:** *Windows Execution Forensics* → "Windows Prefetch: The Gold Standard" / "Parsing Prefetch with PECmd" / "The 10-Second Rule."
**Goal:** prove a program **ran**, **when**, **how many times**, and **what files it touched** — the single strongest piece of execution evidence on a Windows machine.

> **New to this?** Read the next two sections slowly. Every italic term is defined the first time it appears. By the end you'll be able to look at a folder of `.pf` files and tell a story about what happened on a computer.

---

## 1. Background — what Prefetch is and why Windows creates it

### The everyday purpose (why the file exists at all)
Windows wants apps to *start fast*. Every time you launch a program, Windows watches what that program does in its **first ~10 seconds of life** — which code pages it loads, which `.dll` helper files (*Dynamic-Link Libraries*: shared code files a program pulls in) and data files it opens, and in what order. It saves that "shopping list" to a small file so that **next time** you launch the same program it can pre-load those pieces from disk in advance ("pre-fetch" them). That makes the second and later launches noticeably quicker.

That speed-up file is a **Prefetch file**. It lives in `C:\Windows\Prefetch\` and is named like:

```
NOTEPAD.EXE-C5670914.pf
```

- `NOTEPAD.EXE` — the executable's name.
- `C5670914` — an **8-character hexadecimal hash** (a number that fingerprints *where the program was run from*). Windows computes it from the program's **full path**, and for some system programs (like `svchost.exe`) also from the **command-line arguments**. (*Hexadecimal* just means base-16: digits 0-9 plus A-F.)
- `.pf` — the file extension for Prefetch.

The hash is why the same program run from two different folders produces **two different `.pf` files**. That is a gift to investigators: a copy of `cmd.exe` run from `C:\Windows\System32` and a malicious copy run from `C:\Users\Public` leave *two separate* Prefetch files with *two different* hashes.

### Why investigators love it (what you can prove)
Although Windows built this purely for speed, it accidentally created one of the best **evidence-of-execution** artifacts in Windows forensics. An *artifact* is just any trace the operating system leaves behind that we can read later. From one `.pf` file you can prove:

- **That the program ran at all** (the file's mere existence is proof it executed at least once).
- **How many times** it ran — the **run count**.
- **When** it ran — up to the **last 8 run timestamps**.
- **What it loaded** — a list of every file and DLL the program touched in those first seconds (great for spotting a trusted program that was tricked into loading a malicious DLL — a technique called *DLL side-loading*).
- **Where it ran from** — recoverable from the loaded-files list and the path hash.

### How it works under the hood (simple version)
1. You launch `program.exe`.
2. A Windows service called the **Prefetcher** (part of the *SysMain*/Superfetch service) monitors the launch for about **10 seconds**.
3. About 10 seconds *after* the process starts, Windows writes (or updates) the `.pf` file on disk. **This is the famous "10-second rule":** the timestamp baked into the `.pf` is essentially when the program *started*, but the file's own creation/modify time on disk is ~10 seconds later. When you build a timeline, remember the recorded run is the real "go" moment.
4. Since Windows 8, the `.pf` file is **compressed** with an algorithm called **Xpress Huffman** (sometimes shown as `XPRESS10`/`MAM` format). This is why you need a real Prefetch parser to read it — you can't just open it in Notepad.
5. Inside, since Windows 8, Windows keeps the **last 8 run times** (older Windows kept only 1). It also keeps a running **run count**.

### Limits and gotchas (so you don't over-claim)
- **Prefetch can be turned off.** A registry value, `EnablePrefetcher` (under `...\Session Manager\Memory Management\PrefetchParameters`), controls it. On SSDs and Windows Servers it is sometimes disabled, so *no Prefetch file does NOT prove a program never ran.*
- **Capacity is capped.** Modern Windows 10/11 keeps up to **1024** Prefetch files (older Windows kept 128). When full, the oldest get deleted — so absence can simply mean "aged out."
- **Attackers delete Prefetch** to cover tracks. A *missing* `.pf` for a program you know ran is itself a finding.
- **Only the last 8 runs** are timestamped. A program run 50 times shows run count 50 but only 8 dates.

---

## 2. What the tool does — PECmd / `prefetch`

The deck's tool is **PECmd** ("Prefetch Explorer Command-line") by Eric Zimmerman — the standard Windows-native Prefetch parser. It decompresses each `.pf`, decodes the binary structure, and prints (or exports to CSV) the executable name, run count, all 8 run times, the volume/device info, and the full list of loaded files and directories. PECmd is one of the **EZ Tools**; on the lab's Windows VM it lives at `C:\DFIR\tools`.

PECmd needs Windows-only decompression libraries, so **inside this Linux container** we use the equivalent open-source parser, the **`prefetch`** command (a wrapper around **libscca / `sccainfo`**). It reads the same `.pf` structure and prints the same core facts — fully offline. The one difference: `sccainfo` parses **one file at a time** and has **no CSV export**, so we add a small shell loop to summarize the whole folder. On the Windows VM you'd use PECmd's `--csv` for a timeline-ready spreadsheet instead.

**Data for this module (multiple files):** **197 real `.pf` files** extracted from the **DFIR Madness "Case 001"** desktop, hostname `DESKTOP-SDN1RPT` — a documented intrusion, so the exercises have real answers. The whole point of having 197 of them is that real triage means processing a *folder*, not one file: most are an ordinary Windows **baseline** (svchost, explorer, runtimebroker…) and a few are leads (`COREUPDATER.EXE`, plus LOLBins). You'll batch-process the directory, then compare a benign file against the suspect. For convenience the folder also ships a pre-parsed **`pf.csv`** (the same fields PECmd would export) you can open directly if you just want to read, not parse. See `data/README.md` for provenance and licensing of these files.

---

## 3. Setup

```bash
cd module-01-prefetch-pecmd/data        # contains prefetch/*.pf  and  pf.csv
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```

What each piece means:
- `docker run` — start a throwaway container from an image.
- `-it` — **i**nteractive + give us a **t**erminal (so we land at a shell prompt inside the container).
- `--rm` — delete the container when we exit (keeps the host clean; our evidence stays on the host).
- `--network none` — **no network at all.** Forensics is done offline so evidence can never "phone home" and so nothing can tamper with it.
- `-v "$PWD":/data` — **mount** (attach) the current host folder onto the path `/data` inside the container. `$PWD` is "print working directory" — the folder you just `cd`'d into. So `/data` inside the container *is* your `data` folder outside it.
- `dfir-aio:v2` — the offline all-tools image.

You are now at a shell **inside** the container, with your evidence at `/data`.

---

## 4. Step-by-step walkthrough

### Step 1 — Parse a single Prefetch file
Start with one file so you can see the full detail Prefetch holds:

```bash
prefetch /data/prefetch/AM_DELTA.EXE-78CA83B0.pf
```

- `prefetch` — the container's Prefetch parser (libscca's `sccainfo`).
- `/data/prefetch/AM_DELTA.EXE-78CA83B0.pf` — the **single** `.pf` file to read. `sccainfo` takes exactly one file; name it precisely.

**Expected output (real, from Case 001):**
```
Windows Prefetch File (PF) information:
	Format version			: 30
	Executable filename		: AM_DELTA.EXE
	Prefetch hash			: 78ca83b0
	Run count			: 1
	Last run time: 1		: Sep 18, 2020 22:44:32.551352300 UTC
	...
	Number of filenames		: 13
	Filename: 2			: \VOLUME{...}\WINDOWS\SOFTWAREDISTRIBUTION\DOWNLOAD\INSTALL\AM_DELTA.EXE
	...
```

**Reading every field:**
- **Format version: 30** — the internal Prefetch version. `30` = Windows 10/11. (`23` = Win7, `26` = Win8.x.) This confirms the OS family.
- **Executable filename** — the program this `.pf` belongs to.
- **Prefetch hash** — the path hash from the filename, confirmed from inside the file.
- **Run count** — how many times this program has executed. `1` = ran exactly once.
- **Last run time: 1** — the **most recent** execution time, in **UTC** (Coordinated Universal Time — the timezone forensics uses so everyone agrees on "when"). There can be up to 8 of these (`Last run time: 1` is newest).
- **Number of filenames / Filename: N** — every file and DLL the program loaded in its first ~10 seconds. The `\VOLUME{...}` prefix is Windows' internal name for the disk volume. **This list is your DLL side-loading hunt** — it's always printed, no flag needed.

### Step 2 — Summarize ALL 197 files at once
Reading 197 files one at a time is impractical. This loop runs `prefetch` on each file and pulls out the four facts that matter (name, run count, last run, files loaded):

```bash
for f in /data/prefetch/*.pf; do
  prefetch "$f" 2>/dev/null | awk '
    /Executable filename/    {n=$0; sub(/.*: /,"",n)}
    /Run count/              {r=$0; sub(/.*: /,"",r)}
    /Last run time: 1[^0-9]/ {l=$0; sub(/.*: /,"",l); sub(/\..*/,"",l)}
    /Number of filenames/    {c=$0; sub(/.*: /,"",c);
                              printf "%-28s runs=%-3s last=%s loaded=%s files\n", n, r, l, c}'
done
```

**What each part does, in plain English:**
- `for f in /data/prefetch/*.pf; do ... done` — repeat the body once for every `.pf` file; each time, `$f` holds the current filename.
- `prefetch "$f"` — parse that one file.
- `2>/dev/null` — **throw away error messages.** `2>` redirects "standard error" (the error channel); `/dev/null` is the system's trash can. We do this because one file is genuinely corrupt (see Exercise 3) and we don't want its error to clutter the report.
- `| awk '...'` — pipe the text output into **awk**, a tiny text-processing tool. Each `/pattern/ {action}` says "when you see a line matching this pattern, do this."
  - `sub(/.*: /,"",n)` — chop off everything up to and including the `": "`, leaving just the value (e.g. turn `Run count : 1` into `1`).
  - `/Last run time: 1[^0-9]/` — match **only** the *first* (newest) run-time line, not lines 2-8. (`[^0-9]` means "followed by a non-digit," so it matches `1 ` but not `10`.)
  - `sub(/\..*/,"",l)` — drop the fractional seconds for readability.
  - `printf "%-28s runs=%-3s ..."` — print the fields in neat aligned columns (`%-28s` = left-justified 28-character text field).

**Expected output (real, from Case 001):**
```
AM_DELTA.EXE                 runs=1   last=Sep 18, 2020 22:44:32 loaded=13 files
APPLICATIONFRAMEHOST.EXE     runs=7   last=Sep 19, 2020 01:07:38 loaded=77 files
AUDIODG.EXE                  runs=8   last=Sep 19, 2020 05:18:45 loaded=79 files
...
COREUPDATER.EXE              runs=1   last=Sep 19, 2020 03:40:... loaded=... files
...
```
196 of the 197 files summarize cleanly; one (`VSSVC.EXE-6C8F0C66.pf`) is genuinely corrupt and is skipped by `2>/dev/null` (Exercise 3).

### Step 3 — Put it in execution order (build a mini-timeline)
Add a sort so the runs line up chronologically around the incident window:

```bash
for f in /data/prefetch/*.pf; do
  prefetch "$f" 2>/dev/null | awk '
    /Executable filename/    {n=$0; sub(/.*: /,"",n)}
    /Last run time: 1[^0-9]/ {l=$0; sub(/.*: /,"",l); sub(/\..*/,"",l)
                              printf "%s | %s\n", l, n}'
done | sort
```
- `| sort` — orders the lines alphabetically; because the date format starts with the month/day, related events cluster together. (For a *true* chronological sort you'd use the `pf.csv` ISO timestamps; see the shortcut below.)

**Shortcut — just read the pre-parsed CSV.** The folder ships `pf.csv` with PECmd-style columns already extracted. To sort the whole host by real run time without any parsing:
```bash
sort -t, -k4 /data/pf.csv | column -s, -t | less -S
```
- `-t,` — fields are separated by commas.
- `-k4` — sort by **column 4** (`LastRun`, which is in `YYYY-MM-DD HH:MM:SS` ISO order, so it sorts correctly).
- `column -s, -t` — pretty-print the CSV into aligned columns; `less -S` — scroll without wrapping long lines (`q` to quit).

### Step 4 — Compare a benign baseline file against the suspect (multi-file reasoning)
A single file in isolation rarely looks "wrong." You judge it by comparison. Parse a known-good system binary and the suspect side by side:

```bash
echo "===== BENIGN BASELINE: SVCHOST ====="; prefetch /data/prefetch/SVCHOST.EXE-12871F9D.pf 2>/dev/null | grep -E "Executable filename|Run count|Last run time: 1|Number of filenames"
echo "===== SUSPECT: COREUPDATER ====="; prefetch /data/prefetch/COREUPDATER.EXE-157C54BB.pf 2>/dev/null | grep -E "Executable filename|Run count|Last run time: 1|Number of filenames"
```
- `grep -E "...|..."` — print only the lines matching any of these labels (a quick way to line up the same four fields from two different files). `-E` enables the `|` ("or") syntax.

**Read the comparison:** `svchost.exe` is a high-frequency OS service — many runs, many DLLs loaded from System32, unremarkable timing. `coreupdater.exe` is the opposite: it runs a handful of times, in the incident window, with a name that *imitates* a system updater. The contrast — not either file alone — is what flags it. This "baseline vs. outlier" instinct is the heart of every later module.

### Step 5 (Windows VM) — the richer CSV with PECmd
The container's parser has no CSV export. On the **Windows** VM, the deck's PECmd does:
```
PECmd.exe -d C:\Windows\Prefetch --csv C:\DFIR\out --csvf prefetch.csv
```
- `-d <dir>` — parse a whole **d**irectory of `.pf` files (use `-f <file>` for a single one).
- `--csv <dir>` — folder to write the CSV report into.
- `--csvf <name>` — the CSV **f**ilename to use.

This produces a timeline-ready spreadsheet (`ExecutableName, RunCount, LastRun, Volume..., FilesLoaded, ...`) — the same information you assembled by hand above, plus all 8 run times broken out. Use PECmd on the VM; use the loop in the container.

---

## 5. Reading the output — benign vs suspicious

| Field | What it means | Benign looks like | Suspicious looks like |
|---|---|---|---|
| **Executable** | program name | `SVCHOST.EXE`, `EXPLORER.EXE` | a System32-sounding name in a weird place, a typo (`scvhost.exe`), or an unknown name |
| **RunCount** | times executed | high counts for OS tools | a normally-rare tool with `runs=1` at an odd hour |
| **LastRun (UTC)** | most recent execution | during business hours / patching windows | 2-5 AM, right inside the incident window |
| **FilesLoaded** | DLLs/paths touched | DLLs from `\Windows\System32\` | a DLL loaded from `\Temp\`, `\AppData\`, `\Users\Public\` (side-loading) |

**Rules of thumb:**
- A binary in Prefetch but **not** in ShimCache (Module 2) or Amcache (Module 3) — or vice-versa — is a gap worth explaining; the three artifacts cover each other's blind spots.
- LOLBins (*Living-Off-the-Land Binaries*: legit Windows tools attackers abuse — `powershell.exe`, `rundll32.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`) running at unusual times deserve a look at *what they loaded* and *what ran right after*.
- Always apply the **10-second rule** when timelining: the recorded run is the real start; the file's on-disk timestamp is ~10s later.

---

## 6. Investigative narrative (Case 001)

In Case 001, the desktop `DESKTOP-SDN1RPT` was compromised. Among the 197 Prefetch files sits **`COREUPDATER.EXE-157C54BB.pf`** — a name engineered to look like a legitimate updater. Prefetch proves it **executed** on this host on **2020-09-19**, in the small hours, and its loaded-files list shows where it ran from. That single fact — *it ran, here, at this time* — is the anchor. In Modules 2-4 you'll confirm the same binary's **identity** (its SHA1 fingerprint) and learn it's the malware at the center of the case. Prefetch is the corner of the **Triad** that answers **"did it run, and when?"**

---

## 7. Try-it-yourself exercises

1. **Find the LOLBins.** Run the Step-3 sorted loop. Which `POWERSHELL.EXE`, `RUNDLL32.EXE`, `CMD.EXE`, or `WSCRIPT.EXE` entries appear, and when did they last run? (All are present in this data.) Do any cluster around the `2020-09-19` early-morning window?
2. **Inspect the malware's loaded files.** `prefetch /data/prefetch/COREUPDATER.EXE-157C54BB.pf` — read its **Filenames** section. What paths did it touch? Any in `\Temp\`, `\AppData\`, or `\Users\Public\`? (You'll cross-check this binary's identity in Modules 3-4.)
3. **Meet a real corrupt artifact.** Run `prefetch /data/prefetch/VSSVC.EXE-6C8F0C66.pf` directly (no `2>/dev/null`). Note the `libscca` read error. In the loop, `2>/dev/null` skipped it so processing continued — exactly how you handle a damaged artifact in a real case (document it, move on).
4. **Run-count reasoning.** Open `pf.csv` and find a program with `RunCount` far higher than the number of distinct timestamps shown. Explain why (only the last 8 runs are timestamped).
5. **10-second rule.** Pick any entry's `LastRun`. If a teammate says "the file's creation time on disk is 10 seconds later — which is the real execution time?", what's your answer and why?

---

## 8. Key takeaways

- **Prefetch exists for speed, but it's execution gold:** name, **run count**, **last 8 run times**, and **files loaded** per program.
- The **filename hash** ties a run to a *path*, so the same program from two folders leaves two `.pf` files — great for spotting an out-of-place copy.
- **The 10-second rule:** the recorded run time is the real start; the file's on-disk time is ~10s later.
- **Absence isn't innocence:** Prefetch can be disabled, capped at 1024, aged out, or deleted by an attacker.
- In the **Triad**, Prefetch answers **"did it run, when, how often?"** — confirm **existence** in Module 2 (ShimCache) and **identity/SHA1** in Module 3 (Amcache).

## Sources & further reading
This module's structure follows the standard DFIR teaching of Prefetch. To go deeper:
- **libscca — Windows Prefetch File (PF) format** (the open-source format spec the container's `prefetch` tool implements): https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
- **PECmd / EZ Tools** (Eric Zimmerman's official tools + docs): https://ericzimmerman.github.io/ and the AboutDFIR EZ Tools manual: https://aboutdfir.com/toolsandartifacts/windows/eric-zimmermans-tools/
- **Yogesh Khatri — "Windows Prefetch (.PF) files"** (the classic deep-dive on the format, hash, and timestamps): http://www.swiftforensics.com/2013/10/windows-prefetch-pf-files.html
- **Magnet Forensics — "Forensic Analysis of Prefetch files in Windows"** (the 10-second rule, run counts, what you can prove): https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/
- **13Cubed — "Investigating Windows Prefetch"** (excellent free video walkthrough): https://www.youtube.com/c/13cubed
- **DFIR Madness — Case 001** (the dataset these `.pf` files come from): https://dfirmadness.com/the-stolen-szechuan-sauce/

## Pivot
- A binary of interest here → confirm it in **Module 2 (ShimCache)** and **Module 3 (Amcache)**, and grab its **SHA1** from Amcache to hunt the same file on other hosts in **Module 4**.

---
*Next: [Module 2 — ShimCache](../module-02-shimcache-appcompatcache).*
