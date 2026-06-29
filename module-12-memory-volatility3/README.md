# Module 12 — Memory Forensics with Volatility 3

**Deck mapping:** *Advanced Intrusion Forensic Hunting* → "Triage & live response" / memory analysis.
**Goal:** take a snapshot of a Windows machine's **RAM** and reconstruct what was actually running, talking on the network, and hiding in memory **at the moment of capture** — the evidence that never touches the disk.

---

## 1. Background — why this matters

### What a memory image actually is
Everything a computer is *currently doing* lives in **RAM** (random-access memory): every running program, every open network connection, every password the user just typed, every chunk of malware that was decrypted so the CPU could run it. RAM is **volatile** — pull the power and it is gone forever. A **memory image** (also called a *memory dump* or *RAM capture*) is a byte-for-byte copy of that RAM, frozen to a file while the machine is still running, so you can study it later.

Disk forensics (Modules 1-11) reads what was **written to storage**. Memory forensics reads what was **alive in RAM**. They answer different questions, and the memory questions are often the ones that crack a case:

- **What was actually running** at capture time — including processes hidden from Task Manager or unlinked by a rootkit?
- **What code was injected** into a legitimate process — *fileless* malware that exists only in memory and was never a file on disk?
- **What network connections were open**, and to which remote IP — command-and-control (C2) beacons?
- **What exact command line** launched each process — the attacker's tradecraft, including encoded PowerShell?
- **What was decrypted or unpacked** — malware that is encrypted on disk is plaintext in RAM.

> **The one-line idea:** *disk can lie; memory tells the truth at the moment of capture.* A rootkit can hide a file on disk and remove its process from the visible list, but the kernel structures that actually back that process are still sitting in RAM, and Volatility walks them directly.

### How a memory image is captured (context)
Acquisition is a **separate step** done on the live machine *before* analysis, with a tool such as **DumpIt**, WinPMEM, Magnet RAM Capture, or FTK Imager — or by grabbing a virtual machine's RAM file (VMware `.vmem`, Hyper-V `.bin`, VirtualBox `.sav`) or a `hiberfil.sys`/crash dump. The tool produces one flat file; Volatility consumes it. (In *this* module's image you will literally see the acquisition tool, `DumpIt.exe`, still running in the process list — a nice reminder that capturing RAM is itself an action that leaves a trace.)

### What an investigator proves with a memory image
A RAM capture is a **freeze-frame of the live machine**. With it you can prove:
- **what was executing** and its full parent→child ancestry (process injection, masquerading);
- **what it was connected to** (C2, exfiltration);
- **what it typed** (recovered command lines and console buffers);
- **what it hid** (unlinked processes, injected code) — and you can **carve the live payload back out** of RAM to feed `capa`, FLOSS, and YARA (other tools in the lab's container).

---

## 2. What the tool does — Volatility 3

**Volatility 3** is the open-source **framework for memory forensics**, maintained by the Volatility Foundation. It is a complete rewrite of the older Volatility 2. In the container it is on the `PATH` as **`vol`**. It does three things:

1. **Rebuilds the operating system's view of RAM.** A dump is just billions of unlabelled bytes. The CPU uses *page tables* to translate the virtual addresses programs see into physical RAM addresses; Volatility finds the kernel's master page table (the **DTB**, Directory Table Base) and reconstructs that same translation, so it can read memory the way Windows did.
2. **Uses symbol tables to find structures.** To know that "in this Windows build, a process's name is at offset X inside the `_EPROCESS` structure," Volatility ships **symbol tables** — JSON maps of every kernel structure for every Windows build, in *Intermediate Symbol Format (ISF)*. These live in `windows.zip` inside the container, so **Windows analysis works fully offline**. (Volatility 3 replaced Volatility 2's old `--profile` system with these auto-detected symbols — there is **no `--profile` flag** any more.)
3. **Runs plugins that walk the kernel's own data structures.** For example `windows.pslist` walks the same linked list of processes that Task Manager uses; `windows.psscan` instead *scans* the whole dump for the fingerprint of a process structure, so it finds processes even after they were hidden or have exited.

> **Plain-language summary:** Volatility teaches itself the layout of the captured Windows version from bundled symbol maps, rebuilds how the OS saw its own memory, and then lets you ask focused questions ("list the processes," "show injected code," "show network connections") with one short command each.

---

## 3. The scenario in this module's data

You are handed **one Windows 7 memory image** (`Challenge.raw`) captured from a workstation belonging to a user called **`Jaffa`**. The SOC's tip-off: *Jaffa is suspected of staging sensitive files for exfiltration inside a password-protected archive.* A first responder ran **DumpIt** on the live box and shipped you the RAM capture. Your job is classic **live-response triage**:

1. confirm what host and when (anchor the timeline);
2. enumerate what was running and prove nothing is **hidden**;
3. find the **suspicious user activity** and corroborate it;
4. rule **in or out** the three things memory is best at exposing — **code injection**, **C2 network connections**, and **service persistence**.

This image is a real, publicly-published forensics-challenge capture (see `data/README.md` for exact origin, license, and how to fetch it — it is **too large to ship in the repo**, so a `get-data.sh` downloads it). It is **not** a malware-infected host, and that is deliberate: a huge part of triage is learning to read a **mostly-clean machine**, tell the benign noise from the real signal, and state confidently *"there is no implant or C2 here"* — which is itself a finding. Where the course's intrusion-arc malware (`coreupdater.exe`, Case 001) **would** have lit these plugins up, this module shows you exactly what those same plugins look like on a host that has only an **insider** problem.

> **How this ties to the rest of the lab.** Modules 1-4 proved *a binary existed and ran* from disk artifacts. Memory forensics is the other half: it shows *what a program was doing and talking to at capture time*, and lets you extract the live payload. Typical pivot on a real intrusion: `netscan` (a beacon) → owning PID → `cmdline`/`pstree` (how it launched) → `malfind`/`dlllist` (the payload) → `capa`/YARA (what it is).

---

## 4. Setup

```bash
cd module-12-memory-volatility3/data
sh get-data.sh        # one-time: downloads Challenge.raw (~1.5 GB). Online host only.
docker run -it --rm --network none -v "$PWD":/data dfir-aio:v2
```
- **`get-data.sh`** — fetches and unpacks the memory image into `data/` (it is far too big to commit). Run it on a machine with internet; the analysis itself is offline.
- **`docker run`** — start a container from an image.
- **`-it`** — interactive terminal (a shell inside the container).
- **`--rm`** — delete the container on exit (keeps your machine clean).
- **`--network none`** — give the container **no network at all**. Forensics should be offline by default; this proves the evidence cannot phone home, and Volatility's Windows symbols are bundled so nothing needs downloading.
- **`-v "$PWD":/data`** — **mount** the current folder into the container at `/data` so `vol` can read the image and write dumps back out.
- **`dfir-aio:v2`** — the all-in-one DFIR container; Volatility 3 is inside it as `vol`.

Every command below is run **inside** that container, where the image is at `/data/Challenge.raw`.

> **One-shot form (no interactive shell):** you can also run a single plugin per `docker run`, which is handy for scripting:
> ```bash
> docker run --rm --network none -v "$PWD":/data dfir-aio:v2 vol -f /data/Challenge.raw windows.info
> ```

> **A note on speed.** The **first** plugin you run on a fresh image is slow — Volatility scans the whole file to locate the kernel and build a cache. Every later plugin on the same image is much faster.

---

## 5. Step-by-step walkthrough

> Universal flags you will reuse: **`-f FILE`** = the image to analyse (required); **`-q`** = quiet (hide the progress bars); **`-r csv`** = render output as CSV (great for grepping/timelining); **`-o DIR`** = where to write dumped files. Volatility 3 **auto-detects** the OS — you never specify a profile.

### Step 1 — Identify the image (`windows.info`), always first
```bash
vol -q -f /data/Challenge.raw windows.info
```
- **`windows.info`** confirms Volatility found a valid kernel and matched its symbols. If this works, every other plugin will too.

**Real output (trimmed):**
```
Kernel Base      0xf80002609000
DTB              0x187000
Symbols          ...windows.zip!windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz
Is64Bit          True
NTBuildLab       7601.17514.amd64fre.win7sp1_rtm.
SystemTime       2019-08-19 14:41:58+00:00
NtSystemRoot     C:\Windows
KeNumberProcessors  1
```
**Read it:** the host is **Windows 7 SP1, 64-bit** (`win7sp1_rtm`, `Is64Bit True`), single CPU, and — crucially — the capture froze the machine at **2019-08-19 14:41:58 UTC**. That timestamp is the anchor for every time you read below; all Volatility times are **UTC**. The `Symbols` line shows Volatility picked the exact `ntkrnlmp.pdb` ISF for this build straight out of the offline `windows.zip`.

### Step 2 — List the processes (`windows.pslist`)
```bash
vol -q -f /data/Challenge.raw windows.pslist
```
- **`windows.pslist`** walks the kernel's **doubly-linked list of active processes** (`ActiveProcessLinks`) — the same list Task Manager shows.

**Real output (trimmed to the interesting rows):**
```
PID   PPID  ImageFileName    Threads Handles CreateTime (UTC)
4     0     System           78      495     2019-08-19 14:40:07
496   384   lsass.exe        7       513     2019-08-19 14:40:11
1944  1844  explorer.exe     35      894     2019-08-19 14:40:19
880   1944  cmd.exe          1       21      2019-08-19 14:40:26
2124  1944  chrome.exe       27      662     2019-08-19 14:40:46
2080  3060  firefox.exe      59      970     2019-08-19 14:41:08
3716  1944  WinRAR.exe       7       201     2019-08-19 14:41:43
4084  1944  DumpIt.exe       5       46      2019-08-19 14:41:55
```
**Read it.** Most of this is a normal Win7 desktop (System, lsass, explorer, browsers). Two rows matter for our tip-off:
- **`WinRAR.exe` (PID 3716)**, a child of `explorer.exe` (PID 1944 — i.e. launched by the user double-clicking), started at **14:41:43**, ~15 seconds before capture.
- **`DumpIt.exe` (PID 4084)**, also a child of explorer, started at **14:41:55** — this is the **acquisition tool itself**, which explains how this very image was made. Seeing your own capture tool in the dump is normal and expected.

**What "suspicious" looks like in a pslist** (not the case here, but what you hunt for): processes with **odd parents** (`winword.exe`→`cmd.exe`→`powershell.exe`), **misspelled system names** (`svch0st.exe`, `lsasss.exe`), or a real system name running from the **wrong path** (the genuine `svchost.exe` is always under `C:\Windows\System32`). None of those appear here.

### Step 3 — See the parentage as a tree (`windows.pstree`)
```bash
vol -q -f /data/Challenge.raw windows.pstree
```
- **`windows.pstree`** prints the *same* processes but **indented by parent→child** (each `*` = one level deeper), and — very usefully — it includes the **full command line** (`Cmd`) and on-disk **Path** of each process. Masquerading and suspicious ancestry jump out visually here.

**Real output (the rows that matter):**
```
1944  explorer.exe   C:\Windows\Explorer.EXE
* 3716 WinRAR.exe    "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"
* 4084 DumpIt.exe    "C:\Users\Jaffa\Desktop\DumpIt.exe"
* 880  cmd.exe       "C:\Windows\system32\cmd.exe"
```
**Read it — this is the break in the case.** `explorer.exe` (the user's desktop) launched **WinRAR against `C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar`**. A user opening a **password-protected `.rar`** inside a folder literally called **`pr0t3ct3d`**, sitting on the Desktop, is exactly the *staging-data-for-exfiltration* behaviour the SOC flagged. WinRAR's real path is the legitimate `C:\Program Files\WinRAR\WinRAR.exe`, so this is the genuine archiver being **used** for a suspicious purpose — not malware pretending to be WinRAR.

### Step 4 — Hunt for hidden processes (`windows.psscan`, then diff)
```bash
vol -q -f /data/Challenge.raw windows.psscan
```
- **`windows.psscan`** does **pool-tag scanning**: instead of trusting the linked list, it carves the *entire* dump for the memory signature of a process structure (the `Proc` pool tag). Because it does not rely on the list, it finds processes that a rootkit has **unlinked** (DKOM hiding) or that have already **exited**.

**The classic hidden-process hunt is to diff `psscan` against `pslist`** — anything `psscan` sees that `pslist` does not is a candidate hidden process:
```bash
vol -q -r csv -f /data/Challenge.raw windows.pslist | cut -d, -f1 | sort -u > /data/seen_list.txt
vol -q -r csv -f /data/Challenge.raw windows.psscan | cut -d, -f1 | sort -u > /data/seen_scan.txt
comm -13 /data/seen_list.txt /data/seen_scan.txt     # PIDs in scan but NOT in list
```
**Real result:** both plugins return the **same 53 processes**, and the diff is **empty**. **Read it:** no process is hidden or unlinked on this host — the visible list is the true list. (On a rootkit-infected host this diff is where the hidden implant falls out.)

### Step 5 — Read how each process was launched (`windows.cmdline`)
```bash
vol -q -f /data/Challenge.raw windows.cmdline
```
- **`windows.cmdline`** pulls the **full command line** of every process out of its **PEB** (Process Environment Block). This is one of the highest-value plugins: it exposes encoded PowerShell (`-enc …`), `rundll32` exports, download cradles, and the exact arguments a binary ran with.

**Real output (key rows):**
```
3716  WinRAR.exe   "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"
4084  DumpIt.exe   "C:\Users\Jaffa\Desktop\DumpIt.exe"
880   cmd.exe      "C:\Windows\system32\cmd.exe"
2124  chrome.exe   "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
```
**Read it:** this *independently corroborates* Step 3 from a different kernel structure (the PEB, not the process tree) — the same `pr0t3ct3d\flag.rar` argument appears. Corroboration from two structures is what makes the finding defensible. Everything else here is a normal, fully-pathed program; there is no encoded command line, no LOLBin abuse, no script cradle.

### Step 6 — Inspect a suspect process's modules (`windows.dlllist`)
```bash
vol -q -f /data/Challenge.raw windows.dlllist --pid 3716
```
- **`--pid 3716`** focuses the plugin on just WinRAR. **`windows.dlllist`** lists every **DLL loaded** into a process, with its **load path** and **load time**. You use it to spot **DLL side-loading** — a trusted EXE tricked into loading a *malicious* DLL from an unusual directory.

**Real output (trimmed):**
```
3716  WinRAR.exe  WinRAR.exe     C:\Program Files\WinRAR\WinRAR.exe
3716  WinRAR.exe  ntdll.dll      C:\Windows\SYSTEM32\ntdll.dll
3716  WinRAR.exe  kernel32.dll   C:\Windows\system32\kernel32.dll
3716  WinRAR.exe  USER32.dll     C:\Windows\system32\USER32.dll
3716  WinRAR.exe  COMCTL32.dll   C:\Windows\WinSxS\...common-controls...\COMCTL32.dll
```
**Read it:** every module loads from the **expected** locations — the EXE from `Program Files\WinRAR`, the Windows DLLs from `System32`/`WinSxS`. There is **no** DLL loaded out of the user's profile, Temp, or the `pr0t3ct3d` folder. **What suspicious looks like:** a DLL whose path is `C:\Users\…\AppData\…` or right next to the EXE in a user folder, especially one with a name close to a system DLL. Clean here.

### Step 7 — See what the process has open (`windows.handles`)
```bash
vol -q -f /data/Challenge.raw windows.handles --pid 3716
```
- **`windows.handles`** lists every **handle** a process holds open — files, registry keys, mutexes (`Mutant`), events, tokens. It reveals **the files and keys a process was actually touching**, which is gold for tying a process to an artifact.

**Real output (the decisive line, plus context):**
```
3716  WinRAR.exe  File    \Device\HarddiskVolume2\Users\Jaffa\Desktop\pr0t3ct3d
3716  WinRAR.exe  Key     MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\APPCOMPATFLAGS
3716  WinRAR.exe  Mutant  -
```
**Read it:** WinRAR holds an **open `File` handle to `\Device\HarddiskVolume2\Users\Jaffa\Desktop\pr0t3ct3d`** — i.e. at the instant of capture the process was **actively working inside the suspect folder**. That is a third, independent confirmation (after the process tree and the command line) that ties the WinRAR process to the `pr0t3ct3d` staging directory. `\Device\HarddiskVolume2` is just the kernel's name for the system drive (`C:`). For malware, `windows.handles` is also how you find a uniquely-named **mutex** a family uses as its single-instance marker.

### Step 8 — Hunt for injected / hidden code (`windows.malfind`)
```bash
vol -q -f /data/Challenge.raw windows.malfind
```
- **`windows.malfind`** is the **#1 "is there injected malware?" plugin.** It scans every process's *private* memory for regions that are **committed, executable, and not backed by any file on disk**, with **`PAGE_EXECUTE_READWRITE`** (RWX) protection — the signature of **code injection, process hollowing, and reflective DLL loading**. For each hit it prints a hex + disassembly preview.

**Real output (trimmed — four regions were flagged):**
```
1944  explorer.exe   0x4320000  VadS  PAGE_EXECUTE_READWRITE
  41 ba 80 00 00 00 48 b8 38 a1 86 ff fe 07 00 00   A.....H.8.......
  48 ff 20 90 41 ba 81 00 00 00 48 b8 38 a1 86 ff   H. .A.....H.8...
1944  explorer.exe   0x3ce0000  VadS  PAGE_EXECUTE_READWRITE  (all 00 bytes)
2124  chrome.exe     0x4830000  VadS  PAGE_EXECUTE_READWRITE  (all 00 bytes)
2292  WmiPrvSE.exe   0x1bd0000  VadS  PAGE_EXECUTE_READWRITE
```
**Read it — and this is the key lesson of malfind:** it flagged **four RWX regions**, but **none of them is malicious**. Here is how you triage that:
- The two regions full of **`00`** bytes are empty, reserved RWX scratch space — no code, so nothing injected.
- The `explorer.exe` region at `0x4320000` *does* contain code (`mov r10d, …; mov rax, 0x7fefe86a138; jmp rax`), but it is a **hot-patch / API-hook trampoline** — a tiny stub that jumps into a real, file-backed DLL. There is **no `MZ` header** (the bytes `4D 5A` that start a Windows executable) anywhere in these regions.
- `chrome.exe` and `WmiPrvSE.exe` legitimately create RWX memory for their **JIT compilers and WMI providers** — classic, well-known false positives.

> **The rule:** `malfind` finding RWX is a *lead, not a verdict*. A real injected payload usually shows an **`MZ` header** or recognisable shellcode at the top of the region, in a process that has **no reason** for RWX memory. **Legitimate JIT engines (.NET, Java, browsers) and Windows hot-patching also use RWX** — so you **corroborate** with `cmdline`, `netscan`, and a `yara`/`capa` scan of the dumped region before concluding. On this host, every hit is benign: **there is no code injection.**

### Step 9 — Find network connections (`windows.netscan`)
```bash
vol -q -f /data/Challenge.raw windows.netscan
```
- **`windows.netscan`** pool-scans the dump for **TCP/UDP endpoint and listener objects**. For each it shows **local and remote IP:port, state, the owning PID and process name**, and (for listeners/UDP) a creation time. This is how you find **C2 connections and data exfiltration** — and then map a foreign IP straight back to the process responsible.

**Real output (representative rows):**
```
Proto  LocalAddr   LPort  ForeignAddr      FPort  State        PID   Owner
TCPv4  10.0.2.15   49235  172.217.194.189  443    ESTABLISHED  2080  firefox.exe
TCPv4  10.0.2.15   49232  172.217.160.131  80     ESTABLISHED  2080  firefox.exe
TCPv4  10.0.2.15   49198  216.58.197.67    443    ESTABLISHED  2080  firefox.exe
TCPv4  127.0.0.1   49170  127.0.0.1        49171  ESTABLISHED  2968  firefox.exe
TCPv4  0.0.0.0     445    0.0.0.0          0      LISTENING    4     System
TCPv4  0.0.0.0     135    0.0.0.0          0      LISTENING    480   services.exe
UDPv4  0.0.0.0     5353   *                0                   2124  chrome.exe
```
**Read it.** The host's own address is **`10.0.2.15`** (the standard VirtualBox NAT address — this capture came from a VM, also confirmed by the `VBoxService`/`VBoxTray` processes in `pslist`). Every external connection is a **browser** (`firefox.exe` PID 2080) reaching Google ranges (`172.217.x.x`, `216.58.x.x`) on ports **80/443** — i.e. ordinary web browsing. The listeners on **445/139/135/RPC** are standard Windows services. There is **no** connection owned by `WinRAR.exe`, no odd high-port beacon to a single foreign IP, no process talking to the internet that should not be. **There is no C2.**

**To map a suspicious IP to a process you would pivot:** take the `PID` from `netscan` → run `windows.cmdline`/`windows.pstree` on that PID to see how it launched → run `windows.dlllist`/`malfind` on it for the payload. Here that pivot leads only to a normal browser.

### Step 10 — (Tool note) `windows.netstat` vs `windows.netscan`
```bash
vol -q -f /data/Challenge.raw windows.netstat
```
`windows.netstat` is the **linked-list** equivalent of `netscan` (it follows live network structures rather than carving). On **this** image, **offline**, it fails with:
```
ERROR  volatility3.plugins.windows.netstat: Unable to locate symbols for the memory image's tcpip module
```
**Why:** `netstat` needs symbols for the network driver **`tcpip.sys`**, which are *not* in the bundled `windows.zip` (that pack covers the kernel, not every third-party/driver module). With internet, Volatility could fetch the matching PDB from Microsoft; in our **offline** container it cannot, so `netstat` cannot run. **This is expected, and it is exactly why you use `windows.netscan`** for offline work — `netscan` carves the objects directly and does not need the `tcpip.sys` symbols. (If you ever *must* run `netstat` offline, you would add the `tcpip.sys` ISF to the symbol pack — note the gap and flag it to the lab maintainers.)

### Step 11 — Look for persistence in services (`windows.svcscan`)
```bash
vol -q -f /data/Challenge.raw windows.svcscan
```
- **`windows.svcscan`** enumerates Windows **services** out of memory — name, state, type, and the **binary** each service runs. Services are a favourite **persistence** mechanism (a malicious service silently relaunches the implant at every boot), so this is a standard persistence sweep.

**Real result:** **863 service entries**, every one of them a normal Windows service whose binary lives under `C:\Windows\system32\…` or `system32\drivers\…` (e.g. `Power`→`umpo.dll`, `PlugPlay`→`umpnpmgr.dll`, `nsi`→`nsisvc.dll`). A quick filter for the tell-tale of a rogue service — a binary path under a **user-writable** folder — returns nothing:
```bash
vol -q -f /data/Challenge.raw windows.svcscan | grep -Ei 'Users|Temp|AppData|ProgramData'   # -> no rows
```
**Read it:** no service runs from a user directory, no oddly-named service, nothing pointing at `pr0t3ct3d`. **There is no service persistence** on this host. **What suspicious looks like:** a `SERVICE_AUTO_START` service whose binary is `C:\Users\…\AppData\Local\Temp\svc.exe`, or a random-looking service name created minutes before capture.

### Step 12 — Carve the suspect binary out of RAM (`--dump`)
```bash
vol -q -o /data/dump -f /data/Challenge.raw windows.pslist --pid 3716 --dump
```
- **`--pid 3716`** targets WinRAR; **`--dump`** reconstructs that process's executable image from memory and writes it to the **`-o /data/dump`** output directory. (Make sure `data/dump/` exists first: `mkdir -p dump`.)

**Real output:**
```
3716  1944  WinRAR.exe  ...  3716.WinRAR.exe.0x13fdf0000-1.dmp
```
…and on the host, `data/dump/3716.WinRAR.exe.0x13fdf0000.dmp` (~2.9 MB) now exists. **Read it:** you have extracted the *live* binary as it sat in RAM — even if the file had been deleted from disk, you would still have it. From here you hand it to the lab's other tools: `capa` to infer its capabilities, FLOSS to pull obfuscated strings, and YARA to match known-bad signatures. (For a process where you only want the injected region, `windows.malfind --dump` writes just the suspicious RWX memory instead of the whole image.)

---

## 6. Reading the output — suspicious vs. benign

| Plugin | What it proves | Suspicious when… | On THIS image |
|---|---|---|---|
| `windows.info` | OS build + **capture time** | (sanity check) | Win7 SP1 x64, frozen 2019-08-19 14:41:58 UTC |
| `pslist` / `pstree` | what ran + ancestry | odd parent→child, misspelled/mispathed system names | clean tree; **WinRAR opened `pr0t3ct3d\flag.rar`** |
| `psscan` (vs `pslist`) | hidden/exited procs | a PID in `psscan` but **not** `pslist` | identical (53 = 53) → **nothing hidden** |
| `cmdline` | exact launch arguments | encoded PowerShell, LOLBin URLs, cradles | normal; corroborates the `flag.rar` argument |
| `dlllist` | loaded modules + paths | a DLL from Temp/AppData/next-to-EXE (side-load) | all from System32/WinSxS → clean |
| `handles` | files/keys/mutexes open | handle into a staging/temp dir; family mutex | **open File handle to the `pr0t3ct3d` folder** |
| `malfind` | injected RWX code | **`MZ`** header / shellcode in RWX, no reason for RWX | 4 RWX hits, **all benign** (JIT/hooks, no `MZ`) |
| `netscan` | open connections + owner | foreign-IP beacon, exfil, odd owner | only browser→Google 80/443 → **no C2** |
| `svcscan` | service persistence | service binary in a user dir; random name | 863 normal services → **no persistence** |

**Triaging the case:** the three things memory is uniquely good at exposing — **injection (`malfind`)**, **C2 (`netscan`)**, and **persistence (`svcscan`)** — are all **negative** here, and `psscan` proves **nothing is hidden**. That combination lets you state with confidence: *this is not a malware/implant case.* What memory **did** surface, corroborated three independent ways (`pstree`, `cmdline`, `handles`), is the **insider** activity: WinRAR staging a password-protected `flag.rar` in a `pr0t3ct3d` folder. A clean injection/C2/persistence result is **not** "nothing found" — it is the finding that **scopes** the incident.

---

## 7. Investigative narrative — the story the evidence tells

Reconstructed from the RAM capture of user `Jaffa`'s workstation, frozen at **2019-08-19 14:41:58 UTC**:

1. The user's desktop (`explorer.exe`, PID 1944) was in normal use — Chrome and Firefox open and browsing Google over HTTPS (`netscan`).
2. At **14:41:43**, the user launched **WinRAR** (PID 3716) directly against **`C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar`** — visible in `pstree`, confirmed in `cmdline`, and corroborated by an **open file handle** into the `pr0t3ct3d` folder (`handles`). Someone was packaging protected data into an archive.
3. Twelve seconds later, at **14:41:55**, **`DumpIt.exe`** (PID 4084) ran from the same Desktop — the first responder capturing this very image.
4. The host shows **no code injection** (`malfind`'s four RWX hits are benign JIT/hook regions with no `MZ`), **no C2 or exfil connection** (`netscan` = browsers only), **no service persistence** (`svcscan` = all-normal), and **no hidden processes** (`psscan` = `pslist`).

**Conclusion:** this is an **insider data-staging** event, not an external compromise. Memory forensics both **surfaced** the suspicious archive activity *and* **ruled out** an implant — and handed you the WinRAR binary (carved from RAM) to analyse further. On the lab's Case-001 host, these exact same plugins would instead have shown `malfind` lighting up with an injected payload and `netscan` exposing the `coreupdater.exe` beacon — same workflow, different verdict.

---

## 8. Try-it-yourself exercises

1. Run `windows.info` and write down the capture time. Then run `windows.pslist` and find every process that started in the **last 20 seconds** before that time. Which one is the acquisition tool, and which one is the suspicious user action?
2. Reproduce the **hidden-process hunt**: dump `pslist` and `psscan` to CSV (`-r csv`), diff the PID columns, and confirm the result is empty. In one sentence, explain what a *non-empty* result would have meant.
3. `windows.malfind` flagged `explorer.exe`, `chrome.exe`, and `WmiPrvSE.exe`. For each, give the reason that process legitimately holds RWX memory, and state the single byte-pattern you would look for to call a region *actually* injected.
4. Use `windows.handles --pid 3716` and find the **one** handle that ties WinRAR to the suspect folder. Why is an *open handle* stronger evidence than just seeing the path on the command line?
5. `windows.netstat` failed but `windows.netscan` worked. Explain the difference in how the two plugins get their data, and why that makes `netscan` the right choice for **offline** analysis.
6. Dump WinRAR with `--dump`, then (outside the offline container, using the lab's other tools) run `capa` and `strings`/FLOSS over the `.dmp`. Does anything point at the archive contents or the files being staged?

---

## 9. Key takeaways

- **Memory forensics answers what disk cannot:** what was *running, injected, and connected* at capture time. *Disk can lie; RAM tells the truth at the freeze-frame.*
- **Volatility 3 needs no profile** — it auto-detects the Windows build and loads the matching **symbols** from the bundled `windows.zip`, so Windows analysis is **fully offline**. Always run **`windows.info` first**; it both validates symbols and gives you the capture time.
- **Each plugin corroborates the next.** The same `pr0t3ct3d\flag.rar` finding appeared in `pstree`, `cmdline`, **and** `handles` — three independent kernel structures. Never convict on one plugin alone.
- **`psscan` vs `pslist`** is the hidden-process hunt; **`malfind`** is the injection hunt (but RWX is a *lead*, not a verdict — JIT and hot-patching are benign RWX); **`netscan`** is the C2 hunt; **`svcscan`** is the persistence hunt.
- **A clean injection/C2/persistence result is itself a finding** — it *scopes* the incident. Here it turned a "possible malware" tip into a confirmed **insider data-staging** case.
- **You can carve the live payload out of RAM** (`--dump`) and feed it to `capa`/FLOSS/YARA — even if the file is gone from disk.
- **Know the tool gaps:** `windows.netstat` needs `tcpip.sys` symbols that aren't bundled, so it fails offline — use `windows.netscan` instead.

---

## 10. Sources & further reading

- Volatility 3 — official documentation (plugin reference, symbol tables / ISF): <https://volatility3.readthedocs.io/>
- Volatility 3 — source & symbol packs, Volatility Foundation: <https://github.com/volatilityfoundation/volatility3>
- Public memory samples list (provenance of training images): <https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples>
- *The Art of Memory Forensics* (Ligh, Case, Levy, Walters) — the foundational text on the kernel structures these plugins walk.
- 13Cubed — "Investigating Windows Memory" / Volatility 3 walkthroughs (practical `malfind`/`netscan` tradecraft).
- Microsoft Learn — `_EPROCESS`, pool tags, and PDB/symbol-server background.
- Sample image provenance, name, license, and how to fetch it: see **[`data/README.md`](data/README.md)**.

---
*Previous: [Module 11 — Capstone investigation](../module-11-capstone). This module extends the lab into volatile-memory triage with Volatility 3.*
