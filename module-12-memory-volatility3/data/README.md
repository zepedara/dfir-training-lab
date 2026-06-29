# Module 12 — sample data

This module analyses **one Windows 7 SP1 x64 memory image**, `Challenge.raw` (~1.5 GB uncompressed). Memory images are far too large to commit to a git repo, so **the image is not stored here** — run **[`get-data.sh`](get-data.sh)** on an online host to download and unpack it into this folder.

## The image

| | |
|---|---|
| **File** | `Challenge.raw` (raw physical-memory dump, ~1,610,547,200 bytes) |
| **OS** | Windows 7 SP1, 64-bit (`7601.17514.amd64fre.win7sp1_rtm`) |
| **Capture time** | 2019-08-19 14:41:58 UTC (per `windows.info`) |
| **Acquired with** | DumpIt (the `DumpIt.exe` process is still visible in the capture) |
| **Distributed as** | `NotchItUp.7z` (7-Zip, ~342 MB) → extracts to `Challenge.raw` |
| **SHA-256 (the .7z)** | `c8f56eaadf47970c411e338a7f6f9e7dd40edfcef4eeb68a6474b527f4f35138` |

## Origin & license

This is the memory image from the **"NotchItUp"** forensics challenge of **InCTF Internationals 2019**, a public Capture-the-Flag event run by **team bi0s** (Amrita University). The challenge and its files were **published openly for practice**; the image is mirrored on the authors' public Google Drive and is catalogued in the community **[MemoryForensicSamples](https://github.com/pinesol93/MemoryForensicSamples)** list and the **[Volatility Foundation public memory-samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)** ecosystem.

- **Source write-up / provenance:** bi0s — *InCTFi 2019: NotchItUp* — <https://blog.bi0s.in/2019/09/24/Forensics/InCTFi19-NotchItUp/>
- **Sample catalogue entry:** <https://github.com/pinesol93/MemoryForensicSamples>

**License note:** like most public CTF challenge files, the image is released for **educational / training use** but ships **without an explicit open-source license file**. It contains **no malware** — it is a benign Windows 7 desktop capture whose "challenge" is recovering data the user protected in an archive. We **redistribute it by reference only** (via `get-data.sh`, not by committing it) and credit the original authors. If you intend to use it beyond personal training, check the original challenge's terms first.

## What's in it (so you know what you're looking at)

A normal Windows 7 desktop for a user named **`Jaffa`**, captured inside a VirtualBox VM (host IP `10.0.2.15`; `VBoxService`/`VBoxTray` present). 53 processes: System/lsass/explorer, Chrome and Firefox (browsing Google), and — the point of the exercise — **`WinRAR.exe` (PID 3716)** opened against **`C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar`**, plus the **`DumpIt.exe`** acquisition tool. There is no code injection, no C2, and no service persistence; see the module `README.md` for the full walkthrough.

## Fetching it

```sh
sh get-data.sh
```
The script downloads `NotchItUp.7z` from the authors' public Google Drive, verifies the SHA-256, and extracts `Challenge.raw` into this folder. It needs internet **and** a 7-Zip extractor (`7z`/`7za`/`p7zip`) — see the script header for offline guidance. The analysis itself (the module walkthrough) runs fully **offline** inside the `dfir-aio:v2` container.
