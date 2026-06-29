# Research — RegRipper (Registry Plugin-Based Extraction)

> **Status in `dfir-aio:v2`:** PRESENT. `regripper` on `PATH` (`/opt/tools/bin/regripper`, a wrapper that runs `perl /opt/regripper/rip.pl`). **266 plugins** in `/opt/regripper/plugins`. Reports as **Rip v.3.0**. There is **no `rip.pl` on `PATH`** — call the `regripper` wrapper, or `perl /opt/regripper/rip.pl` directly. Verified on rick 2026-06-29.

> **Note:** RegRipper also ships a GUI (`rr.exe`) on Windows; in the container only the CLI (`rip`) is available, which is exactly what you want for scripted/offline work.

---

## 1. What it is and the forensic question it answers

**RegRipper** (by Harlan Carvey) is a **plugin-driven Windows Registry parser**. The registry is a hierarchical database where Windows (and applications) store configuration — and, for an investigator, a treasure trove of **evidence of execution, persistence, user activity, USB history, network connections, and system configuration**. RegRipper answers: **"Extract the forensically-interesting values from this registry hive for me, already interpreted, without me memorising hundreds of key paths."**

Instead of hand-navigating `regedit`-style, you point a plugin (or a profile of plugins) at a **hive file** and it pulls the relevant keys/values, decodes binary blobs (ROT13, timestamps, MRU orders), and prints a readable report.

### The hives and what each holds
| Hive (file) | Lives at | Key evidence |
|---|---|---|
| **SYSTEM** | `C:\Windows\System32\config\SYSTEM` | services, **ShimCache (AppCompatCache)**, USB devices, network interfaces, computer name, time zone, last-shutdown. |
| **SOFTWARE** | `…\config\SOFTWARE` | installed apps, **Run/RunOnce persistence**, OS version/install date, network profiles, **Amcache** cross-refs. |
| **SAM** | `…\config\SAM` | local user accounts, RIDs, login counts, group membership. |
| **SECURITY** | `…\config\SECURITY` | LSA secrets, audit policy. |
| **NTUSER.DAT** | `C:\Users\<u>\NTUSER.DAT` | **per-user**: UserAssist (GUI program execution), RecentDocs, **RunMRU**, TypedPaths, TypedURLs, mounted devices, WordWheelQuery (searches). |
| **USRCLASS.DAT** | `…\AppData\Local\Microsoft\Windows\` | **Shellbags** (folder browsing history). |
| **Amcache.hve** | `…\AppCompat\Programs\` | program inventory + SHA1 (see Amcache module). |

---

## 2. How it works under the hood (plain language)

A hive file is a binary database of **keys** (folders), **values** (name/type/data), and embedded **timestamps** (each key has a *LastWrite* time — when it was last modified, a key forensic timestamp). RegRipper uses the Perl **`Parse::Win32Registry`** library to read the raw hive **offline** (no Windows, no mounting), then each **plugin** is a small Perl script that knows *exactly* which key(s) hold a given artifact, how to decode the value (e.g. UserAssist names are ROT13-encoded; MRU lists store an ordering blob; FILETIME timestamps are 64-bit), and prints it cleanly. Profiles bundle many plugins to process a whole hive in one pass.

Because it's just reading a file, RegRipper is **read-only and forensically sound**, and runs on extracted hives (from a triage collection, a disk image via TSK `icat`, VSS snapshots, or `reg save` output).

---

## 3. The CLI: `rip` / `regripper`

```bash
regripper -h                      # usage
regripper -l                      # LIST all plugins (one-liners describing each)
regripper -l -c                   # list plugins as CSV (name,version,hive,description)
```

| Flag | Purpose |
|---|---|
| `-r HIVE` | the **registry hive file** to parse (**required**). |
| `-p PLUGIN` | run a **single plugin** (e.g. `-p shimcache`). |
| `-f PROFILE` | run a **profile** = a named set of plugins for a hive type (e.g. `-f system`, `-f software`, `-f ntuser`, `-f sam`). |
| `-l` | list available plugins; add `-c` for CSV. |
| `-a` | run **all** plugins applicable (auto). |
| `-g` | guess the hive type. |
| `-u` | (some builds) update/notes. |

> In RegRipper 3.0, profiles are typically named after the hive (`system`, `software`, `ntuser`, `sam`, `security`, `usrclass`, `amcache`). Confirm available profiles in this build by checking the plugins directory / `-l` output.

### Realistic invocations
```bash
# Whole-hive sweep with the matching profile (most common)
regripper -r ./SYSTEM   -f system   > SYSTEM_report.txt
regripper -r ./SOFTWARE -f software > SOFTWARE_report.txt
regripper -r ./NTUSER.DAT -f ntuser > user_bob_report.txt

# Targeted single-artifact extraction (fast, focused)
regripper -r ./SYSTEM   -p shimcache      # AppCompatCache / ShimCache (execution evidence)
regripper -r ./SYSTEM   -p services       # service persistence (PsExec, malware services)
regripper -r ./SOFTWARE -p run            # Run/RunOnce autostart persistence
regripper -r ./NTUSER.DAT -p userassist   # GUI program execution + run counts (per user)
regripper -r ./SYSTEM   -p usbstor        # USB device history (data exfil / introduction)
regripper -r ./SOFTWARE -p networklist    # networks the machine joined (SSIDs, first/last)
regripper -r ./USRCLASS.DAT -p shellbags  # folder-browsing history
```

---

## 4. High-value plugins by investigative question

| Question | Plugin(s) | Hive |
|---|---|---|
| What ran (even if deleted)? | `shimcache`, `appcompatcache` | SYSTEM |
| Persistence / autostart? | `run`, `runonce`, `services`, `appinitdlls`, `winlogon`, `tasks` | SOFTWARE/SYSTEM |
| Per-user GUI execution + counts? | `userassist` | NTUSER.DAT |
| What did the user type/open recently? | `recentdocs`, `runmru`, `typedpaths`, `typedurls`, `wordwheelquery` | NTUSER.DAT |
| Folder browsing (incl. deleted/external)? | `shellbags` | USRCLASS.DAT |
| USB / removable-device history? | `usbstor`, `usb`, `mountdev`, `mountpoints2` | SYSTEM/NTUSER |
| Local accounts / login activity? | `samparse` | SAM |
| Networks joined / interfaces? | `networklist`, `nic`, `compname`, `timezone` | SOFTWARE/SYSTEM |
| Last shutdown / current control set? | `shutdown`, `lastloggedon` | SYSTEM/SOFTWARE |

> Each plugin prints the relevant key's **LastWrite time** — note it; it often *is* the timestamp of the event you care about.

---

## 5. Reading the output / example

```bash
regripper -r ./SYSTEM -p shimcache
```
prints, per cached executable, the **path, the file's modification time**, and (on some OS versions) an **"execution flag"** — a list of binaries the OS recorded, valuable because **ShimCache survives even when the binary is deleted**. Cross-reference these paths with Prefetch (module 1), Amcache (module 3), and the `userassist` per-user execution to build the Triad picture.

`userassist` output is already **ROT13-decoded** by the plugin and shows program name, **run count**, and **last-run time** per user — direct evidence of *interactive* program execution.

---

## 6. Common pitfalls

- **Pick the right hive for the plugin.** `userassist` needs `NTUSER.DAT`, `shimcache` needs `SYSTEM`, `shellbags` needs `USRCLASS.DAT`. Wrong hive → "key not found."
- **Dirty hives:** a hive copied from a live system may have pending **transaction logs** (`.LOG1/.LOG2`); RegRipper reads the base hive and may miss the newest changes. For completeness, replay logs first (e.g. with `yarp`/`registryFlush`/EZ's `RECmd` which auto-replays) — flag this when precision matters.
- **ControlSets:** SYSTEM has `ControlSet001/002` and `Select\Current` points to the active one. Good plugins resolve `CurrentControlSet`; if you read a raw key, target the right set.
- **Plugin coverage drifts** with Windows versions; a value's location can move between builds. If a plugin returns nothing on a new OS, verify the key path changed.
- **RegRipper 2.8 vs 3.0** differ in profiles/plugin names — this container is **3.0**; use `-l` to confirm exact plugin names.
- **Timestamps are key LastWrite times**, not necessarily "event happened" times — interpret carefully.

---

## 7. Where it fits a DFIR investigation

RegRipper is the **registry-analysis engine** of triage. From a host's extracted hives it rapidly yields **execution evidence (ShimCache, UserAssist), persistence (Run keys, services), user activity (RecentDocs, Shellbags, TypedPaths), and device/network history (USBSTOR, NetworkList)** — covering several MITRE tactics from one data source. In this lab it directly backstops the ShimCache (module 2) and Amcache (module 3) modules and adds the persistence/user-activity dimensions that EVTX logs don't capture. Output drops straight into the host timeline.

---

## 8. Sources
- RegRipper repo (Harlan Carvey) — https://github.com/keydet89/RegRipper3.0 (plugins, `rip` usage).
- Harlan Carvey, *Windows Registry Forensics* (Syngress) — the authoritative text on hive structure and artifact locations.
- SANS FOR500 — Windows Registry artifact reference (UserAssist, Shellbags, USBSTOR, ShimCache).
- 13Cubed — "Investigating the Windows Registry" / RegRipper episodes.
- Microsoft Learn — Registry hives and structure (keys/values/LastWrite, ControlSets).
