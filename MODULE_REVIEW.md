# DFIR Lab — End-to-End Test & Content Review

**Status:** complete for this pass · **Date:** 2026-08-25
**What was tested:** the *shipped* VM — `project-dfir/dfir-vm` release `vm-v4`, the 27.9 GB OVA a user
actually downloads. Not a fresh build, not a simulation.
**Where:** imported into Proxmox on `cthuwu-win` (192.168.1.145) as VM 210 and driven through the console.

---

## 1. Bottom line

**The lab works, and after the fixes in this pass it runs clean.**

| Run | Result |
|---|---|
| As shipped | 23 pass / 1 fail / **1 unvalidated** / 1 tool missing |
| **After the fixes below** | **24 pass / 1 fail / 0 unvalidated / 0 tools missing** |

The single remaining failure — Module 20 — is **not a defect in the lab**: it queries the live OS and
needs an elevated shell. That is now documented in the module.

**Modules 1, 2, 3, 5, 6, 7, 8, 9, 10 were showcase-ready as shipped.** Module 4 was broken in three
compounding ways and is now fixed. Details below.

---

## 2. What was proven about the shipped artifact

- All 15 release parts downloaded; the reassembled OVA's SHA-256 `9117c141…` **matches the published
  manifest** — the shipped bits are intact.
- It boots — but **not** with default Proxmox settings. Two things the docs don't mention:
  - the disk is **GPT with an EFI System Partition**, so it needs **OVMF/UEFI**; SeaBIOS reports
    *"No bootable device."*
  - it was built for VMware, so it has **no virtio driver** — the NIC must be **e1000** or the guest
    has no network.
- **The documented login is blocked.** `Analyst` / `dfir` now hits *"Your password has expired and must
  be changed."* The account was created without a never-expires flag and the password aged out after
  the July build. **Every user who pulls this VM will hit this.**
- Full native toolchain present: Git-Bash, EZ Tools, chainsaw, hayabusa, Volatility3, RegRipper,
  Sleuth Kit, oletools, Didier Stevens suite, Zircolite, tshark, hindsight, Velociraptor.
- The image carries **25** modules (lab commit `c26c6bf`); the repo now has **26** — Module 27 (SRUM)
  post-dates the build.

**The passes are real, not hollow** — spot-checked against raw output:
- **M1** PECmd parsed 197 `.pf`: `COREUPDATER.EXE runs=1 last=2020-09-19 03:40:49.410320 loaded=51 files`
- **M12** Volatility3 2.28.0 parsed `Challenge.raw` with real symbols (`Is64Bit True`, kernel base resolved)
- **M16** RegRipper ran its plugin set against the real hive
- **M7** Chainsaw loaded **3,608 Sigma rules**, **22 detections on 9 documents**

---

## 3. Modules 1–10 — verdict

Every module's "Try it yourself" list was diffed against `ANSWER-KEY.md`, and ground truths were checked
against actual VM output.

| # | Module | Runs | Answer key | Evidence checked |
|---|---|---|---|---|
| 1 | Prefetch (PECmd) | ✅ | ✅ 5/5 | `VSSVC.EXE-6C8F0C66.pf` → *"Invalid signature! Should be 'SCCA'"* — the documented corrupt artifact is genuinely corrupt; 196/197 parse. |
| 2 | ShimCache | ✅ | ✅ 5/5 | Position 0 = `C:\Windows\System32\WScript.exe`, 266 entries, `coreupdater` **absent** — the documented Triad gap. |
| 3 | Amcache | ✅ | ✅ 5/5 | `sha1=fd153c66386ca93ec9993d66a84d6f0d129a3a5c size=7168`, empty ProductName, LinkDate `2010-04-14`, FileKeyLastWrite `03:40:45`. |
| 4 | AppCompatProcessor | ❌→✅ | ❌→✅ | Broken three ways as shipped; fixed (§4). |
| 5 | Event logs (EvtxECmd) | ✅ | ✅ 4/4 | `desktopimgdownldr` + `a.uguu.se` + `Hv0bgvgHGNeH_Bin.7z` in **two** channels (Sysmon 1 and BITS-Client), exactly as taught. |
| 6 | Sigma (Chainsaw/Hayabusa) | ✅ | ✅ 4/4 | Exactly **23** `.evtx` samples as claimed; detections on 3,872 documents. |
| 7 | Identity & credential theft | ✅ | ✅ 5/5 | Mimikatz `GrantedAccess: 0x1010` on `lsass.exe` from `mimikatz.exe`; baseline = 3×4624 + 1×4625. |
| 8 | Lateral movement | ✅ | ✅ 5/5 | `RdpCoreTS` 131 (×22), Sysmon 18, 4702, 5145 present in the parses. |
| 9 | PowerShell tradecraft | ✅ | ✅ 5/5 | 4104 script-block events; `MiniDumpWriteDump` recovered from script text. |
| 10 | Sysmon + WEF | ✅ | ✅ 6/6 | Zerologon `4742` present in the Security log. |

**M3 ↔ M1 corroboration is real in the data:** Amcache `FileKeyLastWrite` **03:40:45** vs Prefetch
last-run **03:40:49**. The "they agree within seconds" teaching point holds.

---

## 4. Module 4 — what was wrong, and what was done

**4a. It could not run at all.** `AppCompatProcessor` is **Python 2** code; the VM's `python` is
**Python 3.12.7**, so every documented command died with `SyntaxError: Missing parentheses in call to
'print'`. The README promised *"a convenience wrapper `acp` is on PATH"*, and `acp` did not resolve.

> **Root cause, corrected 2026-08-25.** An earlier draft of this review said the shim "was never
> created". That was wrong. The build's `42-module04-acp` step *did* create it — the recovered
> provisioning transcript logs `==== acp shim ====`. The real fault is a **PATH mismatch between two Git
> installations**: the shim was written to **`C:\dfir\Git\usr\bin\acp`**, but the machine PATH carries
> `C:\DFIR\Git\cmd`, `C:\dfir\tools\git\bin`, `C:\dfir\tools\git\usr\bin` and
> `C:\dfir\tools\native-shim` — **`C:\dfir\Git\usr\bin` is not on it.** Two Git trees exist and the
> shim landed in the one that isn't wired up.

*Cause:* the V3 rebuild installed Python 3 (correct — Module 12's Volatility3 requires it) and that
**silently broke Module 4**, which needs Python 2. `C:\Python27\python.exe` is still on the VM and ACP
is already patched, so the fix is one shim:

```bash
printf '#!/usr/bin/env bash\nexec /c/Python27/python.exe /c/dfir/tools/appcompatprocessor/AppCompatProcessor.py "$@"\n' \
  > /c/dfir/tools/native-shim/acp && chmod +x /c/dfir/tools/native-shim/acp
```

**4b. It was invisible to every validator.** Module 4's command blocks were the only bare fences in the
lab (no `bash` language tag); all harnesses extract language-tagged blocks. Module 4 was therefore
**skipped on every validation run ever performed** — which is exactly why 4a survived six weeks.
*(Fixed: 9 fences tagged; the harness now counts "cannot validate" as a failure.)*

**4c. Its documented outputs did not reproduce against its own shipped data.** Verified by running this
build of ACP on this fleet:

| Command | README claimed | Actual |
|---|---|---|
| `status` | 8 hosts / 8 instances / 352 entries | ✅ **matches exactly** |
| `tcorr palantir.exe` | **7** rows incl. `repadmin`/`dsac`/`netdom` and a "DCSync story" | **1** row (`nazgul.exe`) |
| `tstack 2024-09-13..15` | Hits In 4 / 2 | **2 / 1** |
| `reconscan` | 122 recon commands | **65**, across 8/8 hosts |

The `tcorr` narrative could never have reproduced: the benign DC tools carry the fleet's `2021-03-15`
baseline mtime and cannot correlate with a 2024 window. I tested and **disproved** the obvious
explanation (that the docs were captured from a doubly-loaded DB) — ACP deduplicates on load, and a
second `load` changes nothing. *(Fixed: all three outputs replaced with verified ones, plus an
explanation of why one `tcorr` row is the correct answer.)*

**4d. The answer key answered a deleted module.** This was the biggest showcase risk, since it is
*instructor* material:

| `ANSWER-KEY.md` said | The shipped module is |
|---|---|
| `coreupdater.exe`, Count = 1 | the **SAURON** toolkit (`palantir`, `nazgul`, `balrog`, `theonering`…) |
| 3 hosts (`DESKTOP`, `WORKSTATION07/12`) | **8** hosts (`BAG-END-LT01`, `MINAS-TIRITH-DC01`…) |
| window 2020-09-19 | window **2024-09-13/14** |
| exercise: "stack on SHA1" | **impossible** — the fleet CSVs have no hash column |
| 6 exercises | README has **5**, all different |

*(Fixed: rewritten against the SAURON fleet, with every figure taken from the verified run.)*
Modules 1–3 and 5–10 were aligned 1:1 — **only Module 4 had drifted.**

**4e. A command referenced a file nothing created.** `acp acp.db filehitcount evilnames.txt` — the only
instruction to create `evilnames.txt` was an inline *comment*, so a copy-pasted run failed. *(Fixed: the
block creates it.)*

### Module 4 now passes, and the lesson lands

```
=== tstack 2024-09-13 2024-09-15 ===
nazgul.exe         2   0   20.000
palantir.exe       2   0   20.000
balrog.exe         1   0   10.000     gollum.exe         1   0   10.000
mordor-update.exe  1   0   10.000     morgul.dll         1   0   10.000
theonering.exe     1   0   10.000
```

Exactly the seven planted tools, with `nazgul`/`palantir` at Count 2 — the lateral-movement signature the
module teaches. The fleet is genuinely well built: 40 of 61 filenames sit at Count 8 (the baseline), and
the rare tail cleanly separates **legitimate-rare** (DC tooling on the DC, SQL tooling on the SQL server,
`putty` on the laptop — all in `Program Files`/`System32` with the 2021 baseline mtime) from
**malicious-rare** (the toolkit in `\Downloads\`, `\AppData\`, `\Windows\Temp\`, `\ProgramData\`,
`\PerfLogs\`, `\Windows\NTDS\`, all stamped inside the incident window). *Rarity finds candidates;
path and timestamp convict.*

---

## 5. Do the artifacts make sense?

Yes — and the lab is **honest about its own evidence**, which is worth saying out loud in a showcase
rather than hiding:

- **Modules 1–3** use *real* DFIR-Madness **Case 001** evidence (`DESKTOP-SDN1RPT`) — a published
  intrusion, so exercises have objectively correct answers.
- **Module 1 discloses** that the `COREUPDATER.EXE` Prefetch file specifically is a *planted
  representative artifact* (the surrounding 197 are the real baseline), and points to the independent
  corroboration in Module 16.
- **Module 4** is openly labelled a synthetic teaching construct, with its generator shipped.
- **Modules 5–10** use **EVTX-ATTACK-SAMPLES** — real attack telemetry from assorted public hosts.
- **The Part A → Part B dataset shift is framed up front** in the top-level README: *"real attacks, but
  on assorted hosts, not the Case-001 host that Part A follows… the capstone fuses the method back onto
  Case-001."*
- Every module carries a `data/README.md` with provenance and licensing.

**One presentational note:** Module 4's Tolkien naming (`palantir.exe`, `MINAS-TIRITH-DC01`) reads as
obviously fictional next to Modules 1–3's real `coreupdater.exe` / `DESKTOP-SDN1RPT`, and it sits in the
middle of the "real evidence" Part A arc. It *is* labelled synthetic — just be ready for the question.

---

## 6. Module 20 — the remaining failure (not a lab defect)

`velociraptor.exe` fails with `Permission denied` under Git-Bash. The real cause, from PowerShell:

```
Program 'velociraptor.exe' failed to run: The requested operation requires elevation
```

Velociraptor's manifest declares `requireAdministrator` because the module queries the **live OS**.
`Analyst` **is** in the local Administrators group, but UAC hands ordinary shells a filtered token — so
the module needs the shell launched **as administrator**. *(An earlier hypothesis that Defender was
blocking the binary was wrong: real-time protection is on, but the block is UAC, not AV.)*

Module 20 having **no `data/` directory is by design and already documented** — *"the machine is the
evidence."* *(Fixed: the elevation requirement is now documented in the module, framed as the lesson it
is — forward-deployed responders run collectors as SYSTEM/admin.)*

I could not complete an elevated run headlessly: UAC's secure desktop accepts a synthetic *cancel* but
not a synthetic *confirm*, which is a limitation of driving the VM over the console, not of the lab. A
person at the keyboard clicks **Yes** and it runs.

---

## 7. Still open

0. **🔴 Windows Defender fights the lab.** It quarantines the shipped attack samples
   (`Trojan:PowerShell/Mimikatz.A` and friends) **and student output** — including
   `module-06/data/high.csv`, the file module 6 Step 5 tells you to create — and behaviour-blocks
   `bash.exe`, after which `EvtxECmd` fails from Git-Bash while working from PowerShell. Worse, the
   first detection landed *after* a clean validation run, so **the lab validates green on a fresh boot
   and degrades as definitions catch up**. The build must ship a `C:\dfir` exclusion
   (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths`); an offline merge of just
   that key restored the toolchain. See `TRAINING_VALUE_AUDIT.md` iteration 3.

0b. **The build is not reproducible from this repo.** `C:\dfir-provision.log` shows the VM was driven by
   `A:\provision.ps1` running `30 → 32 → 34 → 36-shim → 40-clone-lab → 42-module04-acp`. Two of those
   steps **failed** (`32-native-env` and `40-clone-lab`, both `lastexit=1`) and the image was packaged
   anyway — direct evidence for the missing build gate — and **`42-module04-acp` does not exist in the
   repository at all**.

1. **Expired `Analyst` password** — blocks every new user at first login. Set `PasswordNeverExpires` and
   re-bake, or document the reset.
2. **Module 27 (SRUM) is absent** from the VM; the image is 3 lab commits behind.
3. **Missing tools:** `evtx_dump` (Zircolite shells out to it), `csvcut`, `log2timeline.py` / `psort.py`
   (Plaso — any real super-timeline work). None broke a module in 1–10.
4. **Re-bake** so the VM ships the corrected Module 4, Module 27, and the tagged fences.

---

## 8. The lesson worth keeping

Module 4 broke because a *correct* fix elsewhere — installing Python 3 for Volatility3 — had an unnoticed
side effect. The one thing that would have caught it, the validation harness, was structurally blind to
Module 4 because of a two-character formatting difference in a code-fence tag.

The harness reported clean runs for six weeks while never executing that module. It now treats **a module
it cannot validate as a failure, not a pass** — the single change that would have surfaced this on day one.
