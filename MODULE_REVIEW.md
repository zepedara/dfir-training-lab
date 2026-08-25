# DFIR Lab — End-to-End Test & Content Review (Modules 1–10)

**Status:** LIVE working document · **Date:** 2026-08-25
**What was tested:** the *shipped* VM (`project-dfir/dfir-vm` release `vm-v4`, 27.9 GB OVA), booted and
driven for real — not a fresh build, not a simulation.
**Where:** imported into Proxmox on `cthuwu-win` (192.168.1.145) as VM 210.

---

## 1. Bottom line for the showcase

**The lab works.** 23 of the 25 modules in the shipped VM execute cleanly end to end, and the ones I
checked in depth produce *the exact findings the answer key documents* — real Prefetch parses, real
Sigma detections, real Volatility3 memory analysis. The teaching content is accurate, honest about its
own evidence, and internally consistent.

**Two things to fix before showcasing, both in Module 4.** Nothing else in Modules 1–10 is blocking.

| | Verdict |
|---|---|
| Modules 1, 2, 3, 5, 6, 7, 8, 9, 10 | ✅ **Run clean and match their answer keys.** Showcase-ready. |
| Module 4 | ⚠️ **Broken as shipped** — but the *content is sound*; it ran perfectly once wired (§4). |
| Module 20 (outside 1–10) | ❌ Fails — `velociraptor.exe` won't execute. |
| Module 27 | ⚠️ Not in the VM at all — it post-dates the v4 build. |

---

## 2. What was actually proven

The VM pulled, verified, imported and booted:

- All 15 release parts downloaded; reassembled OVA SHA-256 `9117c141…` **matches the published manifest**.
- Boots under Proxmox once given **OVMF/UEFI** (the disk is GPT with an EFI System Partition; SeaBIOS
  cannot boot it) and an **e1000** NIC (a VMware-built guest has no virtio driver).
- Full native toolchain present: Git-Bash, EZ Tools, chainsaw, hayabusa, Volatility3, RegRipper,
  Sleuth Kit, oletools, Didier Stevens suite, Zircolite, tshark, hindsight. **37 of 42** probed tools
  resolve on PATH.

Harness result over every module in the image:

```
=== RESULT: 23 pass / 1 fail / 1 unvalidated / 0 conceptual ===
    failed:      module-20-triage-velociraptor
    unvalidated: module-04-scaling-appcompatprocessor
LAB_VALIDATION: FAIL (2 module(s) not demonstrably runnable)
```

**The passes are real, not hollow.** Spot-checked raw output:
- **M1** — PECmd parsed 197 `.pf`; `COREUPDATER.EXE runs=1 last=2020-09-19 03:40:49.410320 loaded=51 files`.
- **M12** — Volatility3 2.28.0 parsed `Challenge.raw` with real symbols (`Is64Bit True`, kernel base resolved).
- **M16** — RegRipper enumerated its plugin set and ran `compname` against the real hive.
- **M7** — Chainsaw loaded **3,608 Sigma rules**, found **22 detections on 9 documents**.

---

## 3. Module-by-module verdict (1–10)

Every claim below was checked against **actual output from the running VM**, and every module's
"Try it yourself" list was compared against `ANSWER-KEY.md`.

| # | Module | Runs? | Answer key aligned? | Notes |
|---|---|---|---|---|
| 1 | Prefetch (PECmd) | ✅ | ✅ 5/5 | Ground truths reproduce exactly (below). |
| 2 | ShimCache | ✅ | ✅ 5/5 | Position 0 = `WScript.exe`, 266 entries, `coreupdater` absent — the documented Triad gap. |
| 3 | Amcache | ✅ | ✅ 5/5 | `sha1=fd153c66…`, `size=7168`, empty ProductName, LinkDate 2010-04-14 — all exact. |
| 4 | AppCompatProcessor | ❌ **as shipped** | ❌ **stale** | Two defects — see §4. Content itself is good. |
| 5 | Event logs (EvtxECmd) | ✅ | ✅ 4/4 | `desktopimgdownldr` + `a.uguu.se` + `Hv0bgvgHGNeH_Bin.7z` confirmed in **two** channels (Sysmon 1 and BITS-Client), exactly as taught. |
| 6 | Sigma (Chainsaw/Hayabusa) | ✅ | ✅ 4/4 | Exactly **23** `.evtx` samples as claimed; 3,608 rules loaded; detections on 3,872 documents. |
| 7 | Identity & credential theft | ✅ | ✅ 5/5 | Mimikatz `GrantedAccess: 0x1010` on `lsass.exe` from `mimikatz.exe`; baseline file = 3×4624 + 1×4625, as documented. |
| 8 | Lateral movement | ✅ | ✅ 5/5 | `RdpCoreTS` 131 events (×22), Sysmon 18, 4702, 5145 all present in the parses. |
| 9 | PowerShell tradecraft | ✅ | ✅ 5/5 | 4104 script-block events parsed; `MiniDumpWriteDump` recovered from script text. |
| 10 | Sysmon + WEF | ✅ | ✅ 6/6 | Zerologon `4742` present in the Security log, as the exercise requires. |

### Verified ground truths (samples)

- **M1 corrupt artifact is genuinely corrupt:** `VSSVC.EXE-6C8F0C66.pf` → *"Invalid signature! Should be
  'SCCA'"*. The lab teaches "document it and move on" — and 196 of 197 do parse. True as written.
- **M3 identity card:** `Unassociated,…,2020-09-19 03:40:45,fd153c66386ca93ec9993d66a84d6f0d129a3a5c,False,
  c:\windows\system32\coreupdater.exe,…,2010-04-14 22:06:53,,7168` — every field the answer key quotes.
- **M3 ↔ M1 corroboration:** Amcache `FileKeyLastWrite` **03:40:45** vs Prefetch last-run **03:40:49**.
  The "they agree within seconds" teaching point is real in the data.

---

## 4. Module 4 — the one thing to fix

Module 4 is the only module in 1–10 that fails, and it fails for **three independent reasons**. The
content is fine; the wiring and the answer key are not.

**4a. It cannot run on the shipped VM (tooling).**
`AppCompatProcessor` is **Python 2** code. The VM's `python` resolves to **Python 3.12.7**, so every
documented command dies with `SyntaxError: Missing parentheses in call to 'print'`. The README also
promises *"a convenience wrapper `acp` is on PATH"* — **there is no `acp` shim on the VM at all.**

*Why it happened:* the V3 rebuild installed Python 3 (correctly — Module 12's Volatility3 needs it) and
that **silently broke Module 4**, which needs Python 2. Nobody noticed for six weeks because of 4b.

*The fix is small — `C:\Python27\python.exe` is already on the VM and ACP is already patched.* Creating
one shim pointing at it makes the whole module work:

```bash
printf '#!/usr/bin/env bash\nexec /c/Python27/python.exe /c/dfir/tools/appcompatprocessor/AppCompatProcessor.py "$@"\n' \
  > /c/dfir/tools/native-shim/acp && chmod +x /c/dfir/tools/native-shim/acp
```

**Proven working after that fix**, on the real VM:

```
=== tstack 2024-09-13 2024-09-15 ===
FullPath           Hits In  Hits Out  Ratio
nazgul.exe         2        0         20.000
palantir.exe       2        0         20.000
balrog.exe         1        0         10.000
gollum.exe         1        0         10.000
mordor-update.exe  1        0         10.000
morgul.dll         1        0         10.000
theonering.exe     1        0         10.000
```

That is **exactly** the seven planted SAURON tools, with `nazgul`/`palantir` at Count 2 (the
lateral-movement signature the module teaches). `tcorr palantir.exe` correctly correlated
`nazgul.exe` at `C:\Windows\Temp`, `2024-09-14 02:09:48`. The lesson lands.

**4b. It was invisible to the validator.**
Module 4's command blocks are the only ones in the lab written as bare ` ``` ` fences instead of
` ```bash `. Every validation harness extracts ` ```bash ` blocks — so Module 4 was **silently skipped
on every validation run ever done**, which is precisely why 4a went unnoticed. *(Fixed: the 9 command
fences are now tagged, and the harness now treats "cannot validate" as a failure rather than a pass.)*

**4c. `ANSWER-KEY.md` Module 4 answers a version of the module that no longer exists.**
This is the one most likely to embarrass a showcase, because the answer key is *instructor material*.

| Answer key says | The shipped module actually is |
|---|---|
| `coreupdater.exe`, Count = 1 | The **SAURON** toolkit (`palantir`, `nazgul`, `balrog`, `theonering`…) |
| 3 hosts: `DESKTOP`, `WORKSTATION07`, `WORKSTATION12` | **8 hosts**, Tolkien-themed (`BAG-END-LT01`, `MINAS-TIRITH-DC01`…) |
| Incident window 2020-09-19 | Incident window **2024-09-13/14** |
| Exercise 2: *"stack on SHA1"* | **Impossible** — the fleet CSVs have no hash column (`Last Modified,Last Update,Path,File Size,Exec Flag`) |
| 6 exercises | README has **5**, all different |

Modules 1–3 and 5–10 are aligned 1:1 with their answer keys; **only Module 4 drifted.** The module was
regenerated as the synthetic 8-host fleet and its dependents were never updated. (`module-11`'s
`data/README.md` still describes the old 3-host version too.)

**4d. Minor:** the README documents `acp acp.db reconscan` returning *"Total number of potential recon
commands detected: 122"*. On the shipped fleet it returns **no output**. Also, ACP warns
`Ooops seems you don't have pyregf! AmCache loading support will be disabled` — harmless for this
CSV-based module, but it means the `tstomp` suggestion of "feed it raw hives" will not work as written.

---

## 5. Do the artifacts make sense?

Yes — and notably, **the lab is honest about its own evidence**, which is a strength worth saying out
loud during a showcase rather than hiding.

- **Modules 1–3** use *real* DFIR-Madness **Case 001** evidence (host `DESKTOP-SDN1RPT`) — a documented,
  published intrusion, so the exercises have objectively correct answers.
- **Module 1 discloses** that the `COREUPDATER.EXE` Prefetch file specifically is a *planted
  representative artifact*, with the surrounding 197 files being the real Case-001 baseline — and points
  at the independent corroboration (UserAssist + service persistence in Module 16).
- **Module 4** is openly labelled a **synthetic teaching construct**, with the generator script shipped
  (`tools/build_fleet_csvs.py`) — reasonable, since no license-clear multi-host AppCompat corpus exists.
- **Modules 5–10** use **EVTX-ATTACK-SAMPLES** (sbousseaden) — real attack telemetry, but from assorted
  public hosts rather than the Case-001 host.
- **The dataset shift is explicitly framed** in the top-level README: *"Part B data… real attacks, but on
  assorted hosts, not the Case-001 host that Part A follows. They teach the method; the capstone (11)
  fuses the method back onto Case-001."* That is the right call and it is stated up front.
- Every module carries a `data/README.md` with provenance and licensing.

**One presentational caveat:** the Tolkien naming in Module 4 (`palantir.exe`, `nazgul.exe`,
`MINAS-TIRITH-DC01`) reads as obviously fictional next to Modules 1–3's real `coreupdater.exe` /
`DESKTOP-SDN1RPT`. That is fine — it is *labelled* synthetic — but be ready for the question, since
Module 4 sits in the middle of the "real evidence" Part A arc.

---

## 6. Outside Modules 1–10 (for completeness)

- **Module 20 (Velociraptor) — the one hard failure.** `velociraptor.exe` is present and valid
  (70 MB PE32+, exec bit set) but every invocation returns **`Permission denied`**, so `collection.zip`
  is never produced and the follow-on `unzip` fails. A Windows Defender notification appeared during
  testing; Defender blocking the binary is the leading hypothesis (Velociraptor is routinely flagged as
  a hacktool). Needs confirmation, then a Defender exclusion at build time.
- **Module 20 also has no `data/` directory** — by design, since it collects from the live VM. Worth
  knowing before demoing it.
- **Module 27 (SRUM) is absent from the VM.** The image was baked at lab commit `c26c6bf`; module 27
  landed after. The VM has **25** modules, the repo now has **26**.
- **Missing tools:** `evtx_dump`, `csvcut`, `log2timeline.py`, `psort.py` (plus `acp`). None broke a
  module in 1–10, but `evtx_dump` underpins Zircolite and Plaso underpins any real super-timeline work.

---

## 7. Recommended order of fixes before the showcase

1. **Module 4 `acp` shim → Python 2.7** (one line, proven above). Unblocks the module entirely.
2. **Rewrite `ANSWER-KEY.md` Module 4** against the SAURON fleet. Currently wrong in every particular.
3. **Fix the Module 4 README's `python …AppCompatProcessor.py`** to name Python 2.7 explicitly, since
   bare `python` is Python 3 on the VM.
4. *(Optional for the demo)* Defender exclusion for `velociraptor.exe`, or skip Module 20 in the demo.
5. *(Optional)* Re-bake the VM so it carries Module 27 and the tagged Module 4 fences.

---

## 8. The lesson worth keeping

Module 4 broke because a *correct* fix elsewhere (installing Python 3 for Volatility3) had an unnoticed
side effect — and the only thing that would have caught it, the validation harness, was structurally
blind to Module 4 because of a two-character formatting difference (` ``` ` vs ` ```bash `).

The harness reported clean runs for six weeks while never executing that module. It has now been changed
so that **a module which cannot be validated counts as a failure, not a pass** — the single change that
would have surfaced this on day one.
