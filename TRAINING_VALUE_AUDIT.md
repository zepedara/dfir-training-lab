# Modules 1–10 — Training-Value & Artifact-Realism Audit (running document)

**Loop task:** audit modules 1–10 for *real training value* — useful data, realistic artifacts and
signatures — and re-test end to end on the VM after each change.
**Test bed:** VM 210 (`dfir-lab-vm-v4`) on `cthuwu-win`, driven via console + HTTP collector.
**Started:** 2026-08-25 · **This is the loop's state file — each iteration updates it.**

> Correctness ("does it run", "does it match the answer key") was settled in `MODULE_REVIEW.md`.
> **This audit asks a harder question:** would a competent analyst actually *learn* something true
> here, and would a sharp student find the artifacts convincing?

---

## Rubric

Each module is scored on five axes:

| Axis | Question |
|---|---|
| **R1 Artifact realism** | Are the artifacts internally consistent (volume serials, SIDs, timestamps) and plausible as real evidence? Would a sharp student spot a fake? |
| **R2 Signature realism** | Do the detections/signatures fire on the real thing, and are they the right ones? Any hand-waved or non-reproducing output? |
| **R3 Data usefulness** | Is there enough volume, noise and decoy material to practise on, or is the answer trivially obvious? |
| **R4 Claim accuracy** | Does every factual claim in the prose survive being checked against the shipped data? |
| **R5 Transferable skill** | Does it teach method that generalises, or trivia about one file? |

Verdicts: ✅ solid · ⚠ weak but usable · ❌ defective (fix before showcase)

---

## Progress

| Module | R1 | R2 | R3 | R4 | R5 | Status |
|---|---|---|---|---|---|---|
| 1 Prefetch | ✅ | ✅ | ✅ | ✅ | ✅ | **audited — excellent** |
| 2 ShimCache | ✅ | n/a | ✅ | ❌→✅ | ✅ | **audited — 2 defects fixed** |
| 3 Amcache | ✅ | n/a | ⚠ | ✅ | ✅ | **audited — solid, low difficulty** |
| 4 AppCompatProcessor | ✅ | ✅ | ✅ | ✅ | ✅ | **re-verified — signatures correct** |
| 5 EvtxECmd | ✅ | ✅ | ⚠ | ✅ | ✅ | **audited — tiny samples, no baseline** |
| 6 Sigma/Chainsaw/Hayabusa | ✅ | ✅ | ✅ | ❌→✅ | ✅ | **audited — 2 answer-key defects fixed** |
| 7 Credential theft | ✅ | ✅ | ✅ | ✅ | ✅ | **audited — claims verified** |
| 8 Lateral movement | ✅ | ✅ | ✅ | ❌→✅ | ✅ | **audited — 1 defect fixed, LogonId claim confirmed** |
| 9 PowerShell | ✅ | ✅ | ✅ | ❌→✅ | ✅ | **audited — 1 answer-key defect fixed** |
| 10 Sysmon + WEF | ✅ | ✅ | ✅ | ✅ | ✅ | **audited — every claim verified** |

---

## Iteration 1 — 2026-08-25

### Module 1 — Prefetch ✅ excellent

**R1 — the planted artifact holds up under scrutiny.** The disclosed "representative"
`COREUPDATER.EXE-157C54BB.pf` carries the **same volume GUID and serial as the 196 real Case-001
files** — `\VOLUME{01d68d85e0da1e22-b0e0e8ff}`, Serial `B0E0E8FF`, volume created
`2020-09-18 06:35:19`. A student cannot unmask it by fingerprinting the volume, which is exactly the
bar a teaching artifact should clear.

**R5 — the loaded-file list is genuinely inferable tradecraft.** Its 51 referenced files read as a
coherent implant profile, not filler:

| Group | Files | What a student can infer |
|---|---|---|
| Networking | `WS2_32`, `MSWSOCK`, `IPHLPAPI`, `NSI`, `DNSAPI`, `DHCPCSVC` | it does sockets and name resolution |
| HTTP C2 | `WININET`, `WINHTTP` | it talks HTTP(S) |
| Crypto | `CRYPT32`, `RSAENH`, `BCRYPT`, `BCRYPTPRIMITIVES`, `MSASN1`, `CRYPTBASE` | it encrypts / handles certs |
| **Credential access** | `DPAPI.DLL` **+ a real DPAPI RSA key blob under `\USERS\ADMINISTRATOR\APPDATA\ROAMING\MICROSOFT\CRYPTO\RSA\S-1-5-21-2232410529-1445159330-2725690660-500\…`** | it touched the **RID-500 Administrator's** DPAPI master-key material |
| Net enumeration | `NETAPI32`, `WKSCLI`, `MPR`, `CSCAPI` | it enumerates shares/workstations |

That DPAPI blob with a real SID is the strongest single detail in the module — a student who reads the
Files-referenced list can derive "network-capable implant that touched the Administrator's DPAPI keys"
without ever seeing the binary. **That is real skill, not trivia.**

**R3 — baseline is rich enough to hunt in:** 197 `.pf`, **107 distinct executables**, all four
documented LOLBins present (`CMD`, `POWERSHELL`, `RUNDLL32`, `WSCRIPT`). `CMD.EXE` RunCount **9**
confirms the run-count-vs-8-slots exercise.

*Minor note:* the capture spans only two days (86 runs on 2020-09-18, 110 on 2020-09-19), so "odd hour"
is a weaker signal than "clusters with the malware". The clustering exercise carries it. Realistic for a
short-lived compromised host; not worth changing.

### Module 2 — ShimCache ❌→✅ two real defects, both fixed

**D1 — a factual claim that one `awk` disproves.** The module asserted **three times** (plus in
`data/README.md`) that the Win10 `Executed` column reads *"`No` for **every** row"* / *"uniformly
`No`"*. Actual: **247 `No`, 19 `Yes`** of 266.

```
awk -F',' 'NR>1{print $5}' shimcache.csv | sort | uniq -c
    247 No
     19 Yes
```

The 19 `Yes` rows are AppX package-identity entries and VMware driver installers — *not* the binaries
known to have executed. **Fixed**, and reframed into a stronger lesson: the flag is not "always No", it
is **inconsistent**, which is worse — a stray `Yes` invites over-claiming.

**D2 — an exercise that promises an observation that doesn't occur.** Exercise 5 asks the student to
re-run with `--nl` and see whether the count changes; the answer key said it "can **drop**". Measured:
**266 either way, delta 0.** The hive *is* dirty and the tool says so, but the pending log changes don't
touch the `AppCompatCache` blob. **Fixed:** the answer key now teaches the warning text and the real
point — *you could not have known in advance that the logs didn't matter here*, which is precisely why
you always replay. Module 3 is cited as the contrasting case where a log replay **is** applied.

**R3 — decoy quality is good:** 22 rows in `\Temp\`/`\AppData\`, and they are all *legitimately benign*
(OneDrive updaters, `MpSigStub.exe`) — exactly the benign-vs-suspicious judgement exercise 2 asks for.
Real user names from the case (`mortysmith`, `ricksanchez`) rather than `user1`/`user2`.

*Cosmetic wart (not fixed):* `shimcache.csv`'s `SourceFile` column reads `/data/SYSTEM` — a leftover
**container path** from when the CSV was generated under Docker. Harmless, but incongruous on a
native Windows lab and a sharp student will notice. Regenerate on the next re-bake.

### Module 3 — Amcache ✅ solid, ⚠ low difficulty

**R1/R4 — reproducible and honest.** The shipped `amcache_UnassociatedFileEntries.csv` matches a fresh
parse of the hive **exactly (15 rows)**. **All 15 rows carry a real 40-char SHA1**, so the hash-pivot
skill the module teaches is genuinely practisable.

**The transaction-log lesson is real here** — the tool visibly does the work:
```
Two transaction logs found. Determining primary log...
Replaying log file: ...Amcache.hve.LOG2 / .LOG1
At least one transaction log was applied. Sequence numbers have been updated to 0x0037.
```
This is the demo module 2's exercise 5 *claims* to be, which is why the corrected module-2 answer now
points here for contrast.

**⚠ R3 — the outlier exercise is nearly free.** Of 15 unassociated entries, `coreupdater.exe` is the
**only** row with an empty ProductName, and only 4 have `IsOsComponent=False`. Sorting on ProductName
hands over the answer instantly. That's acceptable — module 3's job is "build the identity card", not
"find the needle" (module 4 does the needle properly with 61 filenames and a 19-entry rare tail) — but
it is worth knowing the difficulty is low if this module is demoed as a hunting exercise.

---

## Iteration 2 — 2026-08-25

### Module 4 — signatures re-verified ✅

The corrections from the previous pass hold up under a fresh run:

- `acp acp.db search` uses ACP's stock known-bad list and reports **"98 search terms"**, exactly as the
  README states.
- The targeted regex search returns **9 hits**, with correct hosts and paths —
  `ISENGARD-WS04 … C:\ProgramData\palantir.exe 412672`, `MINAS-TIRITH-DC01 … C:\Windows\NTDS\morgul.dll 76288`.
- `filehitcount evilnames.txt` returns exactly the seven planted tools with the documented counts
  (`nazgul` 2, `palantir` 2, the rest 1).

### Module 5 — ⚠ teaches recognition, not hunting

**R3 is the honest weak spot.** The build fetches **36** EVTX samples (the repo ships 4), but each file
holds only a handful of records:

| Sample | Records | Event IDs |
|---|---|---|
| `bits_lolbas_desktopimgdownldr_59_60` | 5 | 3, 4, 59, 60, 209 |
| `evasion_execution_imageload_wuauclt_lolbas` | 3 | 1×2, 7 |
| `exec_driveby_cve-2018-15982_sysmon_1_10` | 2 | 1, 10 |
| `exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler` | 11 | 1×9, 11×2 |

With 2–11 records per file, **100% of the data is the answer** — a student is *recognising* a technique,
not *hunting* for it. That is a legitimate design for a teaching module and the lab's Part-B framing
already says these "teach the method", but it should not be demoed as a hunting exercise. Module 6 is
where the volume lives (18,442 Hayabusa rows), and module 4 is where the needle-in-fleet skill lives.
No change made — this is a scoping note, not a defect.

### Module 6 — ✅ excellent data, ❌→✅ two answer-key defects fixed

**R2/R3 are genuinely strong.** Chainsaw loads **3,608** Sigma rules and produces **4,121 detections on
3,872 documents**; Hayabusa's unfiltered timeline is **18,442 rows**. The rules that fire are real,
well-known ones — `HackTool - Mimikatz Execution`, `Invoke-Obfuscation Obfuscated IEX Invocation`,
`PsExec Default Named Pipe`, `CobaltStrike Service Installations`, `Meterpreter or Cobalt Strike
Getsystem Service Installation`, `Important Windows Eventlog Cleared`, `Rare Service Installations`.
There is real baseline noise (`Proc Exec` 8,413; `Logon Failure (Wrong Password)` 3,558) from the
`many-events-*` bulk logs, so this module *is* a real hunting exercise.

**D1 — exercise 1's answer listed sample filenames, not detections.** The exercise asks for the
technique *the detections reveal*; the key answered with the names of the `.evtx` files. **Fixed:**
replaced with the actual rule titles and their hit counts, plus two lessons the real output hands you
for free:
- **`Godmode Sigma Rule` fires 41 times** — a catch-all meta-rule, not a technique.
- **One rule is 3,561 of the 4,121 detections** (`Metasploit SMB Authentication`). A raw detection count
  is a terrible triage metric; count **distinct rules and hosts** instead.

**D2 — exercise 4 asked students to compare two things when one doesn't exist.** The key said Hayabusa
and Chainsaw "should **agree**" on `mimikatz-privesc-hashdump.evtx`. Measured:

| Tool | Result |
|---|---|
| Chainsaw | `Loaded 1 forensic artefacts (68.0 KiB)` → **0 detections** |
| Hayabusa | `Process Ran With High Privilege` [med] ×4, `Log Cleared` [high] ×1 |

Chainsaw is not broken — the same command on `sysmon_privesc_psexec_dwell.evtx` returns 9 detections. The
sample is a **Security**-channel log (1102 ×1, 4673 ×5, 4798 ×7) that Chainsaw's mapped Sigma set doesn't
cover. **Fixed**, and rewritten into a much better exercise: *"no detections" is not "no evidence"*;
**neither tool names Mimikatz** — you identify it from `Proc: C:\Tools\mimikatz\mimikatz.exe` in the
event detail, so **the alert label is not the identification, the evidence is**. Both mimikatz samples
behave this way.

### ⚠ A finding I raised and then withdrew

I initially measured that severity filtering was **inverted** (`high` returning 3,774 vs `low` 120) and
was about to rewrite exercise 3. **That was my error, not the lab's:** I tested *chainsaw's* `--level`,
which is an **exact-level** filter, while exercise 3 is about *hayabusa's* `--min-level`, a true
**minimum** filter (`-m, --min-level <LEVEL>  Minimum level for rules to load`). Re-measured on the
right tool: informational **18,442** rows → low **8,639**, i.e. raising the floor reduces volume exactly
as the answer key says. **Exercise 3 is correct and was left untouched.**

Worth keeping as its own lesson: chainsaw `--level` (exact) and hayabusa `--min-level` (minimum) are
different semantics with similar names, and the exact-level partition is visible in the data —
info 57 + low 120 + medium 164 + high 3,774 + critical 6 = **4,121**, the full total.

---

## Iteration 3 — 2026-08-25

### 🔴 P1 — Windows Defender quarantines the lab's own evidence and blocks Git-Bash

This is the most consequential finding of the audit so far, and it is a **defect in the shipped VM**,
not merely a quirk of my test bed.

Defender's threat history on the running lab VM:

| Detection | What it hit |
|---|---|
| `Trojan:PowerShell/Mimikatz.A` | the module-6/7 Mimikatz samples |
| `TrojanDownloader:PowerShell/Plasti.A`, `Trojan:PowerShell/Powdow.HNAB!MTB` | the PowerShell attack samples |
| `Trojan:Win32/CeeInject.WN!bit`, `Trojan:Win32/Commando.A!ml` | attack telemetry |
| `Behavior:Win32/SuspClickFix.G2` | behaviour block |
| *(file action)* | **`C:\dfir\lab\module-06-sigma-chainsaw-hayabusa\data\high.csv`** |

That last row is the important one: **`high.csv` is the file module 6's own Step 5 instructs the student
to create.** Defender deletes it mid-write, because a CSV of parsed attack telemetry contains the
malicious command lines. The same happened to my probe outputs (`_hb/medium.csv`, `_hb/critical.csv`,
`_m5/tmp.csv`).

**It also blocks the toolchain itself.** Defender logged behaviour detections against
`C:\dfir\tools\git\usr\bin\bash.exe` and `env.exe`, after which `EvtxECmd.exe` returned
`Permission denied` **when launched from Git-Bash while running fine from PowerShell**. The lab's entire
native-first design runs through Git-Bash, so this degrades everything.

**The timing is the worst part.** The first detection is stamped **01:18**; my clean
`24 pass / 1 fail` validation ran at **01:14**. In other words the lab **validates green on a fresh boot
and then rots as Defender's cloud definitions catch up** — a reproducibility trap that would make a
demo fail for reasons no one could explain.

**Remediation prototyped** (offline hive merge, which also bypasses Tamper Protection):
- `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths\C:\dfir = 0` — **this alone
  restored file access and made EvtxECmd runnable again.**
- Clearing `…\Windows Defender\Features\TamperProtection` then allows
  `DisableRealtimeMonitoring` / `DisableBehaviorMonitoring` to actually apply (the policies are ignored
  while TP is on — `IsTamperProtected: True` overrode them on the first attempt).

**The VM build should ship the `C:\dfir` exclusion.** Without it the lab actively fights the student.

### 🔍 The real build recipe — recovered from `C:\dfir-provision.log`

The shipped VM was provisioned by **`A:\provision.ps1`** (an attached scripts drive), *not* by the
packer provisioner list in the repo. The transcript gives the true sequence:

```
RUN 30-windows-tools    -> DONE (lastexit=0)
RUN 32-native-env       -> DONE (lastexit=1)   <-- FAILED
RUN 34-native-tools     -> DONE (lastexit=0)
RUN 36-shim             -> DONE (lastexit=0)
RUN 40-clone-lab        -> DONE (lastexit=1)   <-- FAILED
RUN 42-module04-acp     -> DONE (lastexit=0)   <-- not in the repo at all
```

Two conclusions, both material:
1. **The build shipped with two failed provisioning steps** (`32-native-env`, `40-clone-lab`) and
   packaged anyway. That is `MODULE_REVIEW.md`'s missing-gate issue, now with direct evidence rather
   than inference.
2. **`42-module04-acp` does not exist in the repository.** It installs Python 2.7, fetches ACP, applies
   the Windows patches, and creates the `acp` shim and `evilnames.txt`. So the shipped VM is *not*
   reproducible from the repo — a step that mattered lives only on the build media.

### 🔧 Module 4 root cause — corrected and sharpened

My earlier conclusion ("no `acp` shim was ever created") was **wrong**. The build *did* create it. The
actual fault is a **PATH mismatch between two Git installations**:

| Fact | Value |
|---|---|
| Git trees present | `C:\dfir\Git` **and** `C:\dfir\tools\git` |
| Where the build put the shim | `C:\dfir\Git\usr\bin\acp` |
| What is on the machine PATH | `C:\DFIR\Git\cmd`, `C:\dfir\tools\git\bin`, `C:\dfir\tools\git\usr\bin`, `C:\dfir\tools\native-shim` |
| `C:\dfir\Git\usr\bin` on PATH? | **No** — hence `acp: command not found` |

Python 2.7 is present exactly as `42-module04-acp` logged. The one-line fix stands, but the *reason*
is worth recording: two Git trees, and the shim went into the one that isn't wired up.

### Module 7 — ✅ claims verified

| Claim | Result |
|---|---|
| Baseline `security_4624_4625_logon_baseline.evtx` yields **zero** detections | ✅ `Loaded 1 forensic artefacts` → **0 Detections** — the "quiet baseline proves your rules don't false-positive" lesson is real |
| Folder-wide detections | 22 detections on 9 documents |
| `sysmon_10_comsvcs_minidump_lsass` contains the LOLBAS dump | ✅ Sysmon 1/7/10/11 present, `comsvcs.dll` in the call trace alongside `rundll32.exe` |
| `security_4662_dcsync` carries the DCSync tell | ✅ `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` ×2 and `1131f6ad-…` ×1 — DS-Replication-Get-Changes / -All |

### Module 8 — ✅ claims verified, ❌→✅ one answer-key defect fixed

| Claim | Result |
|---|---|
| `LM_Remote_Service02_7045` has **three** 7045 events | ✅ exactly 3 |
| DCOM failures appear **only** as System 10016 | ✅ 10016 ×4, no other event ID in the file |
| `lm_sysmon_18_remshell_over_namedpipe` shows Sysmon 18 | ✅ 18 ×1 (plus 1 ×3, 3 ×1, 10 ×2), pipe name `\46a676ab7f179e511e30dd2dc41bd388` — a random-hex pipe, realistic C2 tradecraft |
| RDP sample records the client IP | ✅ **`10.0.2.16`** |

**Defect fixed:** the key claimed the filename `dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx` "even
encodes `168.68.131`-style addressing". It does **not** — `68`, `131` and `168` are the **event IDs** in
the file (68 ×9, 131 ×22, 168 ×9), and the real client IP is `10.0.2.16`. Corrected, with the
transferable lesson attached: *resolve a value from the parsed evidence, never from a filename.*

**Carried:** claim that a `4702` and a `4624` share one LogonId is **not yet verified** — the file holds
4624 ×6, 4702 ×1, 1102 ×1 and six distinct LogonIds by my first (lossy) extraction. Re-check with proper
CSV parsing once Git-Bash is unblocked.

---

## Iteration 4 — 2026-08-25 · modules 9 and 10 (audit of 1–10 complete)

### End-to-end, re-run with the Defender exclusion in place

```
=== RESULT: 24 pass / 1 fail / 0 unvalidated / 0 conceptual ===
    failed:      module-20-triage-velociraptor      (documented elevation requirement)
    missing tools: 0
```

### Module 8 — the carried claim is **CORRECT** (and I nearly filed a false defect)

The key says a `4702` and a `4624` share one LogonId. Reading the events directly:

```
4624  TargetLogonId  = 0x21a8c68
4702  SubjectLogonId = 0x21a8c68     <== SHARED
4624  TargetLogonId  = 0x21a8c80 / 0x21a8c9a / 0x21aa47f / 0x21aad4a / 0x21aadb8
```

My first pass compared **`SubjectLogonId` on the 4624s** — which is `0x0` on all six, because on a 4624
the *new* session's identifier is **`TargetLogonId`**; `SubjectLogonId` is the requesting process
(SYSTEM). Comparing the wrong field produced "no shared LogonId" and would have condemned a correct
answer key. **The sample is well built:** five decoy 4624s carry different TargetLogonIds, so the
student has to find the matching pair rather than being handed it.

### Module 9 — ✅ strong, ❌→✅ one answer-key defect fixed

| Claim | Result |
|---|---|
| The injection sample has **82** Sysmon 8 (CreateRemoteThread) | ✅ **exactly 82** (plus 7 ×1 image load, 10 ×1) — a precise claim that holds |
| `Powershell_4104_MiniDumpWriteDump_Lsass` states intent in clear | ✅ `MiniDumpWriteDump` ×10, `Get-Process lsass` ×2 |
| Guardrail tampering precedes the payload | ✅ CLM-disabled = Sysmon **12 ×1**; execpolicy-changed = Sysmon **13 ×5** |
| Emotet give-aways are `IEX` / `FromBase64String` / `DownloadString` | ❌ **none of them are present** |

**The defect:** `exec_emotet_ps_4104` contains **no `IEX`, no `Invoke-Expression`, no `FromBase64String`,
no `DownloadString`, and no Base64 at all** (0 hits each, read straight from the event). It is a single
4104 record obfuscated a different way. The sample itself is excellent — a real Emotet downloader with
concatenation-built cmdlets (`&('new-'+'obje'+'c'+'t') neT.WEbcLiENt`), backtick/random-case obfuscation
(``"SecURi`T`ypRO`T`oCOL"``), TLS pinning, a `%TEMP%\WOrd\2019\` drop path, and a `*`-separated
fallback list of compromised WordPress URLs.

**Fixed**, and the replacement is a stronger lesson: **you cannot hunt obfuscated PowerShell with a
keyword list** — `IEX`/`FromBase64String` would miss this sample entirely. What catches it is *shape*.

### Module 10 — ✅ every claim verified

| Claim | Result |
|---|---|
| `UACME_45` is a **registry** bypass (12/13) | ✅ Sysmon 12 ×1, 13 ×1, plus 1 ×5 and 5 ×1 (the elevated payoff) |
| `UACME_63` is an **image-load** bypass (7/10) | ✅ Sysmon 7 ×1, 10 ×1, 1 ×1 |
| lsass dump shows Sysmon 10 (access) **and** 11 (`.dmp` written) | ✅ 10 ×2, 11 ×2 — dump file `lsass.exe_190317_120941.dmp` |
| Zerologon: Security uniquely has **4742**, Sysmon uniquely has the process tree | ✅ Security = 4742 ×1 (+4624 ×10, 4634 ×9, 4672 ×10, 4769 ×4, 1102 ×1); Sysmon = 1 ×10, 4, 5 ×10, 16 — **and neither log contains the other's evidence** |

The two-UACME contrast is genuinely distinguishable in the data, and the Zerologon pair is the cleanest
"why forward both logs" demonstration in the whole lab.

### Defender — updated, and the P1 finding stands

- Clearing Tamper Protection offline **did not persist**: `IsTamperProtected: True`,
  `RealTimeProtectionEnabled: True` after reboot. Windows re-asserts it. **Defender was never actually
  disabled**, so the `DisableRealtimeMonitoring` policies never applied.
- **Git-Bash can run the tools again** — so the fix was the `C:\dfir` **exclusion** (and/or the reboot
  clearing a transient behaviour block), *not* disabling AV. **Recommendation for the build: ship the
  exclusion; do not attempt to disable Defender.**
- **Defender is still deleting derived CSVs.** Demonstrated twice this iteration: EvtxECmd reported
  `Records included: 8, Errors: 0`, a `grep` then read the resulting CSV successfully, and a second
  later Python got `FileNotFoundError` on the same path. This is precisely what a student experiences
  with module 6's `high.csv`. Workaround used for the remaining checks: read events directly with
  `Get-WinEvent` and never materialise an intermediate file.

---

## Carried forward / open

- **M2 cosmetic:** regenerate `shimcache.csv` so `SourceFile` isn't a container path.
- ~~M4 signature re-verify~~ — **done, correct** (iteration 2).
- ~~Modules 9–10~~ — **done (iteration 4). All ten modules are now audited.**
- ~~M8 claim 9~~ — **confirmed correct** (iteration 4).
- ~~Verify the Tamper-Protection clear~~ — **it did not persist**; the exclusion is the real fix.
- **Build-side work remains in `project-dfir/dfir-vm`:** ship the `C:\dfir` Defender exclusion, add
  `42-module04-acp` to the repo, put `C:\dfir\Git\usr\bin` on PATH (or write the shim into
  `native-shim`), and gate packaging on the harness so a step exiting 1 fails the build.
- **M6 note:** consider telling learners up front that one rule supplies 86% of the detections, so they
  don't mistake alert volume for severity.
- Defender on the test VM is now actively interfering with process spawning (ASR-style
  `Access is denied` when PowerShell launches a child PowerShell). Workaround in use: type commands into
  the already-open shell rather than spawning. Worth an exclusion at build time if the VM is re-baked.
