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
| 7 Credential theft | — | — | — | — | — | pending |
| 8 Lateral movement | — | — | — | — | — | pending |
| 9 PowerShell | — | — | — | — | — | pending |
| 10 Sysmon + WEF | — | — | — | — | — | pending |

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

## Carried forward / open

- **M2 cosmetic:** regenerate `shimcache.csv` so `SourceFile` isn't a container path.
- ~~M4 signature re-verify~~ — **done, correct** (iteration 2).
- Modules **7–10** not yet audited on these axes.
- **M6 note:** consider telling learners up front that one rule supplies 86% of the detections, so they
  don't mistake alert volume for severity.
- Defender on the test VM is now actively interfering with process spawning (ASR-style
  `Access is denied` when PowerShell launches a child PowerShell). Workaround in use: type commands into
  the already-open shell rather than spawning. Worth an exclusion at build time if the VM is re-baked.
