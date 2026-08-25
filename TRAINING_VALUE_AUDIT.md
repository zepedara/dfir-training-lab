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
| 4 AppCompatProcessor | ✅ | ⚠ | ✅ | ❌→✅ | ✅ | fixed last pass; re-verify signatures |
| 5 EvtxECmd | — | — | — | — | — | pending |
| 6 Sigma/Chainsaw/Hayabusa | — | — | — | — | — | pending |
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

## Carried forward / open

- **M2 cosmetic:** regenerate `shimcache.csv` so `SourceFile` isn't a container path.
- **M4:** signatures re-verify pending (outputs were corrected last pass; confirm `search`/`filehitcount`
  behave as newly documented).
- Modules **5–10** not yet audited on these axes.
- Defender on the test VM is now actively interfering with process spawning (ASR-style
  `Access is denied` when PowerShell launches a child PowerShell). Workaround in use: type commands into
  the already-open shell rather than spawning. Worth an exclusion at build time if the VM is re-baked.
