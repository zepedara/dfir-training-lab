# Module 24 — Anti-Forensics: Volume Shadow Copy (VSS) — Destruction & Recovery

> **Track:** Anti-Forensics (FOR508.5). **Prereqs:** Modules 5 & 10 (event logs / Sysmon), 15 (NTFS). **Tool:** `EvtxECmd` (Lesson A). **Lesson B** references libvshadow.
> **You'll learn:** the two sides of Volume Shadow Copies in an intrusion — **detecting** when an attacker destroys them to stop you recovering (ATT&CK **T1490**), and **recovering** historical evidence from the shadows that survive.

---

## 1. The time machine — and why attackers smash it

A **Volume Shadow Copy (VSS)** is a point-in-time, block-level snapshot of a volume. To the OS it is a "Previous Version"; to a forensic examiner it is a **time machine** — a shadow taken before the attacker's dwell time still holds an *earlier* `$MFT`, registry, event logs, and even files the attacker later deleted or wiped (Modules 23, 25, 26). It is one of the most powerful sources of historical evidence on a Windows host.

Attackers know this. Modern ransomware's **first act** is usually to **destroy the shadow copies** so the victim cannot roll back — and so an investigator cannot recover pre-attack state. This is MITRE ATT&CK **T1490 — Inhibit System Recovery**, and it is loud: every deletion method runs a well-known command that a defender can catch.

This module has two lessons: **Lesson A — detect the destruction** (a hands-on you run here), and **Lesson B — recover from the shadows that remain** (a documented walkthrough, since it needs a Linux-side tool).

> **Under the hood (for context):** VSS uses **copy-on-write** — before a block on the live volume changes, the *original* block is copied into a store under `System Volume Information`, tracked by a catalog GUID `{3808876b-c176-4e48-b7ae-04046e6cc752}`. **Caveat that bites analysts:** since Windows 8, client editions default to **`ScopeSnapshots`**, which restricts snapshots to system-restore files — so user-data recovery from a *client* shadow is often thin. Servers (and clients with `HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore\ScopeSnapshots = 0`) keep full-volume shadows. (libvshadow VSS format spec; Microsoft.)

---

## 2. Lesson A — Detecting VSS destruction (T1490)

Every way to destroy recovery data is a command line, and command-line **process-creation logging** — Security **4688** (with "Include command line" enabled) or Sysmon **1** — captures it. This module ships an inert Security-log capture, `security_t1490.evtx`, recording the four canonical T1490 commands being run (against a system with nothing to delete — they are harmless no-ops, but the *command line* is what you detect).

### Setup

```bash
cd module-24-anti-forensics-vss/data
```

### Step 1 — Parse the process-creation events

```bash
EvtxECmd -f security_t1490.evtx --csv . --csvf t1490.csv
```

### Step 2 — How many process creations?

```bash
grep -c ',4688,' t1490.csv
```

**Read it:** a handful of **4688** (A new process has been created) events — the capture window. On a real host you'd have thousands; the skill is filtering them to the recovery-tampering ones.

### Step 3 — Surface the T1490 command lines

```bash
grep -aoiE 'vssadmin (delete shadows|resize shadowstorage)|wmic shadowcopy delete|wbadmin delete (catalog|systemstatebackup)' t1490.csv | sed 's/  */ /g' | sort -u
```

**Read it — the four faces of T1490:**
- **`vssadmin delete shadows /all /quiet`** — the classic. Deletes every shadow copy silently. The single most common ransomware pre-encryption command.
- **`vssadmin resize shadowstorage … /maxsize=401MB`** — the *quiet* variant: shrink the shadow storage so tiny that Windows purges existing shadows to fit. Evades naive "delete shadows" alerting.
- **`wmic shadowcopy delete`** — the same destruction via WMI instead of `vssadmin` (also visible in **WMI-Activity/Operational 5857** as the `MSVSS__PROVIDER` / `vsswmi.dll` provider load — a second detection source).
- **`wbadmin delete catalog -quiet`** — destroys the Windows Backup catalog so system-state backups can't be restored either.

**The detection:** any of these four command lines on a normal endpoint is high-fidelity malicious — legitimate admins rarely bulk-delete shadows or shrink shadow storage to nothing. Alert on the **command line**, not the binary (renaming `vssadmin.exe` defeats a name-only rule; the arguments give it away). Related tells not shown here: `bcdedit /set {default} recoveryenabled no` and `REAgentC /disable`.

> **Why this is the whole point:** the attacker destroys shadows to *prevent recovery* — but the **act of destruction is itself evidence**, timestamped and attributable. You lose the time machine, but you gain a high-confidence T1490 detection that anchors the intrusion timeline.

---

## 3. Lesson B — Recovering from the shadows that survive *(reference walkthrough)*

If shadows were **not** destroyed (or you have an older disk image), they are a goldmine. On a raw/E01 disk image you analyse them **offline** with Joachim Metz's **libvshadow** (the SIFT/Linux standard — a tool you add to the analysis environment):

```text
# 1) find the partition offset with mmls (Module 15), then list the shadow stores:
vshadowinfo -o <partition_byte_offset> disk.raw
#    -> prints each store's number, creation time, and volume size

# 2) expose every snapshot as a raw device (vss1, vss2, …):
vshadowmount -o <partition_byte_offset> disk.raw /mnt/vss

# 3) now treat each vssN as a volume — run the SAME Sleuth Kit / MFTECmd workflow
#    from Module 15 against the historical state:
mmls /mnt/vss/vss1
fls -r /mnt/vss/vss1        # files that existed at snapshot time
icat /mnt/vss/vss1 <inode>  # recover a file the attacker later deleted/wiped
#    (for an E01 image, ewfmount it first, then point vshadowinfo at ewf1)
```

The payoff: a file wiped on the live volume (Module 23) or a `$MFT`/journal state that has since wrapped (Module 25) can be read **intact** from a snapshot taken before the attack. Diffing the same artifact across snapshots reveals timestamps *before* a stomp and a journal window that has since rolled. **Plaso** (`log2timeline.py --vss_stores all`) can fold every snapshot straight into a super-timeline (Module 18). On Windows-only kit, **Arsenal Image Mounter (free) + Eric Zimmerman's VSCMount** reach the same shadows natively.

*(This lesson is documented rather than run in the lab because libvshadow is a Linux-side add and a shadow-bearing disk image is large; the detection half above is the hands-on.)*

---

## 4. Try it yourself

1. **Four faces.** From `t1490.csv`, list the four distinct recovery-destruction commands and, for each, say *what* it prevents from being recovered (file shadows vs backup catalog).
2. **The quiet one.** Why is `vssadmin resize shadowstorage /maxsize=<tiny>` sometimes used *instead* of `delete shadows`, and would a rule that only matches "delete shadows" catch it?
3. **Name ≠ detection.** An attacker copies `vssadmin.exe` to `svc.exe` and runs `svc.exe delete shadows /all`. Which field in the 4688 event still catches it, and which would miss it?
4. **The other road.** If the shadows were destroyed, is all pre-attack state lost? Name one place (from Modules 25/26 or an older image) you could still recover it.

---

## 5. Key takeaways

- **Volume Shadow Copies are a forensic time machine** — pre-attack `$MFT`, registry, logs, and deleted/wiped files survive inside them.
- **Destroying them is ATT&CK T1490** and is loud: `vssadmin delete shadows`, `vssadmin resize shadowstorage`, `wmic shadowcopy delete`, `wbadmin delete catalog`. Detect on the **command line** (4688/Sysmon 1; WMI path also in WMI-Activity 5857).
- **The destruction is itself evidence** — a high-confidence detection that anchors the intrusion even though it cost you the recovery source.
- **Recovery** (Lesson B): mount surviving shadows with libvshadow (or AIM + VSCMount) and re-run the Module 15 workflow against historical state — mind the client **ScopeSnapshots** caveat.

---

## 6. Sources

- MITRE ATT&CK — **T1490 Inhibit System Recovery** (lists `vssadmin`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit`): <https://attack.mitre.org/techniques/T1490/>
- MITRE CAR-2021-01-009 — *Delete Volume Shadow Copies via WMIC / vssadmin*: <https://car.mitre.org/analytics/CAR-2021-01-009/>
- Microsoft — enabling command line in **4688** process-creation events: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing>
- libvshadow (Joachim Metz) — VSS format & `vshadowinfo`/`vshadowmount`: <https://github.com/libyal/libvshadow>
- Microsoft — VSS / `System Volume Information` store & catalog: <https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview>
- **EvtxECmd** — Eric Zimmerman: <https://github.com/EricZimmerman/evtx>
