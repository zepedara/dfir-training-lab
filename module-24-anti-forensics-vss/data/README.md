# Module 24 data — provenance

**Inert T1490 detection capture.** `security_t1490.evtx` is a small Windows **Security** event log containing **process-creation (4688)** records of the four canonical *Inhibit System Recovery* commands being executed.

## How it was made (and why it is safe)
On an isolated build host, command-line auditing was **temporarily** enabled (`ProcessCreationIncludeCmdLine` + `auditpol` Process Creation) and then four **benign, no-op** recovery-tampering commands were run against a system that **had no shadow copies or backups to delete**:

- `vssadmin delete shadows /all /quiet`
- `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB`
- `wmic shadowcopy delete /nointeractive`
- `wbadmin delete catalog -quiet`

Each printed "no items found" and exited — **nothing was actually deleted** — but the **4688 event recorded the command line**, which is exactly the T1490 signature an analyst hunts. The audit policy was then **reverted** to its prior state.

The log contains only benign process-creation metadata (process names, command lines, timestamps) — **no malware, no real deletion, no sensitive data**. Generation script: `build-t1490-evidence.ps1` (also documents the revert). No `bcdedit`/boot changes were made.
