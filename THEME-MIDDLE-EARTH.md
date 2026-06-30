# Middle-earth — Canonical Lab Theme Reference

> **Single source of truth** for the Lord of the Rings theme used across this lab. The same
> mapping is used in the lab repo, in the prebuilt VM, and in every module walkthrough so they
> never drift. If you add or rename anything themed, change it **here first**, then everywhere else.

## The scenario (fiction)

The fictional victim organization is **Middle-earth Holdings** ("the realm"). It is breached by a
state-sponsored adversary tracked as **SAURON** (a.k.a. *APT-MORDOR*, "the Enemy", "the Eye").
The intrusion begins with a phish to an executive, moves through an insider's host, and ends with
total domain compromise of the domain controller — the classic objective. The story is told across
the modules; the **AppCompatProcessor module (04)** showcases hunting the intrusion across the whole
fleet at once.

> **Evidence-integrity note (read this).** Some modules analyze a *real* public case dataset whose
> artifacts have hostnames/filenames baked into their bytes (e.g. the domain controller is named
> `CITADEL-DC01` inside the real registry hive, event logs, and memory image). **We never alter
> evidence** — that is the cardinal rule of forensics — so in those modules tool output shows the
> real names. Happily, *"the Citadel"* is itself Tolkien's term for the topmost ring of Minas Tirith
> (where the White Tree and the throne stand), so even the immutable real name is on-theme: it is
> literally the Citadel **of** our `MINAS-TIRITH-DC01`. The theme is applied fully to all **synthetic**
> data (the Module 04 fleet, planted artifacts), to the **narrative**, and to the **jokes**; real
> evidence keeps its ground-truth names, always clearly distinguished.

## Host naming scheme

Format: **`<LOTR-LOCATION>-<ROLE><nn>`** — ROLE ∈ { **WS** workstation, **DC** domain controller,
**FS** file server, **SQL** database server, **LT** laptop }.

| Host | Role | Story role |
|---|---|---|
| `RIVENDELL-WS01` | Workstation | Elrond's house — ordinary analyst workstation (clean baseline) |
| `GONDOR-WS02` | Workstation | Realm of Men — ordinary workstation (clean baseline) |
| `ROHAN-WS03` | Workstation | The horse-lords — ordinary workstation (clean baseline) |
| `ISENGARD-WS04` | Workstation | Saruman's tower — **the insider** (`saruman.white`) who turned; lateral-movement launch point |
| `LOTHLORIEN-FS01` | File server | Galadriel's wood — the file server |
| `EREBOR-SQL01` | SQL server | The Lonely Mountain's hoard — the database server |
| `BAG-END-LT01` | Laptop | Frodo's home — exec laptop; **patient zero** (the phish landed here) |
| `MINAS-TIRITH-DC01` | Domain controller | The White City — the DC, the crown jewel (its *Citadel* = the real-evidence `CITADEL-DC01`) |

## Threat actor & accounts

- **SAURON / APT-MORDOR** — the adversary.
- `saruman.white` — the **insider** who turned (operates from `ISENGARD-WS04`).
- `frodo.baggins` — the phished exec (`BAG-END-LT01`).
- `gandalf.grey` — Domain Admin (the account SAURON ultimately wants).
- Other realm users: `samwise.gamgee`, `aragorn.king`, `legolas.greenleaf`, `gimli.son-of-gloin`,
  `peregrin.took`, `meriadoc.brandybuck`.

## Malware catalog (planted / synthetic — clearly a teaching construct)

Each name maps the Tolkien reference to **what the malware actually does** and **where it lands**.

| File | What it actually is | LOTR rationale | Lands on |
|---|---|---|---|
| `theonering.exe` | First-stage **dropper / loader**; re-establishes itself = **persistence** | The One Ring — the seed of it all, and "it always comes back" | `BAG-END-LT01` (`\Users\frodo.baggins\Downloads\`) |
| `gollum.exe` | Stealthy **%TEMP%-resident stager** | Gollum — creeps unseen, "my precious" | `BAG-END-LT01` (`\AppData\Local\Temp\`) |
| `palantir.exe` | **Recon + C2 beacon** (see far, be tasked from afar) | The palantír seeing-stone | `ISENGARD-WS04` then `MINAS-TIRITH-DC01` (spread → Count 2) |
| `nazgul.exe` | **Lateral-movement / remote-exec agent** | The Nine Riders — hunt host to host | `ISENGARD-WS04`, `MINAS-TIRITH-DC01` |
| `mordor-update.exe` | Fake **"software updater" persistence** (masquerade) | Mordor disguised as something benign | `ISENGARD-WS04` (`\Users\saruman.white\AppData\Roaming\`) |
| `morgul.dll` | **Credential / NTDS theft** module on the DC (DCSync / ntds.dit) | The Morgul-blade — poisons the realm's keys | `MINAS-TIRITH-DC01` (`\Windows\NTDS\`) |
| `balrog.exe` | **Heavy end-objective payload** staged on the DC | The Balrog — deep, ancient, powerful ("you shall not pass" — it did) | `MINAS-TIRITH-DC01` (`\PerfLogs\` — a classic staging dir; ACP's known-bad list auto-flags it) |

## Funny tidbits to weave in (sparingly, where they fit)

- "One does not simply RDP into Mordor." (lateral-movement / remote-access discussions)
- Persistence scheduled task named **`second-breakfast`** (runs more than once a morning).
- Service/Run-key value **`myprecious`**.
- A planted note `directions_to_mount_doom.txt`; password hint **`mellon`** ("speak, friend, and enter").
- SOC escalation line: **"The eagles are coming"** (= help/IR arrives).
- Credential-handling aside: **"Keep it secret, keep it safe."**
- `gollum.exe` beaconing to two C2s — "we wants it / no we doesn't."

## What stays un-themed and why

- **Real evidence artifact names** (e.g. `CITADEL-DC01`, real sample SHA1s/filenames) — altering
  evidence is forbidden; we map them to the theme in narration instead (see the evidence note above).
- **Tool names, command syntax, file-format keywords, real Windows binary names** — these are facts a
  student must learn unchanged.
