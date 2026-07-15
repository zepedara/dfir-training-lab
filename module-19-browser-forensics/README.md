# Module 19 — Browser Forensics: reconstructing web activity with Hindsight

**Deck mapping:** *Intrusion Hunting Playbook* → "Evidence of User Activity" → the browser — recovering *what a user searched, visited, downloaded, and when* from the trail a Chromium browser leaves on disk.
**Goal:** answer the question that decides a startling share of real cases — ***what did this person do on the web?*** — by parsing a **Chromium browser profile** (Chrome, Edge, Brave, Opera, Vivaldi — they all share the format) with **Hindsight**. You'll turn a folder of SQLite databases into a single timeline of URLs, searches, downloads, cookies, and autofill, running Hindsight **natively** (Git Bash on the lab VM; `hindsight` and `python3` are on your `PATH`), and read the result the way a real analyst does.

> **Evidence note.** The profile in `data/profile/` is a fixture from **Hindsight's own test suite** (Ryan Benson / Obsidian Forensics). It is an **inert Chromium `History` database** (~100 KB) recording a short, benign browsing session — the Chrome welcome page, a Google search for *"computer forensics,"* and a walk through Wikipedia articles on hard drives and SSDs. **No PII, no credentials, no malware** — it's the very database Hindsight's unit tests parse, chosen because it exercises the URL/visit/download structures without carrying anything sensitive. We never alter evidence, so the tool output shows the fixture's real baked-in values.

---

## 1. Background — why browser forensics matters

For a huge fraction of investigations, **the browser *is* the case.** Insider data theft, exfiltration to a personal cloud drive, phishing that landed, fraud, harassment, CSAM, policy violations, "how did the malware get on the box" — the pivotal facts are almost always *what site did they go to, what did they type into the search box, what did they upload or download, and at what minute.* Nothing else on the system answers those questions as directly as the browser's own history.

And the browser is a **remarkably honest witness**, because it keeps this data for its *own* convenience, not to help an investigator: history so the address bar can autocomplete, download records so "show in folder" works, cookies so you stay logged in, autofill so forms fill themselves. Every one of those conveniences is a **forensic artifact** written as a side effect of normal use — and it survives long after the browser window is closed.

The single fact that makes this module tractable: **Chromium is everywhere and it's all the same format.** Google **Chrome**, Microsoft **Edge**, **Brave**, **Opera**, **Vivaldi**, and dozens of niche browsers are all built on **Chromium**, and they all store their profile as the **same set of SQLite databases** in the same layout. Learn to read one Chromium profile and you can read all of them — one tool, one technique, most of the browser market. (Firefox uses a different schema — `places.sqlite` — but the *approach* is identical, and **current Hindsight now parses Firefox `places.sqlite` too**, so the one tool covers Chromium *and* Firefox rather than needing a separate parser.)

> **Plain-language summary:** Browsers keep detailed notes on where you went, what you searched, and what you downloaded — for their own convenience, so those notes are candid and they outlast the browsing session. Chrome, Edge, Brave and friends all keep those notes in the *same* database format, so one tool reads them all. This module is how you turn that database into a timeline.

---

## 2. The Chromium profile — where the evidence lives

A Chromium **profile** is a folder of **SQLite databases** (plus some flat files and caches). On a live Windows system the default profile is:

```
Chrome:  %LOCALAPPDATA%\Google\Chrome\User Data\Default
Edge:    %LOCALAPPDATA%\Microsoft\Edge\User Data\Default
Brave:   %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default
```
(i.e. `C:\Users\<user>\AppData\Local\...`). A user with multiple profiles gets `Profile 1`, `Profile 2`, … beside `Default` — **parse every one.**

The databases that carry the case (all are SQLite, all readable read-only):

| File | What's inside | Investigative value |
|---|---|---|
| **`History`** | `urls`, `visits`, `downloads`, `keyword_search_terms`, `segments` | The core: every page visited, the visit chain (what linked to what), every download, and **what was typed into search boxes** |
| **`Cookies`** → **`Network\Cookies`** (Chrome M96+) | per-site cookies, hosts, timestamps | *Which sites held a session* — proves account use even without the page in history |
| **`Web Data`** | autofill values, saved addresses, credit-card metadata, search engines | **Autofill** often captures names, emails, addresses the user typed into forms |
| **`Login Data`** | saved usernames + (encrypted) passwords, per origin | Proves *which accounts on which sites* the user saved credentials for |
| **`Bookmarks`** | JSON, not SQLite — bookmark tree + timestamps | Deliberately-saved destinations (intent) |
| **`Favicons`, `Top Sites`, `Shortcuts`** | thumbnails, frequency, omnibox learning | Corroborating "this site mattered / was visited often" signals |

### Three gotchas you must teach and remember

These trip up every beginner. Internalize them now.

- **① Chrome timestamps are NOT Unix time.** Chromium stores time as the **number of microseconds since 1601-01-01 00:00:00 UTC** (the "WebKit"/Chrome epoch — the same base as Windows FILETIME, but in *microseconds* rather than 100-ns ticks). A raw value like `13277420400000000` is **not** seconds since 1970 — feed it to a Unix converter and you'll land ~369 years in the future. Convert it: `unix_seconds = chrome_value/1_000_000 − 11644473600`. **The good news:** Hindsight does this conversion *for you* and emits human-readable UTC — but the moment you `sqlite3` a `History` file by hand, you own the math. Getting an epoch wrong is one of the most common ways to embarrass yourself in a report.

- **② Cookies and saved passwords are DPAPI-encrypted — you find the *artifact*, not the *plaintext*.** On Windows, cookie **values** in `Cookies` and passwords in `Login Data` are encrypted with **DPAPI**, keyed to the user account (and, since Chrome M80, wrapped again with an AES key that DPAPI itself protects — the **"v10"** scheme). Without the user's Windows credentials / DPAPI master key, you **cannot** read the values here. **And since Chrome 127 (July 2024) it got *harder still*:** cookie values now use **App-Bound Encryption (ABE, the "v20" prefix)** — the key is bound to Chrome's own identity and sealed behind a **SYSTEM-level DPAPI + COM elevation service**, so even the logged-in user's own context can't trivially decrypt it (the design explicitly aims to stop infostealers running as the user). Note the asymmetry: **as of the 2024 ABE rollout, `Login Data` (saved passwords) still used the older v10 scheme**, so cookies and passwords are protected differently (Google has said passwords and payment data will migrate to App-Bound Encryption in later Chrome releases — verify against the Chrome version in your evidence). This only *strengthens* the module's point — you reliably recover the **artifact**, and decryption is a separate, more-gated step than ever. What matters forensically is that the **record exists**: a `Login Data` row proves *this user saved a credential for `bank.example.com`*; a `Cookies` row proves *this profile held a session for `drive.google.com`* — even though the secret stays sealed. Teach the distinction: **the presence of the credential is the evidence**, decryption is a separate, credential-gated step we don't perform in this module. (Source: Google Security Blog, July 2024.)

- **③ Grab the `-wal` and `-shm` sidecars with every database.** SQLite runs in **WAL (Write-Ahead Log) mode**, so the newest activity — the pages just visited — often lives in **`History-wal`**, *not yet* merged into `History` itself. If you copy only `History` and leave `History-wal` / `History-shm` behind, you can **lose the most recent, most relevant browsing.** A **graceful browser close checkpoints the WAL** into the main DB; a crash or a live-pull mid-session does not. Rule: collect **`History`, `History-wal`, and `History-shm` together**, as a set, for every SQLite artifact — and note whether the browser was closed cleanly. (Hindsight reads the WAL; a naive `sqlite3 History` may not.)

---

## 3. What Hindsight is

**Hindsight** (Ryan Benson, **Obsidian Forensics**) is the open-source, **Apache-2.0-licensed** standard for Chromium profile analysis. Point it at a profile directory and it:

- **parses the whole profile at once** — `History`, `Cookies`, `Web Data`/autofill, `Login Data`, `Bookmarks`, `Preferences`, extensions, local/session storage — not one database at a time;
- **normalizes every timestamp** to human-readable UTC (see gotcha ①), so you never touch the 1601 epoch by hand;
- **enriches** via a **plugin** system — it flags Google Analytics cookie timestamps, decodes some URL parameters, tags known extensions, and correlates records into a single chronological view;
- **reads the WAL**, so recent activity in `History-wal` is included (gotcha ③).

**Invocation.** The three flags you need:

```
hindsight -i <profile_dir> -o <output_name> -f <format>
```
- **`-i`** — the **input** profile directory (the folder holding `History`, etc.).
- **`-o`** — the **output** base name (Hindsight appends the format's extension).
- **`-f`** — the **format**: **`jsonl`** (one JSON object per line — ideal for `grep`/`jq`/scripting, and what we use here), **`sqlite`** (a queryable results DB), or **`xlsx`** (a formatted, color-coded Excel workbook — **the analyst-friendly deliverable**, with a tab per artifact type and readable timestamps; reach for this when you're handing findings to a human; it is also Hindsight's **default** when `-f` is omitted).

Hindsight runs **read-only** against the evidence and stays **offline** — it never contacts the sites it parses.

---

## 4. Setup

Open **Git Bash** on the lab VM and change into this module's data directory:

```bash
cd module-19-browser-forensics/data
```
- **Every command below runs from inside `data/`.** The evidence profile is the relative path `profile/`.
- **Hindsight** and **`python3`** are installed **natively on the lab VM and already on your `PATH`** (as shims — you call `hindsight` and `python3` directly). No container, no Docker. The VM is kept **offline** so evidence never phones home.
- Confirm the evidence is present — you should see a Chromium `History` SQLite database:
```bash
ls profile/
```

---

## 5. Step-by-step walkthrough

### 5a. Parse the profile with Hindsight

Run Hindsight against the profile and write JSON Lines:

```bash
hindsight -i profile -o browser -f jsonl
```

This produces **`browser.jsonl`** with **48 records**. As it runs, Hindsight tells you what it found and which plugins fired:

- It identifies the input as a Chromium profile, reads the **`History`** database, and extracts **URL visits** and **downloads** — every record here is tagged `source_long` **"Chrome History"**, parser **`hindsight/2026.06`**.
- It also runs its **cookie, autofill, Login Data, and extension** plugins. In *this* fixture those report **0** — the test profile ships **only** a `History` database, nothing else — and that's an important thing to observe, not a bug: **Hindsight parses whatever the profile contains, and honestly reports zero for the artifacts that aren't present.** On a real profile these same plugins would light up with cookies, saved logins, and autofill.

> **Read the run summary.** Hindsight prints a per-artifact tally. Zeros for cookies/autofill/logins here simply mean *this collection was history-only*. On a live pull you'd expect all of them populated — and the absence of, say, `Login Data` on a real system can itself be meaningful (a locked-down or freshly-provisioned profile).

### 5b. Confirm the record count

```bash
wc -l browser.jsonl
```
**48** lines — one JSON object per artifact record. In JSON Lines, **one line = one record**, so `wc -l` *is* your record count. Sanity-checking the count against Hindsight's run summary is a small but real habit: it proves the output is complete and nothing was truncated.

### 5c. Summarize by artifact type and list the visited URLs

This is the **analysis step** — pivot the flat records into "what kinds of artifacts, and what did they actually visit":

```bash
python3 -c "import json; rows=[json.loads(l) for l in open('browser.jsonl')]; from collections import Counter; c=Counter(r.get('source_long') for r in rows); print(c); [print(' -', r.get('url','')[:70]) for r in rows if r.get('url')][:5]"
```

**What you're reading:**
- The **`Counter`** groups the 48 records by **`source_long`** — here, all **"Chrome History"**, confirming this is a history-only profile. On a fuller profile you'd see a mix ("Chrome Cookies", "Chrome Autofill", "Chrome Login Data", …), and this one line would tell you the *shape* of the user's browser evidence at a glance.
- The **URL list** is the payoff — the actual pages visited. In this fixture the story reads cleanly off the URLs: the **Chrome "Getting Started" welcome page**, a **Google search for `computer forensics`**, then a chain into **Wikipedia** — *Computer forensics* → *Hard disk drive* → *Solid-state drive*. That's a coherent little research session, reconstructed from nothing but the database.

> **Pivoting is the skill.** A dump of 48 records isn't an answer — the analysis is choosing the axis. Pivot on **URL** to see *where* they went; on the **visit timestamp** to build a *timeline* and cluster activity into sessions; on **`keyword_search_terms`** to read *what they typed*; on **downloads** to see *what left or arrived*. Hindsight gives you the normalized records; *you* ask them the case's question.

### 5d. Inspect one record's full structure

Pull a single Wikipedia record to see every field Hindsight decoded for a history entry:

```bash
grep -i wikipedia browser.jsonl | head -1
```

Look at the structure of that one JSON object: the **`url`** and page **`title`**, the **visit timestamp** (already converted to human-readable UTC — gotcha ① handled for you), the **visit count / typed count**, and the **`transition`** type (did the user *type* the URL, *click a link*, get *redirected*, or reload — this is how you tell deliberate navigation from being carried along). Those fields are what let you distinguish *"the user typed this address"* from *"a page auto-loaded this resource,"* which is often the difference between intent and noise in a report.

---

## 6. Interpreting the results — from records to a finding

The 48 records here tell a benign story, but the *method* is exactly what you'd apply to a live case:

1. **What did they search?** `keyword_search_terms` (joined to `urls`) gives the literal query — here, *"computer forensics."* Search terms are frequently the single most damning artifact: they capture **intent in the user's own words**.
2. **Where did they go, and how?** The `urls`/`visits` chain plus the **transition type** reconstructs the path — typed a search, clicked a result, followed links deeper. A **redirect** or an **embedded resource** load means the user may not have chosen it; a **typed** URL means they did.
3. **What moved data?** The `downloads` table records **target path, source URL, size, and start/finish times** — the crux of exfil-vs-download questions. (This fixture has two download records; on a real case this is where a leaked file or a dropped payload shows up.)
4. **When?** Every timestamp is normalized UTC. Cluster the visits and you get **sessions**; line them up against logon times (Module 05/17) and file activity (Module 15) and the browser becomes one lane of a **super-timeline** (Module 18).
5. **What's sealed vs. what's proven?** Remember gotcha ②: on a real profile, a `Login Data` or `Cookies` record **proves the account relationship** even when the secret stays DPAPI-encrypted. Report the *existence* of the artifact; flag decryption as a separate, credential-gated step.

> **Forensic value.** A browser history is a **candid, timestamped record of intent and action** — searched, visited, downloaded, when — that the browser maintains for itself and that outlives the closed window. Hindsight collapses the scattered SQLite databases into one normalized timeline; the analyst supplies the question.

---

## 7. Try-it-yourself exercises

1. **Read the search box.** From `browser.jsonl`, find the record whose URL is a Google `search?...q=` query and extract the **search term**. In one sentence, explain why a search term is often stronger evidence of intent than the page the user landed on.
2. **Build the click-chain.** List the Wikipedia URLs in visit order and describe the path the user took (*Computer forensics → Hard disk drive → Solid-state drive*). Which hops look like **typed** navigation and which look like **clicked links**, and how does the `transition` field tell you?
3. **Convert a timestamp by hand.** Take one raw Chrome timestamp (open the `History` DB directly: `python3 -c "import sqlite3; ..."` against `profile/History`, `visits.visit_time`), apply `unix = value/1_000_000 − 11644473600`, and confirm your result matches Hindsight's human-readable UTC for the same record. (This is gotcha ① — prove to yourself the epoch really is 1601.)
4. **Explain the zeros.** Hindsight's run reported **0** cookies, autofill, and logins. Write two sentences: *why* are they zero here, and what would you expect to see — and in which databases — if this were a full profile pulled from a live workstation?
5. **Ship the analyst deliverable.** Re-run Hindsight with `-f xlsx` instead of `jsonl`. Open the workbook, note the per-artifact tabs and the readable timestamps, and say in one line why you'd hand *this* to an examiner rather than the raw JSONL.
6. **Plan the live collection.** You're handed a *running* workstation with Chrome open. Write the three-line collection plan: which profile folder you grab, which **three files** you must copy *together* for the `History` artifact (gotcha ③), and one sentence on why leaving the `-wal` behind could cost you the most important evidence.

---

## 8. Key takeaways

- **The browser is often the whole case** — searched / visited / downloaded / when — and it's a **candid witness** because it keeps this data for its own convenience. Chrome, Edge, Brave, Opera, Vivaldi are **all Chromium**, so **one format and one tool** cover most of the market.
- **A profile is a folder of SQLite databases** at `%LOCALAPPDATA%\<vendor>\...\User Data\Default`: **`History`** (urls/visits/downloads/search terms), **`Cookies`** (moved to `Network\Cookies` in Chrome M96+), **`Web Data`** (autofill), **`Login Data`** (saved logins).
- **Three gotchas that make or break the analysis:** ① Chrome time = **microseconds since 1601-01-01 UTC**, not Unix; ② **cookies and passwords are DPAPI-encrypted** — the *artifact's existence* is the evidence, decryption is a separate credential-gated step; ③ **collect the `-wal`/`-shm` sidecars** — the newest activity lives in the WAL until a clean close checkpoints it.
- **Hindsight** (Apache-2.0, Obsidian Forensics) parses the **whole profile at once**, **normalizes timestamps** to UTC, reads the **WAL**, and enriches via plugins — `hindsight -i <profile> -o <out> -f <jsonl|sqlite|xlsx>`. Use **`xlsx`** for the human deliverable, **`jsonl`** for scripting.
- **The output is records; the analysis is the pivot** — on URL (where), timestamp (when/sessions), search terms (what they typed), downloads (what moved). Fold the browser timeline into the **super-timeline** (Module 18) alongside logons and filesystem activity.

---

## 9. Sources & further reading

- **Hindsight — repo, releases, and User Guide** (Ryan Benson / Obsidian Forensics, Apache-2.0): <https://github.com/obsidianforensics/hindsight> — the README + wiki document the plugins, output formats, and every profile database it parses (History, Cookies, Web Data, Login Data, Bookmarks, Preferences, extensions, storage, and Firefox `places.sqlite`).
- **forensics.wiki — Google Chrome** (profile paths, the `History` tables, and the timestamp epochs): <https://forensics.wiki/google_chrome/>
- **DFIR Blog — "Cookies Database Moving in Chrome 96"** (Ryan Benson) — the `Cookies` -> `Network\Cookies` relocation: <https://dfir.blog/cookies-database-moving-in-chrome-96/>
- **EpochConverter — Chrome/WebKit timestamp converter** (microseconds since 1601-01-01 UTC): <https://www.epochconverter.com/webkit>
- **Google Security Blog — "Improving the security of Chrome cookies on Windows"** (App-Bound Encryption, the "v20" scheme, Jul 2024): <https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html>
- **CyberArk — "The Current State of Browser Cookies"** (the "v10" AES-256-GCM + DPAPI Local-State-key design): <https://www.cyberark.com/resources/threat-research-blog/the-current-state-of-browser-cookies>
- **CyberArk — "C4 Bomb: Blowing Up Chrome's App-Bound Cookie Encryption"** (v20 internals): <https://www.cyberark.com/resources/threat-research-blog/c4-bomb-blowing-up-chromes-appbound-cookie-encryption>
- **ElcomSoft blog — "Browser Forensics in 2026: App-Bound Encryption and Live Triage"**: <https://blog.elcomsoft.com/2026/01/browser-forensics-in-2026-app-bound-encryption-and-live-triage/>
- **SQLite — Write-Ahead Logging (WAL)** (why the `-wal`/`-shm` sidecars must be collected): <https://www.sqlite.org/wal.html>
- **13Cubed (YouTube)** — hands-on Chrome/`History` forensics walkthroughs (WAL behaviour, timestamp conversion): <https://www.youtube.com/@13cubed>
- **MITRE ATT&CK** — **T1071.001 (Web Protocols)** and **T1567 (Exfiltration Over Web Service)** for the web C2/exfil that browser history evidences, and **T1539 (Steal Web Session Cookie)** for why `Cookies` is a target as well as an artifact: <https://attack.mitre.org/techniques/T1539/>


---
*Related modules: fold this browser timeline into the [Super-Timeline (Module 18)](../module-18-super-timeline) alongside logon events from [EVTX (Module 05)](../module-05-evtx-evtxecmd); correlate download target paths with the [Filesystem Timeline (Module 15)](../module-15-filesystem-timeline); and tie web activity to the human-at-the-keyboard picture from [User Activity (Module 17)](../module-17-user-activity).*


---

## Sources

- **Hindsight (Chromium + Firefox places.sqlite parser; Apache-2.0; jsonl/sqlite/xlsx)** — [obsidianforensics/hindsight (GitHub)](https://github.com/obsidianforensics/hindsight)
- **Chrome App-Bound Encryption for cookies ("v20", Chrome 127, July 2024)** — [Google Security Blog — Improving the security of Chrome cookies on Windows (30 Jul 2024)](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- **Chromium profile artifacts, SQLite databases, WAL/timestamp mechanics** — [SANS FOR500 — Windows Forensic Analysis](https://www.sans.org/cyber-security-courses/windows-forensic-analysis/)
- **Steal Web Session Cookie (why Cookies is both artifact and target)** — [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- **Exfiltration over web service / web-protocol C2 (download & history context)** — [MITRE ATT&CK T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) · [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- **DPAPI-protected Chrome credentials/cookies (field reference)** — [NirSoft — ChromePass / browser password recovery notes](https://www.nirsoft.net/utils/chromepass.html)
