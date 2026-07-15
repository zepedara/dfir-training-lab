# Module 22 — Detection Engineering (author → validate → convert → test)

**Deck mapping:** *Intrusion Hunting Playbook* → "Building & Maintaining Detections" · *Advanced Intrusion Forensic Hunting* → "From hunting to detection-as-code."
**Goal:** stop *consuming* other people's detections and start *building your own*. You'll **author** a Sigma rule, **validate** its syntax with `sigma-cli`, **convert** it to a concrete backend query, and **test** it against real event logs with **Zircolite** — the full detection-as-code loop, offline, on evidence you already have.

> **Evidence note.** This module invents **no new evidence**. It reuses two **inert** `.evtx` files already in the lab: a **Security 7045 service-install** log from **Module 8** (lateral movement) and a **PowerShell obfuscation** log from **Module 6** (Sigma hunting). You're pointing rules you wrote at logs you've already met.

---

## 1. Background — why this matters

### Detection engineering, in plain language
In **Module 6** you took a **community** Sigma rule set (SigmaHQ, thousands of rules) and ran it over logs with Chainsaw and Hayabusa. You were a **consumer** of detections. That's the right place to start — but every environment has behaviour the public rules don't cover, and every real SOC eventually has to **write and maintain its own rules**. That discipline is **detection engineering**.

The core idea is **detection-as-code**: a detection rule is not a one-off search you type into a console and forget. It's **source code** — versioned in Git, reviewed by a peer (a pull request), **tested** against known-bad and known-good samples before it ships, and deployed with a way to roll it back. You treat "is this rule good?" the same way a software team treats "is this function correct?": with tests and review, not vibes.

### Where Sigma fits
**Sigma** is the vendor-neutral, plain-text (YAML) language detections are written in — you met it in Module 6. Its superpower is **write once, run anywhere**: the *same* Sigma rule can be compiled to a Splunk search, an Elastic query, a Microsoft Sentinel KQL query, a Zircolite SQL query, or the rule format Chainsaw and Hayabusa consume. You author the *logic* once, abstractly; the toolchain translates it to whatever backend you actually run.

That "write once, run anywhere" promise is exactly what makes Sigma the right format for detection-as-code — your rule library isn't chained to one vendor.

### Module 6 vs. Module 22 — the one-line difference
- **Module 6:** you **ran a community ruleset** someone else wrote and maintained.
- **Module 22:** you **author, validate, convert, and test your own rule** — and you learn how to tell whether it's any good.

---

## 2. The author → validate → convert → test loop

This is the whole module in four moves. Learn the loop; the commands are just how you drive it.

### (a) Author — write the Sigma rule
A Sigma rule is a small YAML document with four parts that matter here:

- **`logsource`** — *which* logs the rule applies to (product / service / category). It's a filter: a rule scoped to `service: system` never even looks at PowerShell script logs. Get this wrong and a perfect rule matches nothing.
- **`detection`** — one or more named **selections** (field/value conditions), e.g. `EventID: 7045`, or `ScriptBlockText|contains: '-enc'`. The `|contains`, `|startswith`, `|endswith` suffixes are **modifiers** that change how the value is matched.
- **`condition`** — how the selections combine (`selection`, `selection1 and not filter`, `1 of them`, …). This is the boolean logic of the rule.
- **`level`** — severity (`informational` → `low` → `medium` → `high` → `critical`). It sets reading order downstream, not importance.

### (b) Validate — `sigma check`
Before you convert or test anything, ask sigma-cli: *is this even a well-formed Sigma rule?* `sigma check` parses the YAML, verifies the schema, flags duplicate IDs, dead references, and structural mistakes. It's your **linter** — the fast "does it compile?" gate. A clean check does **not** mean the rule is *good*; it means it's *valid*.

### (c) Convert — `sigma convert -t <backend> -p <pipeline>`
Conversion compiles your abstract Sigma rule into the **concrete query language** of a target system. `-t sqlite` emits SQL; `-t splunk` emits SPL; and so on. This is the "one rule, many targets" payoff made visible.

**The single most important concept in this module is the processing pipeline, `-p`.** A Sigma rule names **logical** fields (`Image`, `ScriptBlockText`, `EventID`). But the actual event stores those values under *specific, backend-dependent field names* — Sysmon's `Image`, an ECS index's `process.executable`, Zircolite's flattened column. A **pipeline** is the translation table that maps Sigma's abstract field names onto the target's real ones (and can add index conditions, rename fields, drop unsupported ones).

Burn this in: **when a rule validates cleanly and converts without error but still fires nothing, the cause is almost always a missing or wrong pipeline — not broken detection logic.** The logic was fine; the field names didn't line up with the data. Reaching for the pipeline is the first thing an experienced detection engineer checks, and the last thing a beginner thinks of.

### (d) Test — Zircolite
**Zircolite** (by wagga40) is a fast, standalone Sigma engine. It loads `.evtx` (or JSON/Sysmon/auditd) events into an **in-memory SQLite database**, converts your Sigma rules to SQL with **pySigma**, and runs them as `SELECT … WHERE …` queries over that database. It needs no SIEM, no agent, no internet — perfect for a lab and for CI.

The reason Zircolite is a great *teaching* engine: it makes detection **concrete**. A detection isn't magic — it is literally **a query over a table of structured events**. You can see the SQL, and you can see the rows it returns.

---

## 3. Setup

Open **Git Bash** on the lab VM. Every tool in this module — `sigma`, `zircolite`, `python3` — is installed natively and already on your `PATH` (they're shims), so you call them by name; no container, no Docker. The VM is offline and stays offline.

**One-time evidence staging (already done for you).** The detection targets aren't generated here — they're **copied in from Modules 8 and 6**. A helper script, `data/get-data.sh`, does this: it copies the **Security-7045 service-install** evtx from Module 8 and the **PowerShell-obfuscation** evtx from Module 6 into `data/evtx/`. In this lab the evtx is **pre-staged**, so you don't need to run it — but for the record, staging is just:

    # one-time only, already done — copies the inert evtx from Modules 08 + 06 into evtx/
    sh get-data.sh

First, read the two rules that ship with the module so you know what you're about to validate and test:

```bash
cd module-22-detection-engineering/data
cat rules/new_service.yml
```

You'll see a **deliberately broad** rule — it fires on **any** `EventID: 7045` (any Windows service install), no allow-listing, no path filter. That's on purpose: it's the "too broad, now refine it" teaching specimen. `rules/powershell_encoded.yml` (the second rule in the folder) is tighter — it matches PowerShell script blocks containing `-enc`, `-EncodedCommand`, or `FromBase64String`, the fingerprints of base64-obfuscated commands.

> **`cd` once.** Run the `cd` above **only in this first block**. Every command below is executed from inside `data/`, so they never repeat the `cd`.

---

## 4. Step-by-step walkthrough

### Step 1 — Read the authored rule
(You already ran `cat rules/new_service.yml` in Setup.) Look at its anatomy against Section 2(a):

- `logsource: {product: windows, service: system}` — scoped to the **System** log, where service-control-manager events (7045) live.
- `detection.selection: {EventID: 7045}` and `condition: selection` — fire on any service-install event.
- `level: medium`, and a `description` that literally says *"Broad on purpose - refine it."*

This is your specimen for the whole loop.

### Step 2 — Validate the syntax
```bash
sigma check rules/new_service.yml
```
**Expected output:**
```
No validation issues found.
```
sigma-cli parsed the YAML, checked it against the Sigma schema, and found no structural problems. The rule **compiles**. (Remember: valid ≠ good. We haven't tested whether it *detects* anything yet.)

### Step 3 — Convert to a concrete backend query
```bash
sigma convert -t sqlite rules/new_service.yml
```
**Expected output (a SQL query):**
```sql
SELECT * FROM logs WHERE EventID=7045
```
This is the "**write once, run anywhere**" moment made literal. Your abstract Sigma rule just became a concrete **SQL** query. Point `-t` at a different backend (`splunk`, `esql`, `elasticsearch`, …) and the *same rule* emits SPL, ES|QL, or a Lucene query instead. **One rule, many targets** — you never rewrite the logic, you only change the target.

> This is also where **`-p <pipeline>`** enters in real life: `sigma convert -t splunk -p sysmon rules/new_service.yml` would apply the Sysmon field-mapping pipeline so `Image` etc. map to the names Splunk's Sysmon data uses. Our broad rule keys only on `EventID`, which needs no remapping, so we convert without a pipeline here — but on any field-rich rule, `-p` is what makes the query actually match. (See Section 2c.)

### Step 4 — Test both rules against the evtx with Zircolite
```bash
zircolite --evtx evtx -r rules -c fieldMappings.yaml -o detect.json
```
- **`--evtx evtx`** — the folder of target `.evtx` (the staged Module 8 + Module 6 logs).
- **`-r rules`** — the folder of Sigma rules to run (**both** shipped rules).
- **`-c fieldMappings.yaml`** — Zircolite's field-mapping/config (its equivalent of a pipeline: how it flattens and names event fields).
- **`-o detect.json`** — write detections here.

**Expected output (summary lines):**
```
Matched 3 events across 1 rules
Coverage 1/2 rules matched (50.0%)
```
**Read it carefully — this result is the lesson.** Two rules ran. The **"New Service Installed"** rule fired **3 times** on the 7045 log. The **"Encoded PowerShell Command"** rule fired **zero** times — so **coverage is 1 of 2 rules (50%)**. That is **not a failure**: the PowerShell rule is correct, it simply had **no matching events in this evtx set** to fire on. A rule only ever fires where the events it describes actually exist. Detection engineers read this two ways: the service rule earned a **true positive** against a real service-install sample, and the silence of the PowerShell rule here just means *this* evidence didn't contain its trigger — you'd validate that rule against a PowerShell-obfuscation sample instead.

### Step 5 — Read the detections programmatically
```bash
python3 -c "import json,sys; d=json.load(open('detect.json')); print(sum(len(r.get('matches',[])) for r in d), 'detections across', len(d), 'rules'); [print(' -', r.get('title')) for r in d]"
```
**Expected output:**
```
3 detections across 1 rules
 - New Service Installed
```
`detect.json` is machine-readable on purpose: this is how CI (Section 6) checks a rule's results without a human eyeballing a console. Three matches, one rule — the **New Service Installed** rule, exactly as the summary said.

---

## 5. Reading the result — measure detection *quality*, not rule count

The coverage number (1/2, 3 matches) is the doorway to the single most important idea in detection engineering: **how you measure whether a detection is good.**

- **True positives (TP) against attack samples.** Does the rule fire on a *labeled known-bad* event? The service rule did — 3 hits on a real 7045 service-install. That's the evidence a rule *works*.
- **False-positive silence against benign noise.** Does the rule *stay quiet* on *labeled known-good* logs? A rule that screams on every normal admin action is worse than no rule — it trains analysts to ignore it (alert fatigue). You test this by running the rule over benign baseline logs and confirming **zero** hits.
- **A good rule maximises TP on bad *and* FP-silence on good.** Both. Our broad `new_service.yml` nails the TP but would light up on **every legitimate service install** on a real host — high TP, terrible FP profile. That's why its own description says *refine it* (see Try-it-yourself #3).

> **The vanity metric to distrust: rule count.** "Our SOC has 6,000 detections" tells you nothing about whether you'd catch an intrusion. A thousand untested, noisy, overlapping rules is *worse* than fifty rules each proven against known-bad and known-good samples — the thousand bury real alerts in false positives and nobody can maintain them. **Measure coverage and precision against labeled samples, never rule count.**

---

## 6. Detection-as-code — the methodology

The loop you just ran by hand is, in a mature team, an automated pipeline. The rule *is* code, so it gets the software lifecycle:

1. **Version.** Every rule lives in Git. Changes are commits with history — you can see who changed a detection, when, and why, and diff two versions.
2. **Review.** A new or changed rule goes through a **pull request**. A second engineer reviews the logic, the `logsource` scope, and the false-positive risk before it merges — the same gate as production code.
3. **Test in CI.** A CI job (e.g. **GitHub Actions**) runs on every PR: it **`sigma check`**s the rules, converts them with **pySigma**, and runs them (with **Zircolite** or the backend's test harness) against a corpus of **labeled samples** — known-bad evtx that *must* fire, and benign baselines that *must stay silent*. The PR fails if a rule regresses (stops catching its TP, or starts alerting on benign data). This is exactly Steps 2–5, automated.
4. **Compile to target syntax.** On merge, the pipeline **converts** the abstract rules to whatever backends you run (Splunk, Elastic, Sentinel, Zircolite) with the right **`-p` pipelines** — one source of truth, many deployed targets.
5. **Promote with rollback.** Deploy to production detection platforms, but keep the Git history and versioned artifacts so a noisy rule can be **rolled back** instantly. Detections change as environments change; safe promotion and easy revert are part of the job.

That's detection-as-code: **authored, reviewed, tested, versioned, compiled, and reversible** — not a search someone typed once and forgot.

---

## 7. Try-it-yourself exercises

1. **Author a brand-new rule.** Copy `rules/new_service.yml` to `rules/my_rule.yml`, give it a fresh `id` (any UUID) and title, and point its `detection` at a different `EventID` you met in an earlier module (e.g. 4688 process creation, or 4624 logon). Run `sigma check` on it, then `sigma convert -t sqlite`. Did the SQL come out the way you expected?
2. **Convert to another backend.** Run `sigma convert -t splunk rules/new_service.yml` (or another installed backend). Compare the SPL/query to the SQLite SQL. Same rule, different target — that's the whole point of Sigma.
3. **Refine the broad rule to cut false positives.** `new_service.yml` fires on *every* 7045. Add a second selection and a `condition` so it only fires on **suspicious** service installs — e.g. a `ServiceName|contains` or `ImagePath|contains` filter for a world-writable path like `\Users\Public\` or `\Temp\`, or `not` an allow-list of known-good service names. Re-run Zircolite. Does it still catch the attack sample while it would now stay quiet on routine installs? (Check the 7045 evtx's actual `ImagePath` first so your filter matches real evidence.)
4. **Explain a zero.** Point Zircolite at *only* the PowerShell evtx (`--evtx` at just that file). Now which rule fires, and which goes silent? Write one sentence on why coverage is about *where the events are*, not rule quality.

---

## 8. Key takeaways

- **Detection engineering = detection-as-code:** rules are versioned, peer-reviewed, and **tested** source code, not one-off searches.
- **Sigma is write-once-run-anywhere.** Author the logic abstractly; **`sigma convert -t`** compiles it to Splunk / Elastic / SQLite / etc. — one rule, many targets.
- **The loop is author → `sigma check` (validate) → `sigma convert` (compile) → Zircolite (test).**
- **The `-p` processing pipeline is the concept that trips everyone up.** A valid, converting rule that fires nothing almost always has a **missing/wrong pipeline**, not broken logic.
- **Measure quality by TP-on-bad and FP-silence-on-good against labeled samples — never by rule count.** The 1/2 coverage here is a *teaching* result: a rule only fires where its events exist.
- **Automate it:** version in Git, review by PR, test in CI with pySigma + Zircolite, compile to targets, promote with rollback.

---

## 9. Sources & further reading

- **SigmaHQ** — project home & docs (getting-started, backends, pipelines): <https://sigmahq.io/> · Docs: <https://sigmahq.io/docs/>
- **sigma-cli** (the `sigma check` / `sigma convert` tool): <https://github.com/SigmaHQ/sigma-cli>
- **pySigma** (the conversion engine sigma-cli and Zircolite build on): <https://github.com/SigmaHQ/pySigma> · Processing pipelines: <https://sigmahq.io/docs/digging-deeper/pipelines.html>
- **Sigma rule specification** (the `logsource`/`detection`/`condition` schema): <https://github.com/SigmaHQ/sigma-specification>
- **Zircolite** — wagga40: <https://github.com/wagga40/Zircolite> · Docs: <https://wagga40.github.io/Zircolite/>
- **MITRE ATT&CK** — Create or Modify System Process: Windows Service (**T1543.003**, the 7045 service install): <https://attack.mitre.org/techniques/T1543/003/> · Command & Scripting Interpreter: PowerShell (**T1059.001**): <https://attack.mitre.org/techniques/T1059/001/>
- **Detection-as-code in CI** — SigmaHQ rules repo CI as a reference for testing rules in a pipeline: <https://github.com/SigmaHQ/sigma>

---

*This module closes the loop the DFIR track has been building toward: Modules 5–6 taught you to **parse and hunt** with detections others wrote; here you **write, validate, and test your own** — the transition from detection *consumer* to detection *engineer*.*
