# Module 21 — Network Forensics with tshark

**Deck mapping:** *Advanced Intrusion Forensic Hunting* → "Network Forensic Analysis" / evidence on the wire — reconstructing C2, exfil, and reconnaissance from a packet capture.
**Goal:** learn to triage a **PCAP** from the command line with **tshark**, the Wireshark CLI. Where the rest of this lab reads artifacts a host *left on disk*, network forensics reads the *other* half of the story — what actually crossed the wire. You'll take a small capture and, using nothing but tshark, answer the questions that decide network cases: **what protocols are in here, who talked to whom, what did they request, and which lookup looks wrong.** tshark runs **natively** on the lab VM (Git Bash on Windows; `tshark` is on your `PATH` as a shim), so everything below is copy-paste runnable and **offline** — no live capture, no interface, no Npcap needed.

> **Evidence note.** The capture in `data/capture.pcap` is a **crafted, benign, 8-packet** teaching file built with **Scapy** (`data/make_pcap.py`) — no live interface, no real traffic, no malware. It contains a normal **DNS** query/response and a plain-text **HTTP GET → 200 OK** to `example.com`, an **IANA-reserved test domain** that hosts no real service or C2, plus **one DGA-style `NXDOMAIN` lookup** (`kq3v9x7zpl2m8w.example.org`) so you have something *benign-but-suspicious* to hunt. Everything resolves to documentation-range or reserved addresses. We never alter evidence, so tshark's output shows the file's real baked-in values. The pcap **ships pre-built** — you do not need Scapy to do this module.

---

## 1. Background — why network forensics matters

A compromised host lies to you. Malware unhooks its own artifacts, timestomps its files, clears the event log, and lives in memory. **The network is harder to fake**, because the intrusion has to *communicate* to be useful — and communication leaves packets. The wire doesn't lie: a beacon has to reach its **C2** on a schedule, stolen data has to **exfiltrate** somewhere, **DNS tunneling** has to emit oddly-shaped lookups, credential theft has to **carry the hash or ticket** across the LAN, and lateral movement has to **open a session** to the next box. Every one of those actions is a packet you can find.

That's why "do you have a PCAP?" is one of the most valuable questions in incident response. A capture is a **timestamped, tamper-evident record of intent and action** that sits *outside* the attacker's reach on the endpoint. If a network tap, a span port, or a full-packet-capture appliance was recording, the answer to "what did the malware actually do" is often sitting in a `.pcap` — you just have to read it.

**tshark** is how you read it at the command line. Wireshark's GUI is superb for deep, interactive dissection, but triage — the first pass over a capture, and every scripted/automated pass after — belongs to the CLI. tshark is the *same dissection engine* as Wireshark, driven by flags, so it fits into pipelines, `grep`, and `jq`, runs headless on a server, and scales to captures too big to click through. The triage rhythm is always the same four moves:

**protocol hierarchy → filter → extract → follow / carve objects.**

You start with the bird's-eye view (what protocols, in what proportion), narrow to the traffic that matters with a display filter, pull the exact fields you need, and — when a session is interesting — reassemble the stream or carve the files that were transferred. This module walks that rhythm end to end on a capture small enough to hold in your head.

> **Plain-language summary:** The infected computer can hide its tracks, but it can't do its job without talking on the network — and that talking leaves packets. A packet capture (a `.pcap`) is a candid recording of that traffic. `tshark` is the command-line tool that reads it: get the big picture, filter to what matters, pull out the details, rebuild the conversation.

---

## 2. The tshark workflow — the flags you actually use

tshark has hundreds of options; a network-forensics triage uses a handful. Learn these and you can work any capture:

| Flag | What it does | Why it matters |
|---|---|---|
| **`-r <pcap>`** | **Read** a capture file (offline). | Every forensic run is `-r` — you're reading evidence, never capturing. |
| **`-z <stat>`** | Emit a **statistic / report** after reading. | The triage workhorse. `io,phs` (protocol hierarchy), `conv,tcp` (TCP conversations), `endpoints,ip` (per-host talkers), `http,tree` / `dns,tree` (protocol breakdowns), `expert` (tshark's own warnings/anomalies). Pair with **`-q`** to suppress per-packet output and print *only* the report. |
| **`-Y <displayfilter>`** | Apply a **display filter** (Wireshark syntax). | Narrows to the traffic you care about: `http.request`, `dns`, `http.response`, `tcp.port==443`, `ip.addr==10.0.0.50`. This is the same filter language as the Wireshark GUI's green bar. |
| **`-T fields -e <field>`** | Output selected **fields** as columns (tab-separated). | Turns packets into a table you can pipe, sort, and count — e.g. `-e ip.dst -e http.host -e http.request.uri`. Repeat `-e` for each column. |
| **`--export-objects http,<dir>`** | **Carve** transferred files (HTTP/SMB/TFTP/…) out of the capture into a directory. | This is how you recover the *actual payload* — the dropped EXE, the exfiltrated document — reassembled from its packets. |
| **`-z follow,tcp,ascii,<n>`** | **Reassemble** and print TCP stream number `<n>` as ASCII. | "Follow TCP Stream" from the CLI — read a whole request/response conversation as one blob instead of packet-by-packet. |

Two habits worth forming immediately: **`-q`** whenever you ask for a `-z` report (so you get the report, not a wall of packet lines), and **`-T fields -e …`** whenever you want output you'll feed to another tool. Between `-z` (statistics), `-Y` (filter), and `-T fields` (extract), you can answer most triage questions in one line.

---

## 3. Setup

Open **Git Bash** on the lab VM and change into this module's data directory. **Every command in this module runs from inside `data/`** — the evidence is the relative path `capture.pcap`.

```bash
cd module-21-network-forensics/data
tshark -r capture.pcap -q -z io,phs
```

- **tshark** is installed **natively on the lab VM and already on your `PATH`** (as a shim — you call `tshark` directly). No container, no Docker. The VM is kept **offline**, so nothing in this module touches a network interface.
- The capture **ships pre-built**. It was generated once, offline, with Scapy — the equivalent of running `python3 make_pcap.py capture.pcap` in this directory — but you do **not** need Scapy or to regenerate anything; `capture.pcap` is already here. (Peek at `make_pcap.py` if you want to see exactly which 8 packets were crafted.)
- That first command is also your **first analytical move** (Step 4a below) — reading a capture always starts with the protocol hierarchy.

---

## 4. Step-by-step walkthrough

### 4a. Protocol hierarchy — always the first thing you run

The command in Setup is the one you run on *any* new capture, before anything else:

```
tshark -r capture.pcap -q -z io,phs
```

`-z io,phs` prints the **Protocol Hierarchy Statistics** — every protocol tshark dissected, nested by layer, with frame and byte counts. For our capture:

```
eth                                      frames:8 bytes:660
  ip                                     frames:8 bytes:660
    udp                                  frames:3 bytes:255
      dns                                frames:3 bytes:255
    tcp                                  frames:5 bytes:405
      http                               frames:2 bytes:243
        data-text-lines                  frames:1 bytes:130
```

**How to read it:** all **8 frames** are Ethernet → IP, then the tree forks — **3 frames of UDP/DNS** and **5 frames of TCP**, of which **2** carry **HTTP** (the GET request and the 200 response; the response body shows as `data-text-lines`). In ten seconds you've learned the *shape* of the capture: a little DNS, one small web conversation, nothing else. On a real capture this single view is where triage begins — it tells you instantly whether you're looking at plain HTTP, a sea of TLS, unexpected protocols (IRC, SMB, raw TCP on odd ports), or tunneling, and where to point your filters next.

### 4b. HTTP requests — what was fetched

Filter to HTTP requests and pull the fields that describe *what was asked for*:

```bash
tshark -r capture.pcap -Y http.request -T fields -e ip.dst -e http.host -e http.request.uri
```

```
93.184.216.34	example.com	/
```

`-Y http.request` keeps only request packets; `-T fields -e …` prints three columns — the **destination IP**, the **`Host` header**, and the **request URI**. One request: a **`GET /`** to `example.com` at `93.184.216.34`. That triplet — *who you connected to* (`ip.dst`), *what name the client asked for* (`http.host`), and *what resource* (`http.request.uri`) — is the core of HTTP triage. In a real case this is where a malware download URL, a webshell path, or an API call to a C2 panel shows up in plain sight.

### 4c. DNS queries — where the hunting signal hides

DNS is the richest hunting ground in most captures, because *everything resolves a name first*. Pull every queried name:

```bash
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name
```

```
example.com
example.com
kq3v9x7zpl2m8w.example.org
```

`example.com` appears **twice** — once in the query, once echoed back in the response (both frames carry `dns.qry.name`) — a normal, human-readable lookup. The third line is the one that should make you stop: **`kq3v9x7zpl2m8w.example.org`**. Nobody types that. A **long, high-entropy, pronounceable-by-no-one** label that resolves to **`NXDOMAIN`** is a classic **hunting signal** — the fingerprint of a **DGA** (Domain Generation Algorithm: malware computes throwaway domains to find its live C2, so most of them don't exist and return NXDOMAIN) or of **DNS tunneling / exfil** (data encoded into subdomain labels). Here it's a **benign teaching lookalike** — a real, safe `.org` name in a reserved domain — but the *tell* is authentic: **length, entropy, and NXDOMAIN together** are what you triage for. Pivot on those (`-z dns,tree`, or filter `dns.flags.rcode==3` for NXDOMAIN) and you separate the one suspicious lookup from the noise.

### 4d. TCP conversations — the top talkers

Ask tshark to summarize endpoint-to-endpoint conversations:

```bash
tshark -r capture.pcap -q -z conv,tcp
```

```
TCP Conversations
                                                           |       <-      | |       ->      | |     Total     |
10.0.0.50:52000            <-> 93.184.216.34:80                 2 184 bytes       3 221 bytes       5 405 bytes
```

`-z conv,tcp` lists each TCP conversation with its two endpoints (IP:port ↔ IP:port), directional and total **frame/byte counts**, and timing. One conversation here: client **`10.0.0.50:52000`** ↔ server **`93.184.216.34:80`**, 5 frames total. On a real capture this table is how you spot the **top talkers** and, crucially, the **beacons**: a host that opens a small, near-identical conversation to the same endpoint over and over, on a regular interval, is the byte-count-and-timing signature of **C2 beaconing**. Sort conversations by bytes to find bulk **exfil**; sort by count/regularity to find beacons.

### 4e. The HTTP response — status and content type

Finally, look at what came *back*:

```bash
tshark -r capture.pcap -Y 'http.response' -T fields -e http.response.code -e http.content_type
```

```
200	text/html
```

`-Y 'http.response'` keeps only response packets; the fields give the **status code** and **`Content-Type`**. A clean **`200 text/html`** — the server returned a normal web page. Response metadata matters: a `200` with `application/octet-stream` or `application/x-msdownload` means a **file** came down the wire (carve it — Section 5), and mismatches between the URI and the content type (a `.jpg` that's really an executable) are a known evasion you catch right here.

---

## 5. Going further — carving objects and following streams

Two moves that turn triage into recovery. Neither is needed for this tiny capture (there's no file to carve and the stream is trivially short), but they are the reason tshark is a forensic tool and not just a viewer:

- **Carve transferred files.** `--export-objects http,<dir>` walks the whole capture, reassembles every HTTP transfer, and writes each one to disk as the actual file:
  ```
  tshark -r capture.pcap --export-objects http,./carved
  ```
  On a real capture this is how you recover the dropped payload or the exfiltrated document — the bytes, reconstituted from their packets, ready to hash and submit. (tshark can also export `smb`, `tftp`, `imf`, and more.)
- **Follow a TCP stream.** `-z follow,tcp,ascii,<n>` reassembles conversation `<n>` and prints it as one readable blob:
  ```
  tshark -r capture.pcap -q -z follow,tcp,ascii,0
  ```
  This is "Follow TCP Stream" from the CLI — read the full HTTP request and response (headers, `Host`, `User-Agent`, body) as a single exchange instead of hunting across packets.

---

## 6. Two notes every network analyst needs

### (a) TLS decryption — you can read HTTPS, but only if you planned ahead

Most real traffic is **TLS-encrypted**, and a capture of encrypted traffic shows you only the *metadata* (endpoints, timing, SNI, certificate) — not the payload. You can decrypt it, but **only with the session keys**, and those must be captured **at the time of the connection**:

- Set the **`SSLKEYLOGFILE`** environment variable *before* the client runs. Clients that honor it — **curl, Chrome, Firefox, and most OpenSSL/NSS-based tools** — will append their per-session TLS secrets to that file as they connect.
- **Important gotcha:** **.NET / PowerShell `Invoke-WebRequest` does NOT honor `SSLKEYLOGFILE`** (it uses Windows SChannel, not OpenSSL/NSS). Neither do many native Windows components. So a key-log strategy covers curl and browsers but **misses** a lot of Windows-native traffic — know the gap before you rely on it.
- With the key log in hand, Wireshark/tshark decrypts the HTTPS: point tshark at it (`-o tls.keylog_file:<path>`), or bake the secrets **into** the pcap itself with **`editcap --inject-secrets tls <keylog> in.pcap out.pcapng`** so the capture is self-decrypting and portable.

The lesson: **decryption is a collection-time decision.** If nobody set `SSLKEYLOGFILE` (or captured the server's private key for RSA key-exchange, which modern forward-secret ciphers defeat anyway), the TLS payload stays sealed and you work the metadata.

### (b) Zeek — the log-oriented complement to tshark

**Zeek** (formerly Bro) is the other pillar of network forensics. Where tshark answers *packet-level* questions on a capture, Zeek turns traffic into **structured connection and protocol logs** — `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `x509.log` — one tidy record per connection/transaction, ideal for hunting across **huge** captures and for feeding a SIEM. It's how you ask "show me every DNS lookup with a label longer than 30 chars across a week of traffic" without touching a single packet by hand. **Zeek runs on Linux/macOS and is not a native-Windows tool**, which is exactly why *this* lab module uses **tshark** (native on the Windows lab VM). Think of them as partners: **tshark for packet-level triage on the endpoint you're sitting at, Zeek for log-scale hunting on the fleet** (it's a natural fit on the Linux side of a lab — the same box that runs your other log tooling).

---

## 7. Try-it-yourself exercises

1. **Read the hierarchy cold.** Run `-z io,phs` and, *without* looking at any other command, write one sentence predicting what the capture contains and where you'd point your next filter. Then verify with 4b–4e.
2. **Hunt the bad lookup by rcode.** The DGA-style name returns NXDOMAIN. Filter for it directly: `tshark -r capture.pcap -Y 'dns.flags.rcode==3' -T fields -e dns.qry.name`. Explain in one line why **NXDOMAIN + high-entropy label** is a stronger signal together than either alone.
3. **Follow the stream.** Run `-z follow,tcp,ascii,0` and read the full HTTP exchange. Identify the **`User-Agent`** the client sent. Why is a `User-Agent` of `curl/8.0` (rather than a browser string) itself worth a note in a real triage?
4. **Extract with your own fields.** Write a `-T fields` command that outputs, for every DNS packet, the **query name** *and* the **response code** (`-e dns.qry.name -e dns.flags.rcode`). Which line flags the suspicious lookup?
5. **Pivot to conversations.** From `-z conv,tcp`, describe what you'd expect a **beacon** to look like in this table (hint: many small, near-identical conversations to one endpoint at a fixed interval) versus a **bulk exfil** (few conversations, large `->` byte counts). Which column tells you which?
6. **Plan the TLS case.** Suppose this same request had gone to `https://example.com`. Write the three-line plan for making it readable: which environment variable you set, *before what*, and which common Windows tool would still defeat you (Section 6a).

---

## 8. Key takeaways

- **The network is the honest witness.** A host can hide its own artifacts; the intrusion still has to *communicate* — C2 beacons, DNS tunneling/exfil, credential theft, lateral movement — and that communication leaves packets. A `.pcap` is a timestamped record outside the attacker's reach.
- **The triage rhythm is fixed:** **protocol hierarchy → filter → extract → follow/carve.** `-z io,phs` first (the shape of the capture), then `-Y` to narrow, `-T fields -e` to tabulate, `follow`/`--export-objects` to reassemble and recover.
- **The flags that do the work:** `-r` (read evidence), `-z` (`io,phs`, `conv,tcp`, `endpoints,ip`, `http,tree`, `dns,tree`, `expert`), `-Y` (display filter), `-T fields -e` (extract), `--export-objects` (carve files), `-z follow,tcp,ascii,n` (reassemble a stream). Add **`-q`** with any `-z` report.
- **DNS is the hunting ground.** A **long, high-entropy label** that returns **NXDOMAIN** is the fingerprint of a **DGA** or **tunnel** — length + entropy + NXDOMAIN together. TCP **conversations** expose beacons (regular, tiny, repeated) and exfil (large outbound byte counts).
- **TLS is a collection-time decision** — `SSLKEYLOGFILE` before capture (curl/browsers honor it, **`Invoke-WebRequest` does not**), then decrypt or `editcap --inject-secrets tls`. **Zeek** is the log-scale complement to tshark, but it's **Linux/macOS**, so this module stays on tshark.

---

## 9. Sources & further reading

- **`tshark(1)` man page** — the authoritative flag reference (`-r`, `-z`, `-Y`, `-T fields`, `--export-objects`, `follow`): <https://www.wireshark.org/docs/man-pages/tshark.html>. See also the Wireshark **Display Filter Reference** for field names like `http.host`, `dns.qry.name`, `dns.flags.rcode`.
- **SANS FOR572 — Advanced Network Forensics: Threat Hunting, Analysis, and Incident Response** — the definitive course on PCAP triage, protocol analysis, NetFlow/log correlation, and the DGA/tunneling/beaconing tradecraft this module previews.
- **Chris Sanders, *Practical Packet Analysis*, 3rd ed. (No Starch Press)** — the standard hands-on introduction to Wireshark/tshark, display filters, following streams, and reading protocol hierarchies; pairs directly with everything above.
- **Wireshark SampleCaptures wiki** — <https://wiki.wireshark.org/SampleCaptures> — a large library of real benign and malware captures to practice these exact commands against once you outgrow the 8-packet lab file.
- **Zeek documentation** — <https://docs.zeek.org/> — the connection/protocol log model (`conn.log`, `dns.log`, `http.log`, `ssl.log`) for log-scale hunting, the complement described in Section 6b.
- **MITRE ATT&CK** (investigative context): **T1071 — Application Layer Protocol** (C2 over HTTP/DNS/etc., the traffic in Sections 4b/4c); **T1048 — Exfiltration Over Alternative Protocol** (data leaving over DNS/other channels, the tunneling signal in 4c); **T1568.002 — Dynamic Resolution: Domain Generation Algorithms** (the `kq3v9x7zpl2m8w` NXDOMAIN fingerprint): <https://attack.mitre.org/>.

---
*Related modules: this network lane pairs with the host artifacts elsewhere in the lab — correlate C2/exfil timing against logon and process events from [EVTX (Module 05)](../module-05-evtx-evtxecmd) and [Sysmon/WEF (Module 10)](../module-10-sysmon-wef), tie beaconing to the [Lateral Movement (Module 08)](../module-08-lateral-movement) picture, fold packet timestamps into the [Super-Timeline (Module 18)](../module-18-super-timeline), and remember that [Velociraptor (Module 20)](../module-20-triage-velociraptor) is how you'd collect a live capture in the first place.*
