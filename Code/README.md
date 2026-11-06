# tlsfp: Passive TLS Fingerprinting (JA3 / JA3S / JA4 / JA4S)

`tlsfp` passively captures TLS **ClientHello** and **ServerHello** messages, computes
**JA3/JA3S** (Salesforce) and **JA4/JA4S** (FoxIO) fingerprints, and identifies the
client application or TLS library from a curated reference database, **without decrypting
anything**.

```
packets ──► TCP reassembly ──► TLS hello parser ──► JA3 / JA3S / JA4 / JA4S ──► reference DB ──► verdict + status
(Npcap/libpcap,   (multi-segment,     (pure Python,           (spec-exact,            (SQLite; learned +     (agree / ja4_only /
 pcap / pcapng)    out-of-order,       GREASE-aware)           validated)              published entries,     ja3_only / ambiguous /
                   any port, IPv4/6)                                                   optional Redis/Valkey) conflict / unknown)
```

## How the project meets the brief

| Expected outcome | Where it is shown | Current status |
|---|---|---|
| Passive capture of ClientHello + ServerHello (Scapy/libpcap) | `live`, `analyze`; demo steps 2 and 5 | Live on Windows/Npcap and offline pcap/pcapng |
| Optional Linux XDP capture | `live --backend xdp`; [Linux setup](docs/linux-capture-and-benchmark.md) | Code feeds XDP frames into the same decoder, reassembly and fingerprint pipeline. **Not run in this project** (needs Linux + BCC); its tests only cover the CLI option and the clean failure off Linux |
| JA3/JA3S extractor (JA4/JA4S stretch goal) | `tlsfp/fingerprints.py` | Implemented per spec |
| Validated against published reference values | `tests/test_published.py`, `results/fingerprint_validation.csv` | JA4 135/136 and JA4S 76/76 vs FoxIO's published expected output; JA3/JA3S published vectors reproduced; JA3 225/225 and JA3S 202/202 vs Wireshark |
| Curated DB identifying ≥5 distinct clients | `data/reference_db.json` (9 learned clients + 16 published, cited entries) | **75/75** held-out connections from 9 clients identified (JA4+JA3) |
| curl vs browser vs custom client on the wire | demo step 5 (live), `results/client_identification_results.csv` | Chrome, Edge, Firefox, curl, PowerShell, urllib, requests, custom script, hand-crafted client all separated |
| Security role and limitations, incl. browser randomisation | sections below, `results/fingerprint_stability.csv`, `results/spoofing_results.csv` | Chrome: 19 connections → 19 JA3s, 1 JA4. Spoofing: 10/10 accepted as Chrome |
| Optional packet-rate generation | `benchmarks/trex/`; [TRex setup](docs/linux-capture-and-benchmark.md) | Synthetic ClientHello packets; requires a separate Linux TRex host and capture NIC. **Not run in this project**: no TRex results are reported |
| Optional shared Redis/Valkey lookups | `db sync-redis`, `live --redis`, `tests/test_redis_integration.py` | Opt-in integration test against a disposable service (skipped unless `TLSFP_REDIS_URL` is set). Not used in the reported experiments, which use SQLite |

## Install (Windows, PowerShell)

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt matplotlib requests
.venv\Scripts\python -m pytest -q tests          # Redis integration test skips unless TLSFP_REDIS_URL is set
```
Live capture needs **Npcap** (installed with Wireshark). On Linux/macOS install libpcap and run
captures with `sudo`. Wireshark ≥ 4.2 (tshark) is optional and only needed for `validate`.
Python 3.13 is used because its OpenSSL (3.0) is the one the reference DB was learned with.
Other Python versions use a different OpenSSL, so their urllib/requests fingerprints differ (the
unknown-client demo relies on exactly this).

To run the optional Redis/Valkey integration test against a disposable local Valkey:

```powershell
docker compose -p tlsfp-validation up -d valkey
.venv\Scripts\python -m pip install -r requirements-redis.txt
$env:TLSFP_REDIS_URL = "redis://localhost:6380/15"
.venv\Scripts\python -m pytest -q tests\test_redis_integration.py
docker compose -p tlsfp-validation down
```

## Professor demonstration

```powershell
.\demo\run_demo.ps1 -Interface "Wi-Fi 3"           # all steps, pauses between steps
.\demo\run_demo.ps1 -Step offline                  # or one step at a time
```

| Step | Shows |
|---|---|
| `setup` | Load the curated DB (learned + published entries with provenance) |
| `validate` | Unit/reference tests incl. published vectors and FoxIO pcaps; cross-check with Wireshark |
| `offline` | Fingerprints and verdicts from a capture file |
| `evaluate` | Held-out accuracy with JA4+JA3, JA3 only, JA4 only |
| `stability` | Chrome/Edge randomisation: new JA3 every connection, stable JA4 |
| `live` | Second window sniffs the interface; curl, requests, custom, hand-crafted, Chrome and Firefox connect; `proc=` (OS ground truth) vs `=>` (fingerprint verdict) |
| `unknown` | Python 3.14/OpenSSL 3.5 is not in the DB → `UNKNOWN`, never guessed |
| `spoof` | A Python script replays Chrome's JA4 against a real server and is identified as Chrome |
| `server` | JA3S/JA4S; same server, different client, different JA3S; published "Sliver C2" JA4S matches Wikipedia |
| `report` | Monitoring view: history, identification status counts, top unknowns, malware-list hits |
| `results` | Saved CSVs, charts and summary |

The offline steps need no network, so the demo still works if the room has no internet.
Find the interface name with `python -m tlsfp ifaces` (on the development laptop it is `Wi-Fi 3`).
The Scapy backend remains the default. Linux users can opt into XDP with
`python -m tlsfp live --backend xdp -i eth0`; see
[docs/linux-capture-and-benchmark.md](docs/linux-capture-and-benchmark.md) for BCC setup,
supported packet formats, and the isolated TRex benchmark procedure.

## Commands

```
python -m tlsfp [--db tlsfp.db] <command>
  ifaces                                  list capture interfaces
  live      [-i IF] [-f BPF] [--backend scapy|xdp] [-w out.pcap] [--resolve-process] [--auto-learn] [--json] [--sni S] [--show-server]
  analyze   PCAP [--show-server] [--record] [--json] [--sni S] [-v]
  learn     PCAP (--manifest M | --label L [--sni S] [--category C])
  evaluate  PCAP --manifest M [--ja3-only | --ja4-only]
  stability PCAP --manifest M
  validate  PCAP                          compare with Wireshark/tshark's JA3/JA3S/JA4
  report    [--hours N]                   history: status counts, verdicts, top unknowns, malware hits
  db list | add | remove | export | import | import-sslbl | import-csv | sync-redis
```

### Identification logic (`FingerprintDB.identify`)

JA4 and JA3 are looked up independently and the evidence is combined. Neither method silently
overrides the other:

| JA4 lookup | JA3 lookup | Status | Counted as identified? |
|---|---|---|---|
| A | A | `agree` | yes |
| A | nothing | `ja4_only` | yes |
| nothing | A | `ja3_only` | yes (weaker: JA3 is easy to replay) |
| A | B (disjoint) | `conflict`, both shown | no |
| several labels left | | `ambiguous` | no |
| nothing | nothing | `unknown` | no |

If JA4 is shared by several applications, a JA3 match can narrow it down to one (`agree`).
Server hellos use the same logic on JA4S/JA3S.

## Reproducing the experiments

All results in `results/` come from files committed in this repository:

```powershell
.venv\Scripts\python experiments\run_experiments.py   # ~1 min; writes results/*.csv, *.png, SUMMARY.md
```

The captures were recorded like this (two terminals, Windows 11, Wi-Fi):
```powershell
# training capture: 9 clients x 3 runs
python -m tlsfp live -i "Wi-Fi 3" -f "tcp port 443" -w captures/train_v2_raw.pcap -t 200 --no-record
python scripts/gen_traffic.py --repeat 3 -o captures/train_v2_manifest.json
# held-out test capture: 9 clients x 5 runs + unknown client + 2 kinds of Chrome impersonation
python -m tlsfp live -i "Wi-Fi 3" -f "tcp port 443" -w captures/test_v2_raw.pcap -t 330 --no-record
python scripts/gen_traffic.py --repeat 5 -o captures/test_v2_manifest.json `
    --spoof-ja3 "<Chrome ja3_full>" --spoof-ja4r "<Chrome ja4_r>" --spoof-label "SPOOF: raw client impersonating Chrome" `
    --unknown-python C:\Python314\python.exe
# remove unrelated background traffic before sharing
python scripts/filter_pcap.py captures/test_v2_raw.pcap captures/test_v2.pcap wikipedia.org wikimedia.org
```
`gen_traffic.py` runs each client as its own process, one at a time, and records its
`[start, end]` window. Browsers run headless with a fresh profile and QUIC/HTTP3 disabled, so they
use TCP. Ground truth = the ClientHellos to `www.wikipedia.org` inside a client's window.
The live demo also shows OS-level ground truth (`--resolve-process`, owning process via psutil).

## Results (Windows 11; Chrome 156, Edge 156, Firefox 144, curl 8.21/Schannel, Python 3.13/OpenSSL 3.0)

Full tables: [`results/SUMMARY.md`](results/SUMMARY.md). Charts: `results/chart_*.png`.

### 1. Extractor validation

| Reference | JA3 | JA3S | JA4 | JA4S |
|---|---|---|---|---|
| Published string→hash examples (Salesforce) | 2/2 | 1/1, explained¹ | | |
| FoxIO published expected output, 10 FoxIO pcaps | | | 135/136, 1 explained² | 76/76 |
| Published Chrome JA4 (FoxIO README) vs our live Chrome | | | identical: `t13d1517h2_8daaf6152771_cb7bf5808d99` | |
| Wireshark 4.6.7, train + test captures | 225/225 | 202/202 | 225/225 (95 exact + 130 equal after removing tshark's GREASE sigalg³) | (not in Wireshark) |

1. The published JA3S example hash is MD5 of the string **plus a newline** (`echo` without `-n`).
   MD5 of the string itself is what the spec, and `tlsfp`, compute.
2. A non-ASCII ALPN (`0xBA 0xAD`): FoxIO's written spec says print the hex characters (`bd`, which
   `tlsfp` does), while FoxIO's Rust and Python code print `99`. The spec and FoxIO's own code disagree.
3. Chrome/Edge put a GREASE value inside `signature_algorithms`. The JA4 spec says GREASE is ignored,
   and FoxIO's expected output for `sigalg-grease.pcapng` confirms it. Wireshark keeps it, so
   Wireshark's JA4 for Chrome changes every connection.

Testing against the FoxIO pcaps found one real bug, now fixed: IPv6 captures with a BSD/macOS
loopback link layer were not decoded.

### 2. Held-out identification (90 ClientHellos, `results/ja3_vs_ja4_comparison.csv`)

| Method | 9 known clients | Macro F1 | Unknown client → UNKNOWN | Spoofs accepted as Chrome |
|---|---|---|---|---|
| **JA4 + JA3** | **75/75 = 100%** | 0.967 | 5/5 | 10/10 |
| JA3 only | 44/75 = 58.7% (Chrome 0/12, Edge 0/19) | 0.778 | 5/5 | 5/10 (the JA3 replays) |
| JA4 only | 75/75 = 100% | 0.981 | 5/5 | 5/10 (the JA4_r replays) |

Macro F1 is below 1.0 even at 100% accuracy because the spoofed connections are counted as false
positives against the Chrome label. That is the cost of evasion.

### 3. Reference database: 9 clients

| Client | TLS stack | JA4 |
|---|---|---|
| Google Chrome 156 | BoringSSL | `t13d1517h2_8daaf6152771_cb7bf5808d99` (= FoxIO published) |
| Microsoft Edge 156 | BoringSSL | `t13d1517h2_8daaf6152771_a87ad97598a9`, `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Mozilla Firefox 144 | NSS | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` |
| curl 8.21 (Windows) | Schannel | `t13d2013h1_2b729b4bf6f3_e24568c0d440` |
| PowerShell Invoke-WebRequest | .NET → Schannel | `t13d201100_2b729b4bf6f3_36bf25f296df` |
| Python urllib | OpenSSL 3.0 | `t13d1813h1_85036bcba153_d339722ba4af` |
| Python requests | OpenSSL 3.0 | `t13d1812h1_85036bcba153_b26ce05bbdd6` |
| Custom Python script (TLS 1.2, 3 ciphers) | OpenSSL 3.0 | `t12d040700_1905ac1fb84a_e7e480e5a997` |
| Hand-crafted raw TLS client | none (hand-built bytes) | `t12d100600_ef2f9671594d_bb157cc35868` |

Plus 16 published entries with their source URL (`data/published_references.json`): Tor, Trickbot,
Emotet, IcedID, Sliver, Evilginx, Metasploit/Cobalt Strike JA3S, SoftEther and others.
**How to read JA4:** the middle part (sorted cipher hash) identifies the TLS **library**:
`8daaf6152771` is BoringSSL (Chrome, Edge), `2b729b4bf6f3` is Schannel (curl, PowerShell, and
also the published IcedID malware), `85036bcba153` is OpenSSL 3.0's default cipher list (urllib,
requests). The custom script restricts its ciphers, so it has a different cipher hash although it
also uses OpenSSL. The first part (version, counts, ALPN) and the extension hash separate
**applications** built on the same library.
All 9 JA4 entries (8 clients; Edge has 2) from the first capture (`data/reference_db_v1.json`,
2026-11-05) reappeared unchanged in the re-capture a few hours later (2026-11-06). That shows
repeatability on one machine, not long-term stability.

### 4. Fingerprint stability (`results/fingerprint_stability.csv`)

| Client | Connections | Distinct JA3 | Distinct JA4 |
|---|---|---|---|
| Google Chrome | 19 | **19** | 1 |
| Microsoft Edge | 31 | **31** | 2 (with / without session-resumption extension) |
| Mozilla Firefox | 21 | 1 | 1 |
| Every non-browser client | 5–8 each | 1 | 1 |

Chrome (since v110) and Edge **shuffle the order of their TLS extensions** on every connection.
JA3 hashes extensions in wire order, so every Chrome connection gets a new JA3. JA4 sorts
extensions before hashing, which removes the shuffling. Firefox does not shuffle.

### 5. Server side (`results/server_fingerprint_results.csv`)

* JA3S/JA4S fingerprint the server's *answer to a particular client*. The same `www.wikipedia.org`
  produced three different JA4S values in `test_v2.pcap`:

  | JA4S | Extensions in the reply | Client that received it |
  |---|---|---|
  | `t130200_1301_a56c5b993250` | `002b,0033` | Chrome, Edge, Firefox, PowerShell, Python (TLS 1.3 clients) |
  | `t120500_c02c_45145cc9ca06` | `ff01,0000,000b,0023,0017` (TLS 1.2) | the TLS 1.2-only custom script |
  | `t130300_1301_0ee26285a86f` | `002b,0033,0029` | Edge resuming a session (`0029` = pre_shared_key) |

* The JA4S that FoxIO publishes for the **Sliver C2 server** (`t130200_1301_a56c5b993250`) contains
  only the two mandatory TLS 1.3 extensions (`002b` supported_versions, `0033` key_share). In our
  committed captures it is sent by `www.wikipedia.org`, `en.wikipedia.org` and `upload.wikimedia.org`,
  and in `captures/test.pcap` also by Microsoft and Google hosts. SoftEther VPN's published JA4S
  (`t130200_1302_a56c5b993250`) is sent by `www.bing.com` and several `office.com` hosts in
  `captures/test.pcap`. These are generic TLS 1.3 responses, so **a JA4S match alone is not evidence
  of C2**. The CLI therefore prints server matches as "matches published JA4S of …", a hint rather than an identification.

### 6. Performance (`results/performance_results.csv`, one core, Python)

Two runs on the same laptop (timings vary about 2× with machine load):

| Measurement | Range over 2 runs |
|---|---|
| ClientHello parse | 50–97 µs |
| JA3 + JA4 computation | 62–103 µs |
| JA3S + JA4S computation | 9–22 µs |
| DB lookup + identify (SQLite) | 4–31 µs |
| Offline pipeline incl. Scapy decoding | 1,900–3,400 packets/s |

Even at the slow end, fingerprinting handles several thousand hellos per second on one core.
The measured Scapy pipeline is limited by packet decoding, not fingerprint computation. The optional
Linux XDP source is provided separately; measure it on the target NIC before making performance claims.
`results/performance_results.csv` holds the latest run.

## Security monitoring: what fingerprinting is good for

* **Malware/C2 detection.** Implants often use a TLS stack their host OS wouldn't use, or
  hard-coded cipher lists. Published JA3/JA4 values for Trickbot, Emotet, IcedID, Sliver and others are in
  the DB with their source. Load the (historic, last updated 2021) abuse.ch list with
  `python -m tlsfp db import-sslbl ja3_fingerprints.csv`. Detection works on any port, so C2 on unusual ports is also covered.
* **User-Agent mismatch.** A request claiming `User-Agent: Chrome` whose handshake is
  Python/OpenSSL is a bot or scraper. This works without decryption, at the network edge.
* **Asset inventory and policy.** Find unmanaged clients, old TLS 1.2-only libraries, or a
  `curl.exe` running on servers that should never use it.
* **Triage, not verdicts.** `report` lists the most frequent unknown fingerprints (candidates to
  label), conflicts and malware-list hits, with the provenance of each reference entry.

## Limitations and evasion

1. **Fingerprints identify the TLS library and its configuration, not the application.** Chrome and Edge
   share BoringSSL: same ciphers and signature algorithms, and Edge's first-connection hello is Chrome's
   minus a single extension (`ca34`). A Python implant has the same fingerprint as
   `requests`. The published IcedID JA4 shares its cipher hash with curl and PowerShell (Windows Schannel).
2. **Extension-order randomisation** (Chrome 110+, Edge) breaks JA3 for browsers: Chrome 0/12 and
   Edge 0/19 held-out connections identified with JA3 alone (shown above). JA4 fixes this, but only because it sorts. Any client that changes the
   *set* of ciphers or extensions changes its JA4 too.
3. **Spoofing is easy.** `scripts/custom_tls_client.py` reproduced Chrome's JA3 or JA4 from a short
   script, and Wikipedia's real server answered all 10 spoofed hellos with a ServerHello. Tools such as uTLS, curl-impersonate and tls-client do this for
   full connections. One weak signal remained in our test: all 5 JA3 replays were `ja3_only`
   (their JA4 is unknown), while all 12 genuine Chrome connections were `ja4_only`. A JA4_r replay
   leaves no such signal. Fingerprints are evidence, not proof of identity.
4. **Collisions and false positives.** Benign and malicious software share libraries. Server
   fingerprints are especially generic (the Sliver/Wikipedia case above). Published attributions also
   conflict: JA3 `4d7a28d6…` is "Emotet" in the Salesforce README but "Tofsee" in abuse.ch SSLBL.
5. **Drift.** Fingerprints change with releases (e.g. post-quantum `X25519MLKEM768` = group `4588`,
   ECH = `fe0d`), so the DB needs maintenance. Python 3.13 and 3.14 already differ.
6. **Visibility.** QUIC/HTTP3 (UDP) isn't covered here. Its hello is inside encrypted QUIC Initial packets,
   which is why the browsers ran with QUIC disabled. ECH hides the inner hello's SNI, but the outer
   hello is still fingerprintable.

## Layout

```
tlsfp/tls_parser.py      ClientHello/ServerHello parser, GREASE detection
tlsfp/fingerprints.py    JA3, JA3S, JA4, JA4S
tlsfp/flows.py           TCP reassembly + ClientHello/ServerHello session pairing
tlsfp/capture.py         Scapy live/pcap sources, psutil process attribution
tlsfp/db.py              SQLite reference DB, identification statuses, observations, importers, Redis mirror
tlsfp/reference.py       validation against published references (FoxIO pcaps, Salesforce vectors)
tlsfp/validate.py        Wireshark/tshark cross-check
tlsfp/xdp_capture.py     optional Linux XDP/BCC packet source
tlsfp/builder.py         ClientHello builder (custom client, spoofing, tests)
tlsfp/cli.py             CLI
scripts/gen_traffic.py   labelled traffic from 9 real clients (+ spoof / unknown) + manifest
scripts/custom_tls_client.py   hand-crafted client / JA3 & JA4 impersonation
scripts/filter_pcap.py   keep only the experiment's connections in a capture
experiments/run_experiments.py   regenerates everything in results/
demo/run_demo.ps1        professor demonstration
data/reference_db.json   curated reference DB (learned + published); reference_db_v1.json = first capture
data/published_references.json   published fingerprints and test vectors, with source URLs
captures/                train_v2 / test_v2 captures + manifests (test.pcap = first capture)
tests/                   parser, fingerprint, identification, Redis integration, and XDP tests
benchmarks/trex/          synthetic ClientHello TRex profile and benchmark runner
docs/                     architecture and Linux XDP/TRex setup notes
```

