# Architecture and requirement coverage

## Data path

```text
Scapy/Npcap or Linux XDP
        |
        v
Ethernet/IP/TCP decode -> TCP reassembly -> TLS Hello parsing
        |                        tlsfp/capture.py      tlsfp/flows.py
        v
JA3/JA3S + JA4/JA4S -> reference lookup -> verdict / observation
tlsfp/fingerprints.py             tlsfp/db.py
```

Both capture backends feed the same `FlowTracker` and `Pipeline`; fingerprinting,
database matching, and output are shared. XDP is an optional Linux packet source.
The TRex profile generates synthetic ClientHello-bearing TCP packets for an
isolated capture benchmark; it is not a real TLS client or server session.

## Problem statement checklist

| Requirement | Implementation / validation |
|---|---|
| Passively observe ClientHello and ServerHello | Scapy live capture, offline pcap/pcapng, and optional Linux XDP |
| Compute JA3/JA3S | `tlsfp/fingerprints.py`; published vectors and tests |
| JA4/JA4S stretch goal | `tlsfp/fingerprints.py`; FoxIO reference capture tests |
| Identify at least five client tools | Curated references and held-out evaluation in `data/` and `results/` |
| Compare curl, browsers, and custom clients | Capture manifests, traffic generator, and demo script |
| Explain security value and limitations | Main README: monitoring use cases, randomization, spoofing, and false positives |
| High-rate packet generation / optional acceleration | `benchmarks/trex/` and `tlsfp/xdp_capture.py` (Linux-only) |
| Shared Redis/Valkey lookup | SQLite-to-Redis/Valkey sync plus opt-in integration test |

## Repository map

- `tlsfp/`: parser, fingerprint algorithms, capture backends, database, and CLI.
- `tests/`: unit/reference tests; `tests/fixtures/foxio/` contains independent fixtures.
- `data/`: curated and published fingerprint references.
- `captures/`: committed capture pcaps and their label manifests.
- `scripts/`, `experiments/`, `results/`: traffic generation, reproducible evaluation, and outputs.
- `demo/`: instructor-facing Windows PowerShell walkthrough.
- `benchmarks/trex/`: optional TRex STL profile and benchmark runner.
- `docs/`: architecture and platform-specific setup.

## Validation notes

The default test suite covers the platform-independent parser and fingerprint logic.
Redis/Valkey integration is opt-in because it needs a running service. XDP and TRex
need Linux and compatible NIC/test hardware; their actual packet-path results must be
measured on that host and must not be inferred from Windows unit tests.
