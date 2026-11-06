"""Validation against published reference values.

1. FoxIO JA4 test suite: pcaps from https://github.com/FoxIO-LLC/ja4/tree/main/pcap with the
   expected output of FoxIO's own implementation (rust/ja4/src/snapshots/*.snap).
   We compare our JA4 / JA4S for every TCP connection in those snapshots.
2. Published string -> hash vectors and attributed hashes (data/published_references.json).
"""
from __future__ import annotations

import hashlib
import json
import os

from .capture import events_from_pcap


def parse_snapshot(path: str) -> list[dict]:
    """Minimal reader for FoxIO's insta .snap files (YAML list of connections).
    Only the top-level keys of each entry are read (2-space indent); nested certificate
    data is ignored, so no YAML dependency is needed."""
    entries: list[dict] = []
    cur: dict | None = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("- "):
                cur = {}
                entries.append(cur)
                line = "  " + line[2:]
            if cur is None or not line.startswith("  ") or line.startswith("   "):
                continue
            key, _, val = line.strip().partition(":")
            if val.strip():
                cur[key] = val.strip().strip("'\"")
    return entries


def compare_foxio(pcap: str, snap: str) -> list[dict]:
    """One row per (connection, fingerprint) that FoxIO publishes: expected vs ours."""
    expected = parse_snapshot(snap)
    ours: dict[tuple, dict] = {}
    for ev in events_from_pcap(pcap):
        src, sport, dst, dport = ev.flow
        if ev.is_client:
            ours.setdefault((src, sport, dst, dport), {})["ja4"] = ev.fp.ja4
        else:
            ours.setdefault((dst, dport, src, sport), {})["ja4s"] = ev.fp.ja4s
    rows = []
    for e in expected:
        if e.get("transport") != "tcp":
            continue                                  # QUIC is out of scope (documented)
        key = (e.get("src"), int(e.get("src_port", 0)), e.get("dst"), int(e.get("dst_port", 0)))
        for kind in ("ja4", "ja4s"):
            if kind not in e:
                continue
            got = ours.get(key, {}).get(kind, "")
            rows.append({"source": os.path.basename(pcap), "flow": f"{key[0]}:{key[1]}->{key[2]}:{key[3]}",
                         "algorithm": kind.upper(), "expected": e[kind], "ours": got,
                         "result": _classify(kind, e[kind], got)})
    return rows


def _classify(kind: str, expected: str, got: str) -> str:
    if got == expected:
        return "pass"
    # Known FoxIO spec-vs-implementation difference: for a non-ASCII ALPN byte the JA4.md
    # spec prints hex characters (0xBA 0xAD -> "bd"), while FoxIO's Rust/Python code
    # substitutes '9' ("99"). We follow the written spec; the rest must match exactly.
    if (kind == "ja4" and len(got) == len(expected) and got[:8] == expected[:8]
            and got[10:] == expected[10:] and "9" in expected[8:10]):
        return "explained: ALPN spec vs FoxIO code"
    return "FAIL"


def check_vectors(path: str) -> list[dict]:
    """Published JA3/JA3S 'string -> MD5' examples: does our hashing reproduce them?"""
    with open(path, encoding="utf-8") as f:
        refs = json.load(f)
    rows = []
    for v in refs["string_vectors"]:
        got = hashlib.md5(v["string"].encode()).hexdigest()
        if got == v["hash"]:
            result = "pass"
        elif (v.get("publisher_appended_newline")
              and hashlib.md5((v["string"] + "\n").encode()).hexdigest() == v["hash"]):
            result = "explained: publisher hashed string + newline"
        else:
            result = "FAIL"
        rows.append({"source": v["source"], "flow": v["string"], "algorithm": v["algorithm"],
                     "expected": v["hash"], "ours": got, "result": result})
    return rows
