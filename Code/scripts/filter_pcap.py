"""Keep only the TCP connections whose ClientHello SNI ends with one of the given domains.

Used to strip unrelated background traffic (the capturing user's own browsing) out of
experiment captures before they are shared or committed.

    python scripts/filter_pcap.py raw.pcap out.pcap wikipedia.org wikimedia.org
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import PcapReader, PcapWriter  # noqa: E402

from tlsfp.capture import _decode, events_from_pcap  # noqa: E402


def main() -> None:
    src, dst, *domains = sys.argv[1:]
    keep = set()
    for ev in events_from_pcap(src):
        if ev.is_client and ev.sni and any(ev.sni == d or ev.sni.endswith("." + d) for d in domains):
            a, ap, b, bp = ev.flow
            keep.add((a, ap, b, bp))
            keep.add((b, bp, a, ap))
    n = kept = 0
    with PcapReader(src) as rd, PcapWriter(dst, append=False, sync=False) as wr:
        for pkt in rd:
            n += 1
            d = _decode(pkt)
            if d is not None and d[1] in keep:
                wr.write(pkt)
                kept += 1
    print(f"{src}: kept {kept}/{n} packets from {len(keep) // 2} connections -> {dst}")


if __name__ == "__main__":
    main()
