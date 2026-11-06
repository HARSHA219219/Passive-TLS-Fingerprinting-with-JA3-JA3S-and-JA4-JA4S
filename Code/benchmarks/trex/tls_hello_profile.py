"""TRex STL profile that emits synthetic TCP packets carrying TLS ClientHellos."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw
from trex.stl.api import (CTRexVmInsFixHwCs, STLScVmRaw, STLPktBuilder, STLStream,
                          STLTXCont, STLVmFixChecksumHw, STLVmFlowVar,
                          STLVmWrFlowVar)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tlsfp.builder import HelloSpec, build_client_hello  # noqa: E402


class TlsHelloProfile:
    def get_streams(self, **_kwargs):
        client_hello = build_client_hello(HelloSpec(
            version=0x0303,
            ciphers=[0x1301, 0x1302, 0x1303, 0xC02F],
            extensions=[0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x002B, 0x0033],
            groups=[0x001D, 0x0017],
            point_formats=[0],
            alpn=[b"h2", b"http/1.1"],
            supported_versions=[0x0304, 0x0303],
            sni="benchmark.example",
        ))
        packet = (Ether(src=os.environ.get("TLSFP_TREX_SRC_MAC", "02:00:00:00:00:01"),
                        dst=os.environ.get("TLSFP_TREX_DST_MAC", "ff:ff:ff:ff:ff:ff"))
                  / IP(src="192.0.2.10", dst="192.0.2.20")
                  / TCP(sport=20000, dport=443, seq=1, flags="PA")
                  / Raw(load=client_hello))
        vm = STLScVmRaw([
            STLVmFlowVar(name="src_port", min_value=20000, max_value=60000,
                         size=2, op="inc"),
            STLVmWrFlowVar(fv_name="src_port", pkt_offset="TCP.sport"),
            STLVmFixChecksumHw(l3_offset="IP", l4_offset="TCP",
                               l4_type=CTRexVmInsFixHwCs.L4_TYPE_TCP),
        ])
        return [STLStream(packet=STLPktBuilder(pkt=packet, vm=vm), mode=STLTXCont())]


def register():
    return TlsHelloProfile()
