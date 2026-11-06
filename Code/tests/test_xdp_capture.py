import sys

import pytest

from tlsfp.cli import build_parser
from tlsfp.xdp_capture import sniff_xdp


def test_live_capture_defaults_to_scapy():
    args = build_parser().parse_args(["live"])
    assert args.backend == "scapy"


def test_live_capture_accepts_xdp_backend():
    args = build_parser().parse_args(["live", "--backend", "xdp", "-i", "eth0"])
    assert args.backend == "xdp"


@pytest.mark.skipif(sys.platform == "linux", reason="Linux is the supported XDP platform")
def test_xdp_backend_fails_clearly_off_linux():
    with pytest.raises(RuntimeError, match="Linux-only"):
        sniff_xdp(lambda _event: None, iface="not-a-real-interface")
