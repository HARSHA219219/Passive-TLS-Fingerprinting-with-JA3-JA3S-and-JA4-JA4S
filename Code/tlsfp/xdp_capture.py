"""Linux XDP packet source using BCC; parsed events reuse the normal TLS pipeline."""
from __future__ import annotations

import ctypes
import sys
import time
from collections.abc import Callable

from .capture import _decode
from .flows import FlowTracker, HelloEvent

_XDP_PROGRAM = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>

#define MAX_CAPTURE 2048

BPF_PERF_OUTPUT(packets);

struct vlan_header {
    __be16 tci;
    __be16 encapsulated_proto;
};

int xdp_tls_capture(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 protocol = bpf_ntohs(eth->h_proto);
    __u64 offset = sizeof(*eth);
    if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) {
        struct vlan_header *vlan = data + offset;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        protocol = bpf_ntohs(vlan->encapsulated_proto);
        offset += sizeof(*vlan);
    }

    if (protocol == ETH_P_IP) {
        struct iphdr *ip = data + offset;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5
                || ip->protocol != IPPROTO_TCP
                || (bpf_ntohs(ip->frag_off) & 0x3fff))
            return XDP_PASS;
        offset += (__u64)ip->ihl * 4;
    } else if (protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = data + offset;
        if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_TCP)
            return XDP_PASS;
        offset += sizeof(*ip6);
    } else {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + offset;
    if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
        return XDP_PASS;
    offset += (__u64)tcp->doff * 4;
    if (data + offset >= data_end)
        return XDP_PASS;

    __u32 packet_len = (__u32)(data_end - data);
    if (packet_len > MAX_CAPTURE)
        return XDP_PASS;

    packets.perf_submit(ctx, data, packet_len);
    return XDP_PASS;
}
"""


def sniff_xdp(on_event: Callable[[HelloEvent], None], iface: str | None = None,
              write_pcap: str | None = None, timeout: float | None = None,
              count: int = 0) -> None:
    """Capture TCP frames with generic XDP and feed them to the shared flow tracker.

    This backend passes packets onward and supports direct TCP over IPv4/IPv6,
    plus one VLAN tag. It does not replace or drop network traffic.
    """
    if sys.platform != "linux":
        raise RuntimeError("the XDP capture backend is Linux-only")
    if not iface:
        raise ValueError("--iface is required for the XDP capture backend")

    try:
        from bcc import BPF
    except ImportError as exc:
        raise RuntimeError(
            "BCC Python bindings are required for --backend xdp "
            "(install the distro's python3-bpfcc package)"
        ) from exc

    from scapy.all import Ether, PcapWriter

    bpf = BPF(text=_XDP_PROGRAM)
    function = bpf.load_func("xdp_tls_capture", BPF.XDP)
    attached = False
    writer = PcapWriter(write_pcap, append=False, sync=True) if write_pcap else None
    tracker = FlowTracker()
    packets_seen = 0
    lost_packets = 0
    started = time.monotonic()

    def handle_packet(_cpu, data, size):
        nonlocal packets_seen
        packet = Ether(ctypes.string_at(data, size))
        packet.time = time.time()
        packets_seen += 1
        if writer is not None:
            writer.write(packet)
        decoded = _decode(packet)
        if decoded is not None:
            event = tracker.feed(*decoded)
            if event is not None:
                on_event(event)

    def report_lost(_cpu, lost):
        nonlocal lost_packets
        lost_packets += lost
        print(f"[!] XDP perf buffer lost {lost} packets", file=sys.stderr)

    try:
        # Generic/SKB mode is the most compatible XDP mode across Linux NICs.
        bpf.attach_xdp(iface, function, flags=2)
        attached = True
        bpf["packets"].open_perf_buffer(handle_packet, lost_cb=report_lost)
        while True:
            if timeout is not None and time.monotonic() - started >= timeout:
                break
            if count and packets_seen >= count:
                break
            bpf.perf_buffer_poll(timeout=1000)
    finally:
        try:
            if attached:
                bpf.remove_xdp(iface, flags=2)
        finally:
            if writer is not None:
                writer.close()
            print(f"[XDP] TCP frames delivered to userspace: {packets_seen}; "
                  f"perf-buffer losses: {lost_packets}", file=sys.stderr)
