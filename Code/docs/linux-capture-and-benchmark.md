# Linux XDP capture and TRex benchmark

These are optional Linux-only extensions. The normal Scapy/pcap workflow remains
the default and continues to work on Windows.

## XDP packet capture

Install Linux prerequisites (package names vary by distribution):

```sh
sudo apt install python3-bpfcc libbpfcc-dev python3-venv clang llvm
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -r requirements.txt
```

Run with root/CAP_BPF/CAP_NET_ADMIN privileges and use the Linux interface name:

```sh
sudo .venv/bin/python -m tlsfp --db tlsfp.db live --backend xdp -i eth0 \
  --timeout 60 --show-server -w captures/xdp-live.pcap
```

The BCC XDP program copies TCP frames into a perf buffer and returns `XDP_PASS`, so
it does not drop or rewrite traffic. The existing Python reassembler and fingerprint
pipeline process those frames. It supports Ethernet, one VLAN tag, IPv4, IPv6 without
extension headers, and TCP frames up to 2048 bytes. IP-fragmented traffic, IPv6
extension-header chains, and oversized frames are not exported by this first version.
Custom BPF filters are Scapy-only.

XDP attaches to the selected interface in generic/SKB mode. Do not run competing
capture programs on the same interface without checking XDP attachment ownership.
The final stderr line reports packets delivered through the perf buffer; any reported
perf-buffer loss means the observed capture is incomplete.

## TRex packet-rate benchmark

Use an isolated Linux test network and a TRex server. Connect a TRex transmit port
to the sensor's capture interface (or a mirrored/SPAN destination). The profile emits
synthetic ClientHello packets to a documentation-only IP address; it does not perform
a TCP handshake or complete TLS. Do not route it onto a production network.

On the TRex host, install the project dependencies and make the TRex STL Python API
available. Start the TRex server using its normal platform configuration, then run:

```sh
sudo .venv/bin/python -m tlsfp --db tlsfp.db live --backend xdp -i eth1 --timeout 35
.venv/bin/python benchmarks/trex/run_benchmark.py --server 127.0.0.1 \
  --port 0 --duration 30 --mult 100%
```

The TRex runner prints offered packet/byte counters. Compare those with the XDP
sensor's delivered-frame count and reported perf-buffer losses. Repeat at increasing
rates and record NIC, driver, kernel, TRex version, port speed, and rate. A run with
loss is a measured capacity limit, not a successful lossless capture result. Run the
TRex client and sensor in separate terminals; `--iface` must name the sensor-side
interface, not the TRex management interface.
