"""Run the TLS hello profile and print TRex packet counters as JSON."""
from __future__ import annotations

import argparse
import json

from trex.stl.api import STLClient, STLProfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="TRex server management IP")
    parser.add_argument("--port", type=int, default=0, help="TRex data port index")
    parser.add_argument("--duration", type=float, default=30, help="test duration in seconds")
    parser.add_argument("--mult", default="100%", help="TRex rate, e.g. 100%, 100kpps")
    parser.add_argument("--profile", default="benchmarks/trex/tls_hello_profile.py")
    args = parser.parse_args()

    client = STLClient(server=args.server)
    started = False
    try:
        client.connect()
        client.reset(ports=[args.port])
        profile = STLProfile.load_py(args.profile)
        client.add_streams(profile.get_streams(), ports=[args.port])
        client.start(ports=[args.port], mult=args.mult, duration=args.duration)
        started = True
        client.wait_on_traffic(ports=[args.port])
        print(json.dumps({
            "port": args.port,
            "duration_seconds": args.duration,
            "requested_rate": args.mult,
            "stats": client.get_stats()[args.port],
        }, indent=2, default=str))
    finally:
        if started:
            client.stop(ports=[args.port])
        client.disconnect()


if __name__ == "__main__":
    main()
