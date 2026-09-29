#!/usr/bin/env python3
"""Start every demo device at once, simulating a small DER deployment
spanning all three protocols, for the "full pipeline against a simulated
DER cluster" demonstration.

    python3 demo/run_cluster.py

Prints a table of what's running and where, then blocks until Ctrl-C,
terminating every child process on exit.

Requires the SEP2 server's PKI to already exist (run
demo/sep2_server/setup.sh once first) and authbind set up for port 502
(see demo/README.md) -- the three SunSpec devices bind the real Modbus
port, which is privileged.
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cluster import DEVICES, SEP2_CERTS_DIR, start_all, stop_all


def main() -> None:
    if not SEP2_CERTS_DIR.exists():
        print("error: demo/sep2_server/certs/ not found -- run demo/sep2_server/setup.sh first",
              file=sys.stderr)
        sys.exit(1)

    for label, protocol, host, port, _argv in DEVICES:
        print(f"  [{protocol:8s}] {host}:{port:<6d} {label}")

    try:
        procs = start_all()
    except RuntimeError as e:
        print(f"\nerror: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nAll {len(procs)} devices running. Ctrl-C to stop the cluster.\n")
    print("Example: map every device, then merge into one cross-protocol report:\n")
    for label, protocol, host, port, _argv in DEVICES:
        if protocol == "sep2":
            print(f"  der-sep2 map {host} --port {port} "
                  f"--client-cert demo/sep2_server/certs/client_registered.crt "
                  f"--client-key demo/sep2_server/certs/client_registered.key "
                  f"--ca-bundle demo/sep2_server/certs/ca.crt "
                  f"--output /tmp/{host}.json")
        else:
            cli = "der-sunspec" if protocol == "sunspec" else "der-dnp3"
            print(f"  {cli} map {host} --port {port} --output /tmp/{host}.json")
    print("\n  der-report /tmp/127.0.*.json\n")

    def _shutdown(sig, frame):
        print("\nStopping cluster...")
        stop_all(procs)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.pause()


if __name__ == "__main__":
    main()
