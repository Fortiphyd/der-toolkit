#!/usr/bin/env python3
"""Start every demo device at once -- the 7-device mapping cluster plus the
2 intentionally-vulnerable fuzzing targets -- so one recording can show
mapping, cross-protocol reporting, and fuzzing without restarting anything
in between.

    python3 demo/run_cluster.py

Prints a table of what's running and where, then blocks until Ctrl-C,
terminating every child process on exit.

Requires the SEP2 server's PKI to already exist (run
demo/sep2_server/setup.sh once first) and authbind set up for port 502
(see demo/README.md) -- port 502 is privileged, and four of the nine
devices need it (the three "real" SunSpec inverters, plus the SunSpec
fuzzing target).
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cluster import DEVICES, FUZZ_TARGETS, SEP2_CERTS_DIR, start_all, stop_all

ALL_DEVICES = DEVICES + FUZZ_TARGETS


def main() -> None:
    if not SEP2_CERTS_DIR.exists():
        print("error: demo/sep2_server/certs/ not found -- run demo/sep2_server/setup.sh first",
              file=sys.stderr)
        sys.exit(1)

    for label, protocol, host, port, _argv in ALL_DEVICES:
        print(f"  [{protocol:8s}] {host}:{port:<6d} {label}")

    try:
        procs = start_all(devices=ALL_DEVICES)
    except RuntimeError as e:
        print(f"\nerror: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nAll {len(procs)} devices running. Ctrl-C to stop the cluster.\n")
    print("Example: map the 7 mapping-cluster devices, then merge into one")
    print("cross-protocol report (the 2 fuzzing targets are excluded here --")
    print("even a plain map crashes them, see demo/README.md):\n")
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
    print("Fuzzing examples (SEP2 vulnerable server, and the 2 dedicated")
    print("fuzzing targets) are in demo/README.md's Fuzzing section.\n")

    def _shutdown(sig, frame):
        print("\nStopping cluster...")
        stop_all(procs)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.pause()


if __name__ == "__main__":
    main()
