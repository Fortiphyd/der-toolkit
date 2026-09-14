#!/usr/bin/env python3
"""Start every demo device at once, simulating a small DER deployment
spanning all three protocols, for the "full pipeline against a simulated
DER cluster" demonstration.

    python3 demo/run_cluster.py

Prints a table of what's running and where, then blocks until Ctrl-C,
terminating every child process on exit.

Requires the SEP2 server's PKI to already exist -- run
demo/sep2_server/setup.sh once first.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEMO_DIR.parent

# (label, protocol, port, argv)
DEVICES = [
    ("Classic PV inverter",         "sunspec", 5601,
     [sys.executable, str(DEMO_DIR / "sunspec_devices" / "classic_inverter.py"), "5601"]),
    ("DER-compliant inverter",      "sunspec", 5602,
     [sys.executable, str(DEMO_DIR / "sunspec_devices" / "der_compliant_inverter.py"), "5602"]),
    ("Telemetry/storage device",    "sunspec", 5603,
     [sys.executable, str(DEMO_DIR / "sunspec_devices" / "telemetry_storage_device.py"), "5603"]),
    ("Protection relay",            "dnp3",    21000,
     [sys.executable, str(DEMO_DIR / "dnp3_outstations" / "protection_relay.py"), "21000"]),
    ("Setpoint controller",         "dnp3",    21001,
     [sys.executable, str(DEMO_DIR / "dnp3_outstations" / "setpoint_controller.py"), "21001"]),
    ("SEP2 server (hardened)",      "sep2",    18443,
     [sys.executable, "server.py", "--config", "configs/hardened.yaml"]),
    ("SEP2 server (vulnerable)",    "sep2",    18444,
     [sys.executable, "server.py", "--config", "configs/vulnerable.yaml"]),
]


def main() -> None:
    certs_dir = DEMO_DIR / "sep2_server" / "certs"
    if not certs_dir.exists():
        print("error: demo/sep2_server/certs/ not found -- run demo/sep2_server/setup.sh first",
              file=sys.stderr)
        sys.exit(1)

    procs = []
    for label, protocol, port, argv in DEVICES:
        cwd = str(DEMO_DIR / "sep2_server") if protocol == "sep2" else str(REPO_ROOT)
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(proc)
        print(f"  [{protocol:8s}] 127.0.0.1:{port:<6d} {label}")

    time.sleep(1.5)
    alive = [p.poll() is None for p in procs]
    if not all(alive):
        print("\nerror: one or more devices failed to start (see individual scripts for details)",
              file=sys.stderr)
        for p in procs:
            if p.poll() is not None:
                p.terminate()
        sys.exit(1)

    print(f"\nAll {len(procs)} devices running. Ctrl-C to stop the cluster.\n")
    print("Example: map every device, then merge into one cross-protocol report:\n")
    for label, protocol, port, _ in DEVICES:
        if protocol == "sep2":
            print(f"  der-sep2 map 127.0.0.1 --port {port} "
                  f"--client-cert demo/sep2_server/certs/client_registered.crt "
                  f"--client-key demo/sep2_server/certs/client_registered.key "
                  f"--ca-bundle demo/sep2_server/certs/ca.crt "
                  f"--output /tmp/{port}.json")
        else:
            cli = "der-sunspec" if protocol == "sunspec" else "der-dnp3"
            print(f"  {cli} map 127.0.0.1 --port {port} --output /tmp/{port}.json")
    print("\n  der-report /tmp/*.json\n")

    def _shutdown(sig, frame):
        print("\nStopping cluster...")
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=5)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.pause()


if __name__ == "__main__":
    main()
