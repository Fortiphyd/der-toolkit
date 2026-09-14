"""Shared device list and start/stop helpers for the demo cluster -- used by
both run_cluster.py (interactive) and tests/test_demo_cluster.py (the
automated smoke test that protects the demo from silently rotting as
der_dnp3/der_sunspec/der_sep2 change).
"""

from __future__ import annotations

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

SEP2_CERTS_DIR = DEMO_DIR / "sep2_server" / "certs"


def ensure_sep2_certs() -> None:
    """Generate the SEP2 test PKI if it doesn't exist yet (setup.sh is
    idempotent -- gen_certs.sh always overwrites, and the LFDI patch step
    matches whatever's currently in certs/)."""
    if not SEP2_CERTS_DIR.exists():
        subprocess.run([str(DEMO_DIR / "sep2_server" / "setup.sh")], check=True)


def start_all(devices=DEVICES) -> list[subprocess.Popen]:
    """Start every device, wait briefly, and return the live processes.
    Raises RuntimeError (after cleaning up whatever did start) if any
    device fails to come up -- most commonly a port already in use."""
    procs = []
    for _label, protocol, _port, argv in devices:
        cwd = str(DEMO_DIR / "sep2_server") if protocol == "sep2" else str(REPO_ROOT)
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(proc)

    time.sleep(1.5)
    dead = [(label, port) for (label, _p, port, _a), p in zip(devices, procs) if p.poll() is not None]
    if dead:
        stop_all(procs)
        raise RuntimeError(f"device(s) failed to start: {dead}")
    return procs


def stop_all(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
