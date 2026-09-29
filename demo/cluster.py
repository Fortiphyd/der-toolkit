"""Shared device list and start/stop helpers for the demo cluster -- used by
both run_cluster.py (interactive) and tests/test_demo_cluster.py (the
automated smoke test that protects the demo from silently rotting as
der_dnp3/der_sunspec/der_sep2 change).

Each device gets its own address (127.0.10.0/24 for SunSpec, 127.0.20.0/24
for DNP3, 127.0.30.0/24 for SEP2 -- all still loopback, no network setup
needed, see demo/README.md) and the real standard port for its protocol:
Modbus/TCP 502, DNP3 20000, IEEE 2030.5 15388. Port 502 is privileged, so
the SunSpec devices run under authbind -- see ensure_authbind() below.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEMO_DIR.parent

AUTHBIND_PORT = 502


def _authbind(argv: list[str]) -> list[str]:
    return ["authbind", "--deep", *argv]


# (label, protocol, host, port, argv)
DEVICES = [
    ("Classic PV inverter",         "sunspec", "127.0.10.1", 502,
     _authbind([sys.executable, str(DEMO_DIR / "sunspec_devices" / "classic_inverter.py"),
                "127.0.10.1", "502"])),
    ("DER-compliant inverter",      "sunspec", "127.0.10.2", 502,
     _authbind([sys.executable, str(DEMO_DIR / "sunspec_devices" / "der_compliant_inverter.py"),
                "127.0.10.2", "502"])),
    ("Telemetry/storage device",    "sunspec", "127.0.10.3", 502,
     _authbind([sys.executable, str(DEMO_DIR / "sunspec_devices" / "telemetry_storage_device.py"),
                "127.0.10.3", "502"])),
    ("Protection relay",            "dnp3",    "127.0.20.1", 20000,
     [sys.executable, str(DEMO_DIR / "dnp3_outstations" / "protection_relay.py"),
      "127.0.20.1", "20000"]),
    ("Setpoint controller",         "dnp3",    "127.0.20.2", 20000,
     [sys.executable, str(DEMO_DIR / "dnp3_outstations" / "setpoint_controller.py"),
      "127.0.20.2", "20000"]),
    ("SEP2 server (hardened)",      "sep2",    "127.0.30.1", 15388,
     [sys.executable, "server.py", "--config", "configs/hardened.yaml"]),
    ("SEP2 server (vulnerable)",    "sep2",    "127.0.30.2", 15388,
     [sys.executable, "server.py", "--config", "configs/vulnerable.yaml"]),
]

# Two more devices, deliberately NOT part of DEVICES above: small,
# hand-written, intentionally vulnerable fuzzing targets (see
# demo/dnp3_outstations/vulnerable_outstation.py and
# demo/sunspec_devices/vulnerable_device.py) -- even a plain, read-only
# `map` crashes them (a mapper's ordinary base-address probing is enough),
# so they're excluded from the "map everything + der-report" flow and
# from tests/test_demo_cluster.py's DEVICES-based assertions. run_cluster.py
# still starts them alongside DEVICES so one recording can show mapping
# and fuzzing together; use FUZZING_EXAMPLES (demo/README.md) to drive them.
FUZZ_TARGETS = [
    ("DNP3 fuzzing target (vulnerable)",    "dnp3",    "127.0.20.3", 20000,
     [sys.executable, str(DEMO_DIR / "dnp3_outstations" / "vulnerable_outstation.py"),
      "127.0.20.3", "20000"]),
    ("SunSpec fuzzing target (vulnerable)", "sunspec", "127.0.10.4", 502,
     _authbind([sys.executable, str(DEMO_DIR / "sunspec_devices" / "vulnerable_device.py"),
                "127.0.10.4", "502"])),
]

SEP2_CERTS_DIR = DEMO_DIR / "sep2_server" / "certs"
AUTHBIND_BYPORT = Path(f"/etc/authbind/byport/{AUTHBIND_PORT}")


def ensure_sep2_certs() -> None:
    """Generate the SEP2 test PKI if it doesn't exist yet (setup.sh is
    idempotent -- gen_certs.sh always overwrites, and the LFDI patch step
    matches whatever's currently in certs/)."""
    if not SEP2_CERTS_DIR.exists():
        subprocess.run([str(DEMO_DIR / "sep2_server" / "setup.sh")], check=True)


def ensure_authbind() -> None:
    """The SunSpec devices bind the real Modbus port (502), which is
    privileged -- fail fast with an actionable message instead of a bare
    'device failed to start' if authbind isn't set up. This can't be done
    for the user automatically: it's a one-time root/sudo step. See
    demo/README.md."""
    if shutil.which("authbind") is None:
        raise RuntimeError(
            "authbind not found -- port 502 (Modbus) needs it to bind as a "
            "non-root user. One-time setup:\n"
            "  sudo apt-get install -y authbind\n"
            "  sudo touch /etc/authbind/byport/502\n"
            "  sudo chmod 500 /etc/authbind/byport/502\n"
            "  sudo chown $USER /etc/authbind/byport/502"
        )
    if not AUTHBIND_BYPORT.exists():
        raise RuntimeError(
            f"{AUTHBIND_BYPORT} not found -- port 502 isn't authorized for this "
            "user yet. One-time setup:\n"
            "  sudo touch /etc/authbind/byport/502\n"
            "  sudo chmod 500 /etc/authbind/byport/502\n"
            "  sudo chown $USER /etc/authbind/byport/502"
        )


def start_all(devices=DEVICES) -> list[subprocess.Popen]:
    """Start every device, wait briefly, and return the live processes.
    Raises RuntimeError (after cleaning up whatever did start) if any
    device fails to come up -- most commonly a port already in use."""
    ensure_authbind()
    procs = []
    for _label, protocol, _host, _port, argv in devices:
        cwd = str(DEMO_DIR / "sep2_server") if protocol == "sep2" else str(REPO_ROOT)
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(proc)

    time.sleep(1.5)
    dead = [(label, host, port) for (label, _p, host, port, _a), p in zip(devices, procs)
            if p.poll() is not None]
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
