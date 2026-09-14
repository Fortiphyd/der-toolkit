#!/usr/bin/env python3
"""Setpoint-controller style outstation: analog I/O only. Exposes Analog
Input (g30v1, read-only measured values) and Analog Output status (g40v1
-- implies g41 Analog Output Commands are operable, the "rewrite a
setpoint" finding). No binary output/CROB at all -- contrast against
protection_relay.py's binary-switching actuation surface.

    python3 demo/dnp3_outstations/setpoint_controller.py [port]   # default 21001, outstation addr 11
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Group, Outstation

DEFAULT_PORT = 21001
OUTSTATION_ADDR = 11


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    outstation = Outstation(
        name="Setpoint controller (analog-output only)",
        outstation_addr=OUTSTATION_ADDR,
        groups=[
            Group(group=30, variation=1, count=3, point_size=5),  # Analog Input (measured values)
            Group(group=40, variation=1, count=2, point_size=5),  # Analog Output status (-> g41 operable)
        ],
    )
    outstation.serve(port)


if __name__ == "__main__":
    main()
