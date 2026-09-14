#!/usr/bin/env python3
"""Protection-relay style outstation: binary I/O only. Exposes Binary Input
status (g1v2, read-only breaker feedback), Binary Output status (g10v2 --
implies g12 CROB commands are operable per der_dnp3.adapter's _WRITABLE
logic, the classic "flip a breaker" finding), and a couple of read-only
analog inputs (g30v1). No analog output at all -- contrast against
setpoint_controller.py's analog-only actuation surface.

    python3 demo/dnp3_outstations/protection_relay.py [port]   # default 21000, outstation addr 10
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Group, Outstation

DEFAULT_PORT = 21000
OUTSTATION_ADDR = 10


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    outstation = Outstation(
        name="Protection relay (breaker-style CROB)",
        outstation_addr=OUTSTATION_ADDR,
        groups=[
            Group(group=1, variation=2, count=4, point_size=1),   # Binary Input status
            Group(group=10, variation=2, count=4, point_size=1),  # Binary Output status (-> g12 CROB operable)
            Group(group=30, variation=1, count=2, point_size=5),  # Analog Input (line current/voltage)
        ],
    )
    outstation.serve(port)


if __name__ == "__main__":
    main()
