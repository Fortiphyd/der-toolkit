#!/usr/bin/env python3
"""Classic PV inverter: Common (1) + three-phase inverter telemetry (103) +
Immediate Controls (123) -- the textbook SunSpec writable surface this
toolkit has sampled from the start: WMaxLimPct power limiting, a fixed
power-factor setpoint, VAR limiting.

    python3 demo/sunspec_devices/classic_inverter.py [host] [port]
    # default 127.0.10.1:502 -- port 502 needs authbind, see demo/README.md
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import build_device_registers, serve

DEFAULT_HOST = "127.0.10.1"
DEFAULT_PORT = 502


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    registers = build_device_registers([
        (1, {
            "Mn": "Acme Solar", "Md": "AS-3000 String Inverter", "Vr": "2.4",
            "SN": "ACME-INV-0001", "DA": 1,
        }),
        (103, {
            "A": 4200, "A_SF": -1,
            "PhVphA": 2401, "PhVphB": 2402, "PhVphC": 2400, "V_SF": -1,
            "W": 9500, "W_SF": 1,
            "Hz": 6000, "Hz_SF": -2,
            "TmpCab": 42, "Tmp_SF": 0,
            "St": 4,  # MPPT
        }),
        (123, {
            "WMaxLimPct": 10000, "WMaxLimPct_SF": -2, "WMaxLim_Ena": 1,
            "OutPFSet": 10000, "OutPFSet_SF": -4, "OutPFSet_Ena": 0,
            "VArPct_Ena": 0, "VArPct_SF": -2,
        }),
    ])
    serve(registers, host, port, "Classic PV inverter (Acme Solar AS-3000)")


if __name__ == "__main__":
    main()
