#!/usr/bin/env python3
"""Modern DER-compliant inverter: Common (1) + single-phase inverter
telemetry (101) + DER AC Controls (704) -- the richer, newer writable
surface this session added field-level decode for: active/reactive power
setpoints, power-factor injection/absorption, and AntiIslEna (anti-
islanding enable) sitting right next to the power controls. Deliberately
contrasted against classic_inverter.py's older, narrower control set.

    python3 demo/sunspec_devices/der_compliant_inverter.py [port]   # default 5602
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import build_device_registers, serve

DEFAULT_PORT = 5602


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    registers = build_device_registers([
        (1, {
            "Mn": "Volt Dynamics", "Md": "VD-DER1547 Grid-Forming Inverter",
            "Vr": "4.1.0", "SN": "VD-DER-0042", "DA": 2,
        }),
        (101, {
            "A": 1800, "A_SF": -1,
            "PhVphA": 2405, "V_SF": -1,
            "W": 4100, "W_SF": 1,
            "Hz": 5998, "Hz_SF": -2,
            "TmpCab": 38,
            "St": 4,
        }),
        (704, {
            "PFWInjEna": 1, "PFWAbsEna": 1,
            "WMaxLimPctEna": 1, "WMaxLimPct": 8000, "WMaxLimPct_SF": -2,
            "WSetEna": 1, "WSetMod": 0, "WSet": -1500, "WSetPct": 75,
            "VarSetEna": 1, "VarSetMod": 0, "VarSet": 500,
            "WRmp": 10, "VarRmp": 10,
            "AntiIslEna": 1,
            "PF_SF": -3, "WSet_SF": 0, "WSetPct_SF": -2,
            "VarSet_SF": 0, "VarSetPct_SF": -2,
        }),
    ])
    serve(registers, port, "DER-compliant inverter (Volt Dynamics VD-DER1547)")


if __name__ == "__main__":
    main()
