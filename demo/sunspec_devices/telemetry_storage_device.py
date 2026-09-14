#!/usr/bin/env python3
"""Telemetry/storage-adjacent device: Common (1) + environmental sensors
(Irradiance 302, Back-of-Module Temp 303, Base Met weather station 307) +
DER Capacity Status (715) -- mostly read-only telemetry, contrasted against
the two inverters' power-setpoint-heavy surfaces. Model 715 is the one
exception: a small but genuinely dangerous operational control (OpCtl --
"Set Operation", plus a heartbeat/alarm-reset pair) rather than a power
setpoint, showing that "writable" doesn't always mean "power limit."

    python3 demo/sunspec_devices/telemetry_storage_device.py [port]   # default 5603
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import build_device_registers, serve

DEFAULT_PORT = 5603


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    registers = build_device_registers([
        (1, {
            "Mn": "Fieldpoint Sensors", "Md": "FP-WX200 Met Station + BESS Controller",
            "Vr": "1.2", "SN": "FP-WX-7781", "DA": 3,
        }),
        (302, {"GHI": 812, "POAI": 790, "DFI": 120, "DNI": 690, "OTI": 4}),
        (303, {"TmpBOM": 46}),
        (307, {
            "TmpAmb": 28, "RH": 41, "Pres": 1013,
            "WndSpd": 34, "WndDir": 210, "Rain": 0, "Snw": 0,
        }),
        (715, {
            "LocRemCtl": 1, "DERHb": 8_640_000,
            "ControllerHb": 8_640_000, "AlarmReset": 0, "OpCtl": 1,
        }),
    ])
    serve(registers, port, "Telemetry/storage device (Fieldpoint FP-WX200)")


if __name__ == "__main__":
    main()
