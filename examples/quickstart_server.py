#!/usr/bin/env python3
"""A minimal SunSpec/Modbus device simulator for the README quickstart.

Requires only pymodbus (already part of der-toolkit's 'sunspec' extra) --
no separate simulator tool or compiled binary needed. Serves the "SunS"
marker + a single Common (model 1) block at holding register 0, matching
examples/quickstart_device.model's field values, then the end-of-model
marker. der-sunspec's SUNSPEC_BASE_CANDIDATES tries base 0 after 40000 and
50000, so this is found the same way a real device at any of those bases
would be.

    python3 examples/quickstart_server.py [port]   # default port 5503
"""

from __future__ import annotations

import sys

from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartTcpServer


def _encode_string(s: str, num_regs: int) -> list[int]:
    b = (s.encode("ascii") + b"\x00" * (num_regs * 2))[: num_regs * 2]
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)]


def build_registers() -> list[int]:
    regs: list[int] = []
    regs += [0x5375, 0x6E53]                      # "SunS" marker
    regs += [1, 66]                                # model 1 header: ID, length
    regs += _encode_string("DER Toolkit", 16)      # Mn
    regs += _encode_string("Quickstart Simulator", 16)  # Md
    regs += _encode_string("", 8)                  # Opt
    regs += _encode_string("1.0", 8)                # Vr
    regs += _encode_string("DEMO0001", 16)          # SN
    regs += [42, 0xFFFF]                            # DA (writable), pad
    regs += [0xFFFF, 0]                             # end-of-model marker
    return regs


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5503
    registers = build_registers()
    # pymodbus's ModbusDeviceContext.getValues/setValues always add 1 to the
    # requested protocol address before indexing into the store (there is no
    # zero_mode toggle in pymodbus 3.x) -- start the block at 1 so protocol
    # address 0 maps to registers[0], matching where der_sunspec's mapper
    # looks for the "SunS" marker.
    block = ModbusSequentialDataBlock(1, registers)
    device_ctx = ModbusDeviceContext(hr=block)
    context = ModbusServerContext(devices=device_ctx, single=True)
    print(f"Quickstart SunSpec simulator on 127.0.0.1:{port} -- Ctrl-C to stop", flush=True)
    StartTcpServer(context=context, address=("127.0.0.1", port))


if __name__ == "__main__":
    main()
