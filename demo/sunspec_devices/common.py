"""Shared helpers for the demo SunSpec device profiles.

Builds a full SunSpec Modbus register image (SunS marker + model chain +
end-of-model marker) from a list of (model_id, field_values) pairs, using
der_sunspec's own vendored SMDX definitions to place each field at its real
offset -- so a device profile can't silently drift out of sync with the
offsets der_sunspec.adapter actually decodes.
"""

from __future__ import annotations

from der_sunspec.smdx_parser import load_model_def

_DOUBLE_REGISTER_TYPES = {"uint32", "acc32", "bitfield32", "int32"}
_QUAD_REGISTER_TYPES = {"uint64", "acc64", "int64"}


def encode_string(s: str, num_regs: int) -> list[int]:
    b = (s.encode("ascii") + b"\x00" * (num_regs * 2))[: num_regs * 2]
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)]


def _encode_value(point, value) -> list[int]:
    t = point.point_type
    if t == "string":
        return encode_string(value, point.length)
    if t in _QUAD_REGISTER_TYPES:
        v = value & 0xFFFFFFFFFFFFFFFF
        return [(v >> 48) & 0xFFFF, (v >> 32) & 0xFFFF, (v >> 16) & 0xFFFF, v & 0xFFFF]
    if t in _DOUBLE_REGISTER_TYPES:
        v = value & 0xFFFFFFFF
        return [(v >> 16) & 0xFFFF, v & 0xFFFF]
    # uint16 / acc16 / bitfield16 / int16 / sunssf / enum16 -- one register
    return [value & 0xFFFF]


def build_model_block(model_id: int, field_values: dict) -> list[int]:
    """One model's data block (the registers after its ID/L header),
    zero-filled except for the fields given."""
    mdef = load_model_def(model_id)
    if mdef is None:
        raise ValueError(f"no vendored SMDX def for model {model_id} -- "
                         "can't build a demo device profile with it")
    regs = [0] * mdef.length
    by_id = {p.id: p for p in mdef.points}
    for field, value in field_values.items():
        if field not in by_id:
            raise ValueError(f"model {model_id} has no field {field!r}")
        point = by_id[field]
        encoded = _encode_value(point, value)
        regs[point.offset:point.offset + len(encoded)] = encoded
    return regs


def build_device_registers(models: list[tuple[int, dict]]) -> list[int]:
    """Full register image for a device with this model chain, in order:
    "SunS" marker, then each model's [ID, length, ...data...], then the
    0xFFFF/0 end-of-model marker."""
    regs: list[int] = [0x5375, 0x6E53]
    for model_id, field_values in models:
        block = build_model_block(model_id, field_values)
        regs += [model_id, len(block)]
        regs += block
    regs += [0xFFFF, 0]
    return regs


def serve(registers: list[int], host: str, port: int, name: str) -> None:
    """Serve `registers` as a Modbus/TCP device on host:port. Same
    pymodbus-based approach as examples/quickstart_server.py.

    port 502 (the real Modbus/TCP port) needs authbind or an equivalent --
    see demo/README.md."""
    from pymodbus.datastore import (
        ModbusDeviceContext,
        ModbusSequentialDataBlock,
        ModbusServerContext,
    )
    from pymodbus.server import StartTcpServer

    # pymodbus's ModbusDeviceContext always adds 1 to the requested protocol
    # address before indexing into the store (no zero_mode toggle in
    # pymodbus 3.x) -- start the block at 1 so protocol address 0 maps to
    # registers[0], matching where der_sunspec's mapper looks for "SunS".
    block = ModbusSequentialDataBlock(1, registers)
    device_ctx = ModbusDeviceContext(hr=block)
    context = ModbusServerContext(devices=device_ctx, single=True)
    print(f"{name} -- SunSpec simulator on {host}:{port} -- Ctrl-C to stop", flush=True)
    StartTcpServer(context=context, address=(host, port))
