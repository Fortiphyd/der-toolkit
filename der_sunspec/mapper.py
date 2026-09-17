#!/usr/bin/env python3
"""
sunspec_mapper.py

Offline SunSpec Modbus mapper (Phase 1) with CIDR scanning support:

- Connects to a Modbus TCP device
- Finds the SunSpec base ("SunS" marker)
- Walks all SunSpec models (ID/LEN)
- Can scan a single host OR an entire CIDR range
- Outputs a YAML mapping of models for each discovered device

Dependencies:
  pip install pymodbus pyyaml
"""

import argparse
import ipaddress
import logging
from dataclasses import dataclass

import yaml
from pymodbus.client import ModbusTcpClient

LOG = logging.getLogger("sunspec_mapper")

# Known SunSpec base logical registers (holding registers)
SUNSPEC_BASE_CANDIDATES = [40000, 50000, 0]

# 32-bit "SunS" marker as per SunSpec spec (0x53 0x75 0x6e 0x53)
SUNS_MARKER = b"SunS"


@dataclass
class SunSpecModel:
    id: int
    start: int        # logical register of first data point
    length: int       # number of 16-bit registers in model data block
    registers: list[int] | None = None  # full data block, if fetched


@dataclass
class DeviceMapping:
    host: str
    unit_id: int
    sunspec_base: int  # logical register of base (where "SunS" starts)
    models: list[SunSpecModel]
    common_info: dict[str, str] | None = None


def read_holding_regs(client: ModbusTcpClient, unit_id: int, reg: int, count: int) -> list[int] | None:
    """
    Read 'count' holding registers starting at register 'reg'.

    We pass `reg` directly to pymodbus without subtracting 40001.
    Devices differ in how they interpret Modbus addressing, and the safest
    strategy for scanning is to probe the explicit register number.
    """
    try:
        resp = client.read_holding_registers(address=reg, count=count, device_id=unit_id)
    except Exception as e:
        LOG.error("Error reading %d regs at %d: %s", count, reg, e)
        return None

    if resp.isError():
        LOG.error("Modbus error reading %d regs at %d: %s", count, reg, resp)
        return None

    return list(resp.registers)


def find_sunspec_base(client: ModbusTcpClient, unit_id: int) -> int | None:
    """
    Try known base candidates and return the register where the "SunS" marker is found.
    """
    for base in SUNSPEC_BASE_CANDIDATES:
        regs = read_holding_regs(client, unit_id, base, 2)
        if not regs:
            continue

        # Combine into 4 bytes (big-endian)
        high, low = regs[0], regs[1]
        marker_bytes = high.to_bytes(2, "big") + low.to_bytes(2, "big")

        if marker_bytes == SUNS_MARKER:
            LOG.info("Found SunSpec marker 'SunS' at register %d", base)
            return base
        else:
            LOG.debug(
                "Base candidate %d mismatch: [%d, %d]",
                base,
                high,
                low,
            )

    LOG.error("Failed to find SunSpec 'SunS' marker using known bases")
    return None


def walk_sunspec_models(client: ModbusTcpClient, unit_id: int, sunspec_base: int,
                        max_models: int = 200, max_reg: int = 65000) -> list[SunSpecModel]:
    """
    Walk SunSpec model chain after 'SunS'.

    Returns a list of SunSpecModel entries.
    """
    models: list[SunSpecModel] = []
    current = sunspec_base + 2  # first model header
    count = 0

    while count < max_models and current < max_reg:
        header = read_holding_regs(client, unit_id, current, 2)
        if not header:
            LOG.warning("Stopping model walk: read error at %d", current)
            break

        model_id, length = header[0], header[1]
        LOG.debug("Model header @%d: id=%d len=%d", current, model_id, length)

        if model_id == 0xFFFF:
            LOG.info("Reached SunSpec end model @%d", current)
            break

        data_start = current + 2
        models.append(SunSpecModel(id=model_id, start=data_start, length=length))
        count += 1

        current = data_start + length

    return models


def read_model_registers(client: ModbusTcpClient, unit_id: int, model: SunSpecModel,
                         chunk_size: int = 123) -> list[int] | None:
    """Read a model's full data block, chunked to stay under Modbus's per-read
    register cap (chunk_size defaults just under the common 125-register limit)."""
    if model.length == 0:
        return []
    regs: list[int] = []
    addr = model.start
    remaining = model.length
    while remaining > 0:
        n = min(chunk_size, remaining)
        chunk = read_holding_regs(client, unit_id, addr, n)
        if chunk is None:
            return None
        regs.extend(chunk)
        addr += n
        remaining -= n
    return regs


def read_common_model(client: ModbusTcpClient, unit_id: int, base: int, models: list[SunSpecModel]) -> dict[str, str] | None:
    """
    Read SunSpec Common Model (ID = 1), which contains:
      Mn  = Manufacturer
      Md  = Model
      Vr  = Version
    """
    common = next((m for m in models if m.id == 1), None)
    if not common:
        return None

    try:
        # Following SunSpec definition, strings are 16-bit registers holding ASCII bytes
        regs = read_holding_regs(client, unit_id, common.start, common.length)
        if not regs:
            return None

        # Convert registers to bytes
        raw = b"".join(r.to_bytes(2, "big") for r in regs)

        # Strings are null-terminated
        def extract_field(offset, size):
            field_bytes = raw[offset:offset+size]
            return field_bytes.split(b"\x00", 1)[0].decode(errors="ignore").strip()

        # Known Model 1 layout (sizes in bytes): Mn=32, Md=32, Opt=16, Vr=16
        return {
            "manufacturer": extract_field(0, 32),
            "model": extract_field(32, 32),
            "options": extract_field(64, 16),
            "version": extract_field(80, 16),
        }
    except Exception as e:
        LOG.error(f"Exception while parsing Common Model: {e}")
        return None


def build_device_mapping(host: str, port: int, unit_id: int, timeout: float = 0.4,
                         read_registers: bool = True) -> DeviceMapping | None:
    """
    Attempt to connect and build mapping for ONE host.

    `read_registers` fetches each model's full data block (one extra Modbus
    read per model, chunked for large blocks) so the adapter can decode
    field-level control points instead of just the model-level header. Set
    False for a fast, header-only scan across a large CIDR.
    """
    client = ModbusTcpClient(host=host, port=port, timeout=timeout)
    if not client.connect():
        LOG.warning("Connection failed to %s:%d", host, port)
        return None

    try:
        base = find_sunspec_base(client, unit_id)
        if base is None:
            return None

        models = walk_sunspec_models(client, unit_id, base)
        # Read SunSpec Model 1 (Common Model) info
        LOG.debug("Attempting to read SunSpec Common Model (ID=1)")
        common_info = read_common_model(client, unit_id, base, models)

        if read_registers:
            for model in models:
                model.registers = read_model_registers(client, unit_id, model)

        return DeviceMapping(host=host, unit_id=unit_id, sunspec_base=base, models=models, common_info=common_info)
    finally:
        client.close()


def mappings_to_yaml(mappings: list[DeviceMapping], failed: list[str]) -> str:
    """
    Convert results into YAML with multiple hosts.
    """
    data: dict[str, dict] = {}

    for m in mappings:
        host_entry = {
            "unit_id": m.unit_id,
            "sunspec_base": m.sunspec_base,
            "device_info": m.common_info if m.common_info else {},
            "models": {},
        }
        for model in m.models:
            host_entry["models"][str(model.id)] = {
                "start": model.start,
                "length": model.length,
            }
        data[m.host] = host_entry

    if failed:
        data["failed_hosts"] = failed

    return yaml.safe_dump(data, sort_keys=False)


def mappings_to_lua(mappings: list[DeviceMapping], failed: list[str]) -> str:
    """
    Output results as a Lua table for Suricata (fastest format).
    """
    lines = []
    lines.append("return {")

    for m in mappings:
        lines.append(f"  ['{m.host}'] = {{")
        lines.append(f"    unit_id = {m.unit_id},")
        lines.append(f"    sunspec_base = {m.sunspec_base},")

        # Device info
        if m.common_info:
            lines.append("    device_info = {")
            for k, v in m.common_info.items():
                v_esc = v.replace("'", "\'") if isinstance(v, str) else v
                lines.append(f"      {k} = '{v_esc}',")
            lines.append("    },")
        else:
            lines.append("    device_info = {},")

        # Models
        lines.append("    models = {")
        for model in m.models:
            lines.append(f"      ['{model.id}'] = {{ start = {model.start}, length = {model.length} }},")
        lines.append("    },")
        lines.append("  },")

    if failed:
        lines.append("  failed_hosts = {")
        for h in failed:
            lines.append(f"    '{h}',")
        lines.append("  },")

    lines.append("}")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Offline SunSpec Modbus mapper with CIDR support")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device IP or hostname")
    group.add_argument("--cidr", help="CIDR range to scan, e.g., 192.168.1.0/24")

    p.add_argument("--port", type=int, default=502, help="Modbus TCP port (default 502)")
    p.add_argument("--unit-id", type=int, default=1, help="Modbus Unit ID (default 1)")
    p.add_argument("--output", "-o", help="Output file (default stdout)")
    p.add_argument("--format", choices=["yaml", "lua"], default="yaml", help="Output format: yaml or lua")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s [%(levelname)s] %(message)s")

    mappings: list[DeviceMapping] = []
    failed: list[str] = []

    # --- Single host mode ---
    if args.host:
        LOG.info("Scanning single host %s", args.host)
        result = build_device_mapping(args.host, args.port, args.unit_id)
        if result:
            mappings.append(result)
        else:
            failed.append(args.host)

    # --- CIDR mode ---
    else:
        LOG.info("Scanning CIDR range %s", args.cidr)
        net = ipaddress.ip_network(args.cidr, strict=False)
        for ip in net.hosts():
            ip_str = str(ip)
            LOG.info("Scanning %s", ip_str)
            result = build_device_mapping(ip_str, args.port, args.unit_id)
            if result:
                mappings.append(result)
            else:
                failed.append(ip_str)

        # Output selection
    if args.format == "lua":
        out = mappings_to_lua(mappings, failed)
    else:
        out = mappings_to_yaml(mappings, failed)


    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
            print(f"Wrote output to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# Library entry points (used by der_sunspec.cli / der_sunspec.adapter)
# ---------------------------------------------------------------------------

def expand_targets(cidr_or_host: str) -> list[str]:
    """Expand a CIDR or a single host/IP into a list of IP strings."""
    try:
        net = ipaddress.ip_network(cidr_or_host, strict=False)
    except ValueError:
        return [cidr_or_host]
    ips = list(net.hosts())
    if not ips:            # /32 single host
        ips = [net.network_address]
    return [str(ip) for ip in ips]


def run_scan(targets: list[str], port: int = 502, unit_id: int = 1,
             timeout: float = 0.4, read_registers: bool = True) -> tuple[list[DeviceMapping], list[str]]:
    """Map SunSpec devices across a list of hosts.

    Returns (mappings, failed_hosts).
    """
    mappings: list[DeviceMapping] = []
    failed: list[str] = []
    for host in targets:
        result = build_device_mapping(host, port, unit_id, timeout=timeout, read_registers=read_registers)
        if result:
            mappings.append(result)
        else:
            failed.append(host)
    return mappings, failed
