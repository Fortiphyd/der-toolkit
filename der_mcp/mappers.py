"""Framework-agnostic mapping + discovery helpers used by the MCP tools.

Kept separate from server.py so the real logic is testable without the MCP
runtime. Each function returns plain dicts / der_common models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from der_common.schema import AttackSurface

DEFAULT_PORTS = {"sep2": 15388, "dnp3": 20000, "sunspec": 502}


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# map_attack_surface (read-only)
# ---------------------------------------------------------------------------

def map_sep2(ip: str, port: int, client_cert: Optional[str] = None,
             client_key: Optional[str] = None, timeout: float = 10.0,
             max_depth: int = 8, rate_limit: float = 5.0) -> AttackSurface:
    from der_sep2.models import ServiceTarget, ProbeType
    from der_sep2.tls.client import TLSContextFactory, TLSProfiler
    from der_sep2.mapping.resource_mapper import ResourceMapper
    from der_sep2.adapter import build_attack_surface

    target = ServiceTarget(ip=ip, port=port, hostname=ip, base_path="/dcap")
    factory = TLSContextFactory(client_cert=client_cert, client_key=client_key)
    probe_types = [ProbeType.NO_CERT, ProbeType.SELF_SIGNED]
    if client_cert:
        probe_types += [ProbeType.VALID_UNREG, ProbeType.VALID_REG]

    result = ResourceMapper(target=target, context_factory=factory, probe_types=probe_types,
                            rate_limit_rps=rate_limit, max_depth=max_depth, timeout=timeout).run()
    try:
        profile = TLSProfiler(target, factory, connect_timeout=timeout).profile()
    except Exception:
        profile = None
    return build_attack_surface(result, tls_profile=profile,
                                used_cert=bool(client_cert), generated_at=_now())


def map_dnp3(ip: str, port: int, timeout: float = 3.0) -> Optional[AttackSurface]:
    from der_dnp3.scanner import run_scan
    from der_dnp3.adapter import build_attack_surfaces
    doc = run_scan([ip], port=port, workers=1, listen_seconds=timeout, probe_timeout=timeout)
    surfs = build_attack_surfaces(doc, generated_at=_now())
    return surfs[0] if surfs else None


def map_sunspec(ip: str, port: int, unit_id: int = 1, timeout: float = 0.4) -> Optional[AttackSurface]:
    from der_sunspec.mapper import build_device_mapping
    from der_sunspec.adapter import build_attack_surface
    m = build_device_mapping(ip, port, unit_id, timeout=timeout)
    return build_attack_surface(m, port=port, generated_at=_now()) if m else None


def map_attack_surface(protocol: str, ip: str, port: Optional[int] = None,
                       client_cert: Optional[str] = None, client_key: Optional[str] = None,
                       unit_id: Optional[int] = None) -> Optional[AttackSurface]:
    port = port or DEFAULT_PORTS[protocol]
    if protocol == "sep2":
        return map_sep2(ip, port, client_cert=client_cert, client_key=client_key)
    if protocol == "dnp3":
        return map_dnp3(ip, port)
    if protocol == "sunspec":
        return map_sunspec(ip, port, unit_id=unit_id or 1)
    raise ValueError(f"unknown protocol {protocol!r}")


# ---------------------------------------------------------------------------
# discover_targets (read-only)
# ---------------------------------------------------------------------------

def _discover_dnp3(scope: list[str], timeout: float) -> list[dict]:
    from der_dnp3.scanner import expand_targets, discover_outstation_address
    found = []
    for cidr in scope:
        for ip in expand_targets(cidr):
            got = discover_outstation_address(ip, 20000, listen_seconds=timeout,
                                              per_probe_timeout=timeout)
            if got:
                master, outstation = got
                found.append({"ip": ip, "port": 20000, "protocol": "dnp3",
                              "outstation_addr": outstation, "master_addr": master})
    return found


def _discover_sunspec(scope: list[str], timeout: float) -> list[dict]:
    from der_sunspec.mapper import expand_targets, find_sunspec_base
    from pymodbus.client import ModbusTcpClient
    found = []
    for cidr in scope:
        for ip in expand_targets(cidr):
            client = ModbusTcpClient(host=ip, port=502, timeout=timeout)
            if not client.connect():
                continue
            try:
                base = find_sunspec_base(client, 1)
            finally:
                client.close()
            if base is not None:
                found.append({"ip": ip, "port": 502, "protocol": "sunspec", "sunspec_base": base})
    return found


def _discover_sep2(scope: list[str]) -> list[dict]:
    from der_sep2.discovery.dns_sd import DiscoveryOrchestrator
    orch = DiscoveryOrchestrator(scan_targets=list(scope), skip_mdns=True,
                                 skip_dns_sd=True, skip_scan=False)
    return [{"ip": t.ip, "port": t.port, "protocol": "sep2", "base_path": t.base_path}
            for t in orch.run()]


def discover(scope: list[str], protocol: Optional[str] = None, timeout: float = 1.0) -> list[dict]:
    protocols = [protocol] if protocol else ["dnp3", "sunspec", "sep2"]
    out: list[dict] = []
    for proto in protocols:
        if proto == "dnp3":
            out += _discover_dnp3(scope, timeout)
        elif proto == "sunspec":
            out += _discover_sunspec(scope, timeout)
        elif proto == "sep2":
            out += _discover_sep2(scope)
    return out
