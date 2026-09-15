"""Adapter: SunSpec mapper output -> der_common.AttackSurface.

A SunSpec device answers unauthenticated Modbus/TCP reads with its full,
self-describing model chain. Where we have a vendored SMDX definition for a
model (der_sunspec/smdx/), each *field* becomes its own control point --
e.g. model 123 offset 3 -> "WMaxLimPct" -- since that is the actual unit of
read/write access on the wire. Models without a definition fall back to one
coarse point for the whole model. Writable points reachable over
unauthenticated Modbus are the high-severity surface either way.
"""

from __future__ import annotations

from datetime import datetime, timezone

from der_common.schema import (
    AttackSurface,
    AuthProfile,
    ControlPoint,
    Finding,
    Target,
)
from der_sunspec.models_catalog import is_control_model, model_name
from der_sunspec.smdx_parser import ModelDef, PointDef, load_model_def

# model IDs that are pure identity/comms/nameplate -> informational only
_INFO_MODELS = {1, 11, 12, 13, 120, 125}


def _severity(model_id: int) -> str:
    if is_control_model(model_id):
        return "critical"          # writable control reachable unauthenticated
    if model_id in _INFO_MODELS:
        return "info"
    return "low"                   # measurement / inverter / meter models


def _decode_point(regs: list[int], point: PointDef) -> object | None:
    """Best-effort decode of one point's raw registers into a Python value.
    Returns None (rather than raising) on anything short/malformed -- a
    partially-read device shouldn't kill the whole mapping."""
    off, n = point.offset, point.length
    if off + n > len(regs):
        return None
    chunk = regs[off:off + n]
    t = point.point_type

    def u32(a, b):
        return (a << 16) | b

    def u64(a, b, c, d):
        return (a << 48) | (b << 32) | (c << 16) | d

    def to_signed(v, bits):
        return v - (1 << bits) if v >= (1 << (bits - 1)) else v

    try:
        if t == "string":
            raw = b"".join(r.to_bytes(2, "big") for r in chunk)
            return raw.split(b"\x00", 1)[0].decode(errors="ignore").strip()
        if t in ("uint16", "acc16", "bitfield16"):
            return chunk[0]
        if t in ("int16", "sunssf"):
            return to_signed(chunk[0], 16)
        if t == "enum16":
            return point.symbols.get(chunk[0], chunk[0])
        if t in ("uint32", "acc32", "bitfield32"):
            return u32(chunk[0], chunk[1])
        if t == "int32":
            return to_signed(u32(chunk[0], chunk[1]), 32)
        if t in ("uint64", "acc64"):
            return u64(*chunk)
        if t == "int64":
            return to_signed(u64(*chunk), 64)
        return chunk[0] if len(chunk) == 1 else list(chunk)
    except Exception:
        return None


def _field_control_points(model, mdef: ModelDef) -> list[ControlPoint]:
    """One ControlPoint per SMDX-defined field. Padding carries no meaning
    and is dropped; everything else -- including read-only scale factors --
    is kept so the raw register layout is fully accounted for."""
    name = model_name(model.id)
    points = []
    for p in mdef.points:
        if p.point_type == "pad":
            continue
        value = _decode_point(model.registers, p) if model.registers is not None else None
        severity = "critical" if p.writable else ("info" if p.point_type == "sunssf" else "low")
        points.append(ControlPoint(
            address=f"model{model.id}@{model.start + p.offset}",
            semantic_label=f"{name} / {p.label or p.id}",
            model=f"SunSpec {model.id}.{p.id}",
            readable=True,
            writable=p.writable,
            value=value,
            units=p.units,
            severity=severity,
            reachable_unauthenticated=True,
        ))
    return points


def _control_point(model) -> ControlPoint:
    """Coarse, model-level fallback for models with no vendored SMDX def."""
    name = model_name(model.id)
    control = is_control_model(model.id)
    return ControlPoint(
        address=f"model{model.id}@{model.start}",
        semantic_label=name,
        model=f"SunSpec {model.id}",
        readable=True,
        writable=control,
        units=f"{model.length} registers",
        severity=_severity(model.id),
        reachable_unauthenticated=True,   # Modbus/TCP is unauthenticated
    )


def _control_points_for_model(model) -> list[ControlPoint]:
    mdef = load_model_def(model.id)
    if mdef is not None:
        return _field_control_points(model, mdef)
    return [_control_point(model)]


def build_attack_surface(mapping, port: int = 502, generated_at: str | None = None) -> AttackSurface:
    """Convert one DeviceMapping into an AttackSurface."""
    gen = generated_at or datetime.now(tz=timezone.utc).isoformat()
    info = mapping.common_info or {}

    control_ids = sorted({m.id for m in mapping.models if is_control_model(m.id)})
    undecoded_control_ids = sorted(i for i in control_ids if load_model_def(i) is None)

    findings: list[Finding] = [Finding(
        severity="high",
        title="SunSpec device exposes its self-describing model map over unauthenticated Modbus",
        description=("The device answered unauthenticated Modbus/TCP reads and returned its "
                     "full SunSpec model chain. Any client on the network can enumerate every "
                     "control point and its meaning without vendor documentation."),
        category="auth",
        evidence={"sunspec_base": mapping.sunspec_base,
                  "model_count": len(mapping.models),
                  "device": info},
    )]

    if control_ids:
        names = [f"{i} ({model_name(i)})" for i in control_ids]
        findings.append(Finding(
            severity="critical",
            title="Writable DER control models reachable without authentication",
            description=("The device exposes writable SunSpec control/settings models "
                         "(" + ", ".join(names) + "). An unauthenticated Modbus client can "
                         "write these registers to change setpoints, ride-through curves, or "
                         "connect/disconnect the DER."),
            category="policy",
            evidence={"control_models": control_ids},
        ))

    if undecoded_control_ids:
        names = [f"{i} ({model_name(i)})" for i in undecoded_control_ids]
        findings.append(Finding(
            severity="info",
            title="Some control models lack a vendored field-level definition",
            description=("No SMDX definition is bundled for " + ", ".join(names) + ", so these "
                         "appear as one coarse model-level control point rather than individual "
                         "writable registers. See der_sunspec/smdx/NOTICE.md."),
            category="policy",
            evidence={"undecoded_control_models": undecoded_control_ids},
        ))

    auth = AuthProfile(scheme="none", requires_auth=False, tls=False)
    if info:
        auth.notes = (f"Device: {info.get('manufacturer','?')} "
                      f"{info.get('model','?')} v{info.get('version','?')}")

    return AttackSurface(
        protocol="sunspec",
        target=Target(
            ip=mapping.host,
            port=port,
            protocol="sunspec",
            unit_id=mapping.unit_id,
        ),
        auth_profile=auth,
        control_points=[cp for m in mapping.models for cp in _control_points_for_model(m)],
        findings=findings,
        generated_at=gen,
    )


def build_attack_surfaces(mappings, port: int = 502,
                          generated_at: str | None = None) -> list[AttackSurface]:
    gen = generated_at or datetime.now(tz=timezone.utc).isoformat()
    return [build_attack_surface(m, port=port, generated_at=gen) for m in mappings]
