"""Adapter: DNP3 scanner output -> der_common.AttackSurface.

The scanner READs an outstation's Class 0 / device-attribute objects and gets
back an inventory of object groups. Over DNP3/TCP there is no authentication by
default, so any group the outstation returns is reachable by an unauthenticated
attacker. Crucially, the presence of Binary/Analog *Output* groups means the
device has operable control points -- an attacker can issue Binary Output
Commands (g12 CROB) or Analog Output Commands (g41) to actuate them.
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

# status group -> the command group that operates it
_OUTPUT_STATUS = {10: 12, 40: 41}
# direct command / dangerous groups
_COMMAND_GROUPS = {12, 41, 70}
_WRITABLE = set(_OUTPUT_STATUS) | _COMMAND_GROUPS
_OPERABLE = {10, 12, 40, 41}
_MEASUREMENT = {1, 2, 3, 4, 20, 21, 22, 23, 30, 31, 32, 33}
_SECURE_AUTH = {120, 121, 122}


def _points_in_range(rng: dict | None) -> int | None:
    if not rng:
        return None
    if "start" in rng and "stop" in rng:
        return rng["stop"] - rng["start"] + 1 if rng["stop"] >= rng["start"] else None
    return rng.get("count")


def _severity(group: int, reachable_unauth: bool) -> str:
    if group in _OPERABLE:
        return "critical" if reachable_unauth else "high"
    if group == 70:                      # File Control
        return "high"
    if group in _MEASUREMENT:
        return "low"
    return "info"


def _collect_headers(result: dict) -> list[dict]:
    headers: list[dict] = []
    for key in ("class0", "g0v254", "g0v255"):
        blk = result.get(key)
        if blk and blk.get("headers"):
            headers.extend(blk["headers"])
    return headers


def _control_points(headers: list[dict]) -> list[ControlPoint]:
    seen: set[tuple] = set()
    cps: list[ControlPoint] = []
    for h in headers:
        g, v = h["group"], h["variation"]
        rng = h.get("range")
        key = (g, v, str(rng))
        if key in seen:
            continue
        seen.add(key)
        writable = g in _WRITABLE
        cps.append(ControlPoint(
            address=f"g{g}v{v}",
            semantic_label=h.get("group_name"),
            model=h.get("group_name"),
            readable=True,
            writable=writable,
            value=rng or None,
            units=f"{_points_in_range(rng)} points" if _points_in_range(rng) else None,
            severity=_severity(g, reachable_unauth=True),
            reachable_unauthenticated=True,
        ))
    return cps


def _findings(result: dict, groups: set[int]) -> list[Finding]:
    findings: list[Finding] = []
    findings.append(Finding(
        severity="high",
        title="Outstation responds to unauthenticated DNP3 requests",
        description=("The outstation returned application data to a READ issued with "
                     "no authentication. DNP3/TCP has no transport security by default; "
                     "any master that can reach this port can read the full object model."),
        category="auth",
        evidence={"outstation_addr": result.get("outstation_addr"),
                  "master_addr": result.get("master_addr")},
    ))

    operable = groups & _OPERABLE
    if operable:
        names = sorted({_group_name(g) for g in operable})
        findings.append(Finding(
            severity="critical",
            title="Controllable output points reachable without authentication",
            description=("The outstation exposes output objects (" + ", ".join(names) + "). "
                         "Because DNP3/TCP is unauthenticated, an attacker can issue Binary "
                         "Output Commands (g12 CROB) or Analog Output Commands (g41) to "
                         "actuate these points. (The scanner enumerates the surface; it does "
                         "not send operate commands.)"),
            category="policy",
            evidence={"operable_groups": sorted(operable)},
        ))

    if groups & _SECURE_AUTH:
        findings.append(Finding(
            severity="info",
            title="DNP3 Secure Authentication objects present but not enforced for reads",
            description=("Security-statistics/authentication objects were seen, yet the "
                         "outstation still answered an unauthenticated READ."),
            category="auth",
            evidence={"secure_auth_groups": sorted(groups & _SECURE_AUTH)},
        ))

    if result.get("unsolicited_seen"):
        findings.append(Finding(
            severity="info",
            title="Outstation sends unsolicited responses",
            description="The outstation emits unsolicited responses, aiding passive discovery.",
            category="discovery",
            evidence={"count": len(result["unsolicited_seen"])},
        ))
    return findings


def _group_name(g: int) -> str:
    from der_dnp3.scanner import DNP3_GROUP_NAMES
    return DNP3_GROUP_NAMES.get(g, f"Group {g}")


def _one(result: dict, default_port: int | None, generated_at: str) -> AttackSurface:
    headers = _collect_headers(result)
    groups = {h["group"] for h in headers}
    auth = AuthProfile(scheme="none", requires_auth=False, tls=False)
    if groups & _SECURE_AUTH:
        auth.notes = "Secure Authentication objects present but not enforced for reads."
    return AttackSurface(
        protocol="dnp3",
        target=Target(
            ip=result["ip"],
            port=result.get("port") or default_port or 20000,
            protocol="dnp3",
            unit_id=result.get("outstation_addr"),
        ),
        auth_profile=auth,
        control_points=_control_points(headers),
        findings=_findings(result, groups),
        generated_at=generated_at,
    )


def build_attack_surfaces(scan_doc: dict, generated_at: str | None = None) -> list[AttackSurface]:
    """Convert a run_scan document into one AttackSurface per reachable outstation."""
    gen = generated_at or datetime.now(tz=timezone.utc).isoformat()
    return [
        _one(r, scan_doc.get("port"), gen)
        for r in scan_doc.get("results", [])
        if r.get("ok")
    ]
