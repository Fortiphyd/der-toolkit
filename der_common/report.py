"""Cross-protocol summary report.

Every protocol's `map --output result.json` command already saves
`{"attack_surfaces": [...]}` -- this reads that same shape from one or more
files (any mix of dnp3/sunspec/sep2 results) and merges them into a single
view ranked by severity, regardless of which protocol a point came from.
No new data format to produce or maintain; this is purely a downstream
reader of what already exists.

  der-report result_dnp3.json result_sunspec.json result_sep2.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from der_common.schema import AttackSurface, ControlPoint, Finding

_SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_key(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev, len(_SEVERITY_ORDER))


def _target_label(surface: AttackSurface) -> str:
    t = surface.target
    return f"{surface.protocol}://{t.ip}:{t.port}"


@dataclass
class _RankedPoint:
    surface: AttackSurface
    point: ControlPoint


@dataclass
class _RankedFinding:
    surface: AttackSurface
    finding: Finding


def load_attack_surfaces(paths: list[str]) -> list[AttackSurface]:
    """Load every AttackSurface out of one or more saved `map --output`
    files. Skips a file with no attack_surfaces key rather than erroring, so
    a mixed batch of result files (some maybe from other tools) still works."""
    surfaces: list[AttackSurface] = []
    for path in paths:
        doc = json.loads(Path(path).read_text())
        for raw in doc.get("attack_surfaces", []):
            surfaces.append(AttackSurface.model_validate(raw))
    return surfaces


def summarize(surfaces: list[AttackSurface]) -> dict[str, Any]:
    """Every writable+unauthenticated-reachable control point and every
    cross-cutting finding, across all supplied surfaces, ranked by severity
    regardless of protocol -- the point of the toolkit's shared schema."""
    ranked_points = [
        _RankedPoint(surface=s, point=cp)
        for s in surfaces for cp in s.writable_reachable()
    ]
    ranked_points.sort(key=lambda r: _sev_key(r.point.severity))

    ranked_findings = [
        _RankedFinding(surface=s, finding=f)
        for s in surfaces for f in s.findings
    ]
    ranked_findings.sort(key=lambda r: _sev_key(r.finding.severity))

    by_protocol: dict[str, dict[str, int]] = {}
    for s in surfaces:
        entry = by_protocol.setdefault(s.protocol, {"targets": 0, "writable_reachable": 0})
        entry["targets"] += 1
        entry["writable_reachable"] += len(s.writable_reachable())

    return {
        "targets_assessed": len(surfaces),
        "by_protocol": by_protocol,
        "writable_reachable_points": [
            {
                "protocol": r.surface.protocol,
                "target": f"{r.surface.target.ip}:{r.surface.target.port}",
                "address": r.point.address,
                "semantic_label": r.point.semantic_label,
                "severity": r.point.severity,
                "value": r.point.value,
            }
            for r in ranked_points
        ],
        "findings": [
            {
                "protocol": r.surface.protocol,
                "target": f"{r.surface.target.ip}:{r.surface.target.port}",
                "severity": r.finding.severity,
                "title": r.finding.title,
                "category": r.finding.category,
            }
            for r in ranked_findings
        ],
    }


def format_report(summary: dict[str, Any]) -> str:
    lines = ["=" * 60, "  CROSS-PROTOCOL ATTACK SURFACE SUMMARY", "=" * 60, ""]

    protos = ", ".join(f"{proto}: {info['targets']}" for proto, info in summary["by_protocol"].items())
    lines.append(f"Targets assessed: {summary['targets_assessed']}  ({protos})")
    lines.append("")

    points = summary["writable_reachable_points"]
    lines.append(f"Writable + unauthenticated-reachable control points: {len(points)}")
    lines.append("-" * 60)
    for p in points:
        label = p["semantic_label"] or p["address"]
        lines.append(f"  [{p['severity'].upper():8s}] {p['protocol']:8s} {p['target']:22s} "
                     f"{p['address']:14s} {label} = {p['value']!r}")
    if not points:
        lines.append("  (none)")
    lines.append("")

    findings = summary["findings"]
    lines.append(f"Cross-cutting findings: {len(findings)}")
    lines.append("-" * 60)
    for f in findings:
        lines.append(f"  [{f['severity'].upper():8s}] {f['protocol']:8s} {f['target']:22s} {f['title']}")
    if not findings:
        lines.append("  (none)")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="der-report",
        description="Merge multiple protocol map --output result files into one ranked, "
                    "cross-protocol summary.",
    )
    ap.add_argument("files", nargs="+", metavar="RESULT.json",
                    help="One or more files saved by dnp3/sunspec/sep2 'map --output'")
    ap.add_argument("--output", "-o", default=None, metavar="FILE",
                    help="Save the structured JSON summary (in addition to the console report)")
    args = ap.parse_args(argv)

    try:
        surfaces = load_attack_surfaces(args.files)
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    if not surfaces:
        print("No attack surfaces found in the given file(s).", file=sys.stderr)
        return 1

    summary = summarize(surfaces)
    print(format_report(summary))

    if args.output:
        Path(args.output).write_text(json.dumps(summary, indent=2, default=str))
        print(f"\nStructured summary saved to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
