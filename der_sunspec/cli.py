"""der-sunspec CLI: map / fuzz / fuzz-client.

  der-sunspec map <cidr|host> [--port 502] [--unit-id 1] [--format json|yaml|lua]
      Walk the self-describing SunSpec model chain -> AttackSurface (default json).
      yaml/lua formats are preserved for the original Suricata-rules workflow.

  der-sunspec fuzz <host> --authorized-scope <cidr> --allow-disruptive
      Fuzz a SunSpec device's Modbus/TCP server (boofuzz). DISRUPTIVE to the target.

  der-sunspec fuzz-client [--host 0.0.0.0] [--port 502] --allow-disruptive
      Start a malicious Modbus server that fuzzes SunSpec masters/clients which
      connect to it. DISRUPTIVE to the connecting client.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _cmd_map(args: argparse.Namespace) -> int:
    from der_sunspec.adapter import build_attack_surfaces
    from der_sunspec.mapper import expand_targets, mappings_to_lua, mappings_to_yaml, run_scan
    from der_sunspec.models_catalog import is_control_model

    targets = expand_targets(args.target)
    mappings, failed = run_scan(targets, port=args.port, unit_id=args.unit_id, timeout=args.timeout,
                                read_registers=not args.no_registers)
    gen = datetime.now(tz=timezone.utc).isoformat()
    surfaces = build_attack_surfaces(mappings, port=args.port, generated_at=gen)

    if args.format == "yaml":
        out = mappings_to_yaml(mappings, failed)
    elif args.format == "lua":
        out = mappings_to_lua(mappings, failed)
    else:
        out = json.dumps({"generated_at": gen, "attack_surfaces": [s.model_dump() for s in surfaces],
                          "failed_hosts": failed}, indent=2, default=str)

    print(f"[sunspec] {len(mappings)} device(s) mapped, {len(failed)} failed", file=sys.stderr)
    for m, surf in zip(mappings, surfaces):
        ctrl = [mdl.id for mdl in m.models if is_control_model(mdl.id)]
        wr = surf.writable_reachable()
        print(f"  {m.host} unit={m.unit_id}: {len(m.models)} models, "
              f"{len(ctrl)} writable control model(s) {ctrl or ''}, "
              f"{len(wr)} unauth-writable field(s)", file=sys.stderr)

    if args.output:
        Path(args.output).write_text(out)
        print(f"  saved to {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    from der_common.scope import assert_in_scope, require_disruptive_consent
    # Fail closed: an in-scope target and explicit disruptive consent are required.
    assert_in_scope(args.host, args.authorized_scope or [])
    require_disruptive_consent(args.allow_disruptive)

    from der_common.boofuzz_db import parse_boofuzz_db, summarize_boofuzz_db
    from der_sunspec.fuzzer import run_fuzz
    print(f"[sunspec] fuzzing {args.host}:{args.port} (DISRUPTIVE) — unit={args.unit_id}",
          file=sys.stderr)
    run_fuzz(args.host, args.port, unit_id=args.unit_id, max_depth=args.max_depth)

    dbs = sorted(Path("boofuzz-results").glob("*.db")) if Path("boofuzz-results").exists() else []
    findings = []
    for db in dbs:
        summary = summarize_boofuzz_db(db)
        crashes = parse_boofuzz_db(db)
        findings += crashes
        print(f"  {db.name}: {summary['total_cases']} cases, "
              f"{summary['crashed_cases']} crashed", file=sys.stderr)
        for c in crashes:
            print(f"    CRASH: {c.title}", file=sys.stderr)

    if args.output:
        Path(args.output).write_text(json.dumps([f.model_dump() for f in findings],
                                                 indent=2, default=str))
        print(f"  findings saved to {args.output}", file=sys.stderr)
    return 0


def _cmd_fuzz_client(args: argparse.Namespace) -> int:
    from der_common.scope import require_disruptive_consent
    # This tool fuzzes whichever client connects to it, so there is no single
    # target IP to scope-check; the disruptive-consent gate still applies.
    require_disruptive_consent(args.allow_disruptive)

    from der_sunspec.client_fuzzer.server import start_fake_server
    print(f"[sunspec] malicious Modbus server on {args.host}:{args.port} — fuzzes SunSpec "
          f"masters/clients that connect. Only point authorized clients at it. Ctrl-C to stop.",
          file=sys.stderr)
    start_fake_server(host=args.host, port=args.port)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="der-sunspec",
                                description="SunSpec Modbus attack-surface mapper and fuzzer")
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("map", help="Map SunSpec devices -> AttackSurface")
    m.add_argument("target", help="CIDR or single host")
    m.add_argument("--port", type=int, default=502)
    m.add_argument("--unit-id", type=int, default=1)
    m.add_argument("--timeout", type=float, default=0.4)
    m.add_argument("--format", choices=["json", "yaml", "lua"], default="json")
    m.add_argument("--no-registers", action="store_true",
                   help="Skip per-model register reads (header-only; faster over a large CIDR, "
                        "but drops field-level control points down to one per model)")
    m.add_argument("--output", "-o", default=None, metavar="FILE")
    m.set_defaults(func=_cmd_map)

    fz = sub.add_parser("fuzz", help="Fuzz a device's Modbus/TCP server (DISRUPTIVE, boofuzz)")
    fz.add_argument("host")
    fz.add_argument("--port", type=int, default=502)
    fz.add_argument("--unit-id", type=int, default=1)
    fz.add_argument("--max-depth", type=int, default=3)
    fz.add_argument("--authorized-scope", nargs="+", metavar="CIDR", default=None,
                    help="IPs/CIDRs you are authorized to test (required)")
    fz.add_argument("--allow-disruptive", action="store_true",
                    help="Confirm you accept that fuzzing can crash the device")
    fz.add_argument("--output", default=None, metavar="FILE",
                    help="Save parsed FuzzFinding[] (crashes only) as JSON")
    fz.set_defaults(func=_cmd_fuzz)

    f = sub.add_parser("fuzz-client",
                       help="Fuzz SunSpec masters/clients via a malicious server (DISRUPTIVE)")
    f.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    f.add_argument("--port", type=int, default=502)
    f.add_argument("--allow-disruptive", action="store_true",
                   help="Confirm you accept that fuzzing can crash the connecting client")
    f.set_defaults(func=_cmd_fuzz_client)

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
