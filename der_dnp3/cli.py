"""der-dnp3 CLI: discover / map / fuzz.

  der-dnp3 discover <host> [--port 20000]
  der-dnp3 map <cidr|host> [--port 20000] [--output map.json]   -> AttackSurface
  der-dnp3 fuzz <host> --authorized-scope <cidr> --allow-disruptive
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _cmd_discover(args: argparse.Namespace) -> int:
    from der_dnp3.scanner import discover_outstation_address, parse_int_list
    got = discover_outstation_address(
        host=args.host, port=args.port,
        typical_master_addrs=parse_int_list(args.masters),
        typical_outstation_addrs=parse_int_list(args.outstations),
        listen_seconds=args.listen_seconds, per_probe_timeout=args.probe_timeout,
    )
    if not got:
        print("no DNP3 outstation discovered")
        return 1
    master, outstation = got
    print(f"master={master} outstation={outstation}")
    return 0


def _cmd_map(args: argparse.Namespace) -> int:
    from der_dnp3.scanner import run_scan, expand_targets, parse_int_list
    from der_dnp3.adapter import build_attack_surfaces

    ips = expand_targets(args.target, include_network_broadcast=args.include_network_broadcast)
    scan_doc = run_scan(
        ips, port=args.port, workers=args.workers,
        listen_seconds=args.listen_seconds, probe_timeout=args.probe_timeout,
        typical_master_addrs=parse_int_list(args.masters),
        typical_outstation_addrs=parse_int_list(args.outstations),
    )
    gen = datetime.now(tz=timezone.utc).isoformat()
    surfaces = [s.model_dump() for s in build_attack_surfaces(scan_doc, generated_at=gen)]

    total_cp = sum(len(s["control_points"]) for s in surfaces)
    print(f"[dnp3] {scan_doc['ok']}/{scan_doc['scanned']} outstation(s) reachable; "
          f"{total_cp} control point(s) mapped")
    for s in surfaces:
        wr = [c["address"] for c in s["control_points"]
              if c["writable"] and c["reachable_unauthenticated"]]
        print(f"  {s['target']['ip']} outstation={s['target']['unit_id']}: "
              f"{len(s['control_points'])} points, {len(wr)} unauth-writable {wr or ''}")

    if args.output:
        doc = {"generated_at": gen, "attack_surfaces": surfaces, "scan": scan_doc}
        Path(args.output).write_text(json.dumps(doc, indent=2, default=str))
        print(f"  saved to {args.output}")
    return 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    from der_common.scope import assert_in_scope, require_disruptive_consent
    # Fail closed: an in-scope target and explicit disruptive consent are required.
    assert_in_scope(args.host, args.authorized_scope or [])
    require_disruptive_consent(args.allow_disruptive)

    from der_dnp3.fuzzer import run_fuzz
    from der_common.boofuzz_db import parse_boofuzz_db, summarize_boofuzz_db
    print(f"[dnp3] fuzzing {args.host}:{args.port} (DISRUPTIVE) — "
          f"outstation={args.outstation} master={args.master}")
    run_fuzz(args.host, args.port, max_depth=args.max_depth,
             dst=args.outstation, src=args.master)

    dbs = sorted(Path("boofuzz-results").glob("*.db")) if Path("boofuzz-results").exists() else []
    findings = []
    for db in dbs:
        summary = summarize_boofuzz_db(db)
        crashes = parse_boofuzz_db(db)
        findings += crashes
        print(f"  {db.name}: {summary['total_cases']} cases, "
              f"{summary['crashed_cases']} crashed")
        for c in crashes:
            print(f"    CRASH: {c.title}")

    if args.output:
        Path(args.output).write_text(json.dumps([f.model_dump() for f in findings],
                                                 indent=2, default=str))
        print(f"  findings saved to {args.output}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="der-dnp3", description="DNP3 attack-surface mapper and fuzzer")
    sub = p.add_subparsers(dest="command", required=True)

    common_addr = dict(masters="1", outstations="1,2,3,10,11,12,20,100,101,102,1000,1002,1024")

    d = sub.add_parser("discover", help="Discover an outstation's link addresses")
    d.add_argument("host")
    d.add_argument("--port", type=int, default=20000)
    d.add_argument("--masters", default=common_addr["masters"])
    d.add_argument("--outstations", default=common_addr["outstations"])
    d.add_argument("--listen-seconds", type=float, default=3.0)
    d.add_argument("--probe-timeout", type=float, default=3.0)
    d.set_defaults(func=_cmd_discover)

    m = sub.add_parser("map", help="Scan and inventory outstations -> AttackSurface")
    m.add_argument("target", help="CIDR or single host, e.g. 192.168.1.0/24")
    m.add_argument("--port", type=int, default=20000)
    m.add_argument("--workers", type=int, default=8)
    m.add_argument("--masters", default=common_addr["masters"])
    m.add_argument("--outstations", default=common_addr["outstations"])
    m.add_argument("--listen-seconds", type=float, default=3.0)
    m.add_argument("--probe-timeout", type=float, default=3.0)
    m.add_argument("--include-network-broadcast", action="store_true")
    m.add_argument("--output", default=None, metavar="FILE")
    m.set_defaults(func=_cmd_map)

    f = sub.add_parser("fuzz", help="Fuzz an outstation (DISRUPTIVE, boofuzz)")
    f.add_argument("host")
    f.add_argument("--port", type=int, default=20000)
    f.add_argument("--outstation", type=int, default=10, help="Outstation link address (dst)")
    f.add_argument("--master", type=int, default=1, help="Master link address (src)")
    f.add_argument("--max-depth", type=int, default=2)
    f.add_argument("--authorized-scope", nargs="+", metavar="CIDR", default=None,
                   help="IPs/CIDRs you are authorized to test (required)")
    f.add_argument("--allow-disruptive", action="store_true",
                   help="Confirm you accept that fuzzing can crash the device")
    f.add_argument("--output", default=None, metavar="FILE",
                   help="Save parsed FuzzFinding[] (crashes only) as JSON")
    f.set_defaults(func=_cmd_fuzz)

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
