"""Subprocess fuzz runner launched by der_mcp.jobs.JobManager.

Runs with CWD = the job's run directory. Writes:
  status.json   -> {"state": running|done|failed, "summary"|"error"}
  findings.json -> [FuzzFinding dict, ...]
Any large evidence (boofuzz DB, pcaps) is left in the run dir and referenced by
path from a finding's artifact_ref.

  python -m der_mcp.fuzz_runner --protocol dnp3 --host 10.0.0.5 --port 20000 --opts '{}'
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path


def _write(name: str, obj) -> None:
    Path(name).write_text(json.dumps(obj, indent=2, default=str))


def _fuzz_dnp3(host: str, port: int, opts: dict) -> list[dict]:
    from der_dnp3.fuzzer import run_fuzz
    run_fuzz(host, port, max_depth=opts.get("max_depth", 2),
             dst=opts.get("outstation", 10), src=opts.get("master", 1))
    return _collect_boofuzz_findings("DNP3", opts)


def _fuzz_sunspec(host: str, port: int, opts: dict) -> list[dict]:
    from der_sunspec.fuzzer import run_fuzz
    run_fuzz(host, port, unit_id=opts.get("unit_id", 1), max_depth=opts.get("max_depth", 3))
    return _collect_boofuzz_findings("SunSpec", opts)


def _collect_boofuzz_findings(label: str, opts: dict) -> list[dict]:
    from der_common.boofuzz_db import parse_boofuzz_db, summarize_boofuzz_db

    # boofuzz writes its DB under ./boofuzz-results/ (i.e. inside the run dir).
    dbs = sorted(Path("boofuzz-results").glob("*.db")) if Path("boofuzz-results").exists() else []
    if not dbs:
        return [{"title": f"{label} boofuzz run complete", "input_summary": "no results db produced",
                 "severity": "info", "crashed": False}]

    max_crashes = opts.get("max_crashes", 100)
    findings: list[dict] = []
    for db in dbs:
        summary = summarize_boofuzz_db(db)
        crashes = parse_boofuzz_db(db, max_crashes=max_crashes)
        findings += [f.model_dump() for f in crashes]
        dropped = summary["crashed_cases"] - len(crashes)
        note = f"{summary['total_cases']} cases, {summary['crashed_cases']} crashed"
        if dropped > 0:
            note += f" ({dropped} more crash records not parsed, see artifact_ref)"
        findings.append({
            "title": f"{label} boofuzz run complete ({db.name})",
            "input_summary": note, "crashed": False,
            "severity": "critical" if crashes else "info",
            "artifact_ref": str(db),
        })
    return findings


def _fuzz_sep2(host: str, port: int, opts: dict) -> list[dict]:
    from der_sep2.models import ServiceTarget
    from der_sep2.tls.client import TLSContextFactory
    from der_sep2.fuzzing.xml_fuzzer import XMLFuzzer
    from der_sep2.fuzzing.http_fuzzer import HTTPFuzzer
    from der_sep2.adapter import _fuzz_finding

    target = ServiceTarget(ip=host, port=port, hostname=host)
    factory = TLSContextFactory(client_cert=opts.get("client_cert"),
                                client_key=opts.get("client_key"))
    findings = []
    xr = XMLFuzzer(target=target, context_factory=factory, mapping_result=None,
                   rate_limit_rps=opts.get("rate_limit", 2.0), timeout=opts.get("timeout", 10.0),
                   callback_host=opts.get("callback_host", "127.0.0.1"),
                   callback_port=opts.get("callback_port", 9999)).run()
    findings += [_fuzz_finding(f).model_dump() for f in xr.findings]
    hr = HTTPFuzzer(target=target, context_factory=factory, mapping_result=None,
                    rate_limit_rps=opts.get("rate_limit", 3.0), timeout=opts.get("timeout", 10.0),
                    idor_range=opts.get("idor_range", 10)).run()
    findings += [_fuzz_finding(f).model_dump() for f in hr.findings]
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="der_mcp.fuzz_runner")
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--opts", default="{}", help="JSON options blob")
    a = ap.parse_args(argv)
    opts = json.loads(a.opts)
    target = f"{a.host}:{a.port}"

    _write("status.json", {"state": "running", "protocol": a.protocol, "target": target})
    try:
        if a.protocol == "dnp3":
            findings = _fuzz_dnp3(a.host, a.port, opts)
        elif a.protocol == "sunspec":
            findings = _fuzz_sunspec(a.host, a.port, opts)
        elif a.protocol == "sep2":
            findings = _fuzz_sep2(a.host, a.port, opts)
        elif a.protocol == "_selftest":          # test hook: no network, no deps
            findings = [{"title": "selftest finding", "input_summary": "synthetic",
                         "severity": "info", "crashed": False}]
        else:
            raise ValueError(f"device fuzzing is not supported for protocol {a.protocol!r}")
        _write("findings.json", findings)
        _write("status.json", {"state": "done", "protocol": a.protocol, "target": target,
                               "summary": {"findings": len(findings),
                                           "crashes": sum(1 for f in findings if f.get("crashed"))}})
        return 0
    except Exception as e:
        _write("status.json", {"state": "failed", "protocol": a.protocol, "target": target,
                               "error": f"{type(e).__name__}: {e}",
                               "traceback": traceback.format_exc()})
        return 1


if __name__ == "__main__":
    sys.exit(main())
