"""MCP server for the DER toolkit.

stdio transport, launched by the AI client. Read-only mapping/discovery return
inline; fuzzing is an async job (start_fuzz -> job_id, poll with get_job, collect
with get_findings). Every active operation routes through der_common.scope so the
safety policy lives in one auditable place.

All real logic lives in der_mcp.mappers / der_mcp.jobs / der_mcp.fuzz_runner so it
is testable without the MCP runtime; this module is a thin binding.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Literal, Optional

from der_common.scope import assert_in_scope, require_disruptive_consent
from der_mcp import mappers
from der_mcp.jobs import JobManager

# FastMCP was renamed MCPServer in the 2.x SDK; support both.
try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server
except ModuleNotFoundError:  # mcp 2.x
    from mcp.server import MCPServer as _Server

mcp = _Server("der-toolkit")
JOBS = JobManager()

Protocol = Literal["dnp3", "sunspec", "sep2"]


@mcp.tool()
def list_capabilities() -> dict[str, Any]:
    """List supported protocols, which operations each supports (discover / map /
    fuzz), default ports, and any credentials that unlock more of the surface."""
    return {
        "protocols": {
            "dnp3": {"discover": True, "map": True, "fuzz": True,
                     "port": 20000, "creds": None},
            "sunspec": {"discover": True, "map": True, "fuzz": True,
                        "port": 502,
                        "creds": None,
                        "note": "fuzz targets the device's Modbus/TCP server; a separate "
                                "client fuzzer for masters/clients is available via the "
                                "der-sunspec fuzz-client CLI (not exposed over MCP)"},
            "sep2": {"discover": True, "map": True, "fuzz": True,
                     "port": 15388,
                     "creds": "optional client_cert/client_key — a leaked cert "
                              "exposes the full self-describing surface"},
        }
    }


@mcp.tool()
def discover_targets(scope: list[str], protocol: Optional[Protocol] = None) -> list[dict]:
    """Discover DER endpoints within `scope` (IPs/CIDRs you are authorized to
    assess). READ-ONLY. If `protocol` is given, probe only that protocol,
    otherwise probe all three. Returns candidate targets."""
    for entry in scope:
        assert_in_scope(entry.split("/")[0], scope)  # validates form + non-empty scope
    return mappers.discover(scope, protocol=protocol)


@mcp.tool()
def map_attack_surface(protocol: Protocol, ip: str, authorized_scope: list[str],
                       port: Optional[int] = None, client_cert: Optional[str] = None,
                       client_key: Optional[str] = None, unit_id: Optional[int] = None) -> dict:
    """Map the unauthenticated attack surface of a single target. READ-ONLY and
    safe. Returns an AttackSurface: control points with semantic labels,
    read/write reachability, and severity. For sep2, supplying client_cert/key
    simulates a leaked-credential scenario and reveals the full self-describing
    surface. Returns {"found": false, ...} if no device answered."""
    assert_in_scope(ip, authorized_scope)
    surface = mappers.map_attack_surface(protocol, ip, port=port, client_cert=client_cert,
                                         client_key=client_key, unit_id=unit_id)
    if surface is None:
        return {"found": False, "protocol": protocol,
                "target": f"{ip}:{port or mappers.DEFAULT_PORTS[protocol]}"}
    return surface.model_dump()


@mcp.tool()
def start_fuzz(protocol: Protocol, ip: str, authorized_scope: list[str],
               port: Optional[int] = None, allow_disruptive: bool = False,
               opts: Optional[dict] = None) -> dict:
    """Start an async fuzz run against a target. DISRUPTIVE: can hang or crash
    live equipment, so it requires allow_disruptive=True and an in-scope target.
    Returns {job_id}. Poll with get_job, collect with get_findings."""
    assert_in_scope(ip, authorized_scope)
    require_disruptive_consent(allow_disruptive)
    port = port or mappers.DEFAULT_PORTS[protocol]
    argv = [sys.executable, "-m", "der_mcp.fuzz_runner",
            "--protocol", protocol, "--host", ip, "--port", str(port),
            "--opts", json.dumps(opts or {})]
    job_id = JOBS.start(argv, protocol=protocol, target=f"{ip}:{port}")
    return {"job_id": job_id, "state": "running", "target": f"{ip}:{port}"}


@mcp.tool()
def get_job(job_id: str) -> dict:
    """Status of a fuzz job: state (running/done/failed), target, run_dir, and a
    compact summary. No large artifacts inline."""
    return JOBS.status(job_id)


@mcp.tool()
def list_jobs() -> list[dict]:
    """List known fuzz jobs and their states."""
    return JOBS.list()


@mcp.tool()
def stop_job(job_id: str) -> dict:
    """Request a running fuzz job to stop."""
    return JOBS.stop(job_id)


@mcp.tool()
def get_findings(job_id: str) -> list[dict]:
    """Return the FuzzFindings for a job — compact records whose artifact_ref
    points into the job's run dir (never an inline blob)."""
    return JOBS.findings(job_id)


def main() -> None:
    """Console entry point (der-mcp). Runs the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
