"""End-to-end smoke test for the demo cluster (demo/cluster.py).

Starts all 7 simulated devices, runs the real installed CLI commands against
them exactly as the demo README instructs, and asserts on the specific
finding/point counts documented there. This is what protects the demo from
silently rotting as der_dnp3/der_sunspec/der_sep2 change -- a change that
alters what a mapper reports should break this test, not surface for the
first time during a live recording.

Marked `integration`: it spawns real subprocesses and binds real ports, so
it's excluded from the fast unit-test run and given its own CI step instead.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo"

sys.path.insert(0, str(DEMO_DIR))
from cluster import DEVICES, ensure_sep2_certs, start_all, stop_all  # noqa: E402

CERTS_DIR = DEMO_DIR / "sep2_server" / "certs"


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    ensure_sep2_certs()
    procs = start_all()
    try:
        yield
    finally:
        stop_all(procs)


def _run_map(cli: str, target: str, *extra_args: str, out: Path) -> dict:
    subprocess.run(
        [cli, "map", target, *extra_args, "--output", str(out)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
        timeout=60,
    )
    return json.loads(out.read_text())


def _writable_addresses(surface: dict) -> set[str]:
    return {
        cp["address"]
        for cp in surface["control_points"]
        if cp["writable"] and cp["reachable_unauthenticated"]
    }


def _sep2_args() -> list[str]:
    return [
        "--client-cert", str(CERTS_DIR / "client_registered.crt"),
        "--client-key", str(CERTS_DIR / "client_registered.key"),
        "--ca-bundle", str(CERTS_DIR / "ca.crt"),
    ]


def test_classic_pv_inverter(cluster, tmp_path):
    data = _run_map("der-sunspec", "127.0.10.1", "--port", "502", out=tmp_path / "out.json")
    surface = data["attack_surfaces"][0]
    assert len(_writable_addresses(surface)) == 22


def test_der_compliant_inverter(cluster, tmp_path):
    data = _run_map("der-sunspec", "127.0.10.2", "--port", "502", out=tmp_path / "out.json")
    surface = data["attack_surfaces"][0]
    assert len(_writable_addresses(surface)) == 33


def test_telemetry_storage_device(cluster, tmp_path):
    data = _run_map("der-sunspec", "127.0.10.3", "--port", "502", out=tmp_path / "out.json")
    surface = data["attack_surfaces"][0]
    assert len(_writable_addresses(surface)) == 4


def test_protection_relay(cluster, tmp_path):
    data = _run_map(
        "der-dnp3", "127.0.20.1", "--port", "20000", "--listen-seconds", "6",
        out=tmp_path / "out.json",
    )
    surface = data["attack_surfaces"][0]
    assert _writable_addresses(surface) == {"g10v2"}


def test_setpoint_controller(cluster, tmp_path):
    data = _run_map(
        "der-dnp3", "127.0.20.2", "--port", "20000", "--listen-seconds", "6",
        out=tmp_path / "out.json",
    )
    surface = data["attack_surfaces"][0]
    assert _writable_addresses(surface) == {"g40v1"}


def test_sep2_hardened_has_no_high_or_critical_findings(cluster, tmp_path):
    data = _run_map(
        "der-sep2", "127.0.30.1", "--port", "15388", *_sep2_args(),
        out=tmp_path / "out.json",
    )
    surface = data["attack_surfaces"][0]
    severities = {f["severity"] for f in surface["findings"]}
    assert "high" not in severities and "critical" not in severities
    # /dcap alone (info-severity) -- the DER control surface stays gated.
    assert _writable_addresses(surface) == {"/dcap"}


def test_sep2_vulnerable_flags_the_open_der_control_surface(cluster, tmp_path):
    data = _run_map(
        "der-sep2", "127.0.30.2", "--port", "15388", *_sep2_args(),
        out=tmp_path / "out.json",
    )
    surface = data["attack_surfaces"][0]
    high_titles = {
        f["title"] for f in surface["findings"] if f["severity"] == "high"
    }
    assert high_titles == {
        "Resource accessible without client certificate: /edev/0/der",
        "Resource accessible without client certificate: /edev/0/der/0/ctrl",
        "Resource accessible without client certificate: /edev/1/der",
        "Resource accessible without client certificate: /edev/1/der/0/ctrl",
    }
    # Same 4 endpoints show up as writable+reachable control points too, plus
    # the always-present /dcap (info-severity) every SEP2 target reports.
    assert _writable_addresses(surface) == {
        "/dcap", "/edev/0/der", "/edev/0/der/0/ctrl", "/edev/1/der", "/edev/1/der/0/ctrl",
    }


def test_full_cluster_report_matches_documented_totals(cluster, tmp_path):
    saved = []
    for label, protocol, host, port, _argv in DEVICES:
        out = tmp_path / f"{host}.json"
        if protocol == "sunspec":
            _run_map("der-sunspec", host, "--port", str(port), out=out)
        elif protocol == "dnp3":
            _run_map("der-dnp3", host, "--port", str(port),
                      "--listen-seconds", "6", out=out)
        else:
            _run_map("der-sep2", host, "--port", str(port), *_sep2_args(), out=out)
        saved.append(out)

    report_out = tmp_path / "report.json"
    subprocess.run(
        ["der-report", *[str(p) for p in saved], "--output", str(report_out)],
        cwd=REPO_ROOT, check=True, timeout=30,
    )
    summary = json.loads(report_out.read_text())

    assert summary["targets_assessed"] == 7
    assert len(summary["writable_reachable_points"]) == 67
    assert summary["by_protocol"] == {
        "sunspec": {"targets": 3, "writable_reachable": 59},  # 22 + 33 + 4
        "dnp3": {"targets": 2, "writable_reachable": 2},      # g10v2 + g40v1
        "sep2": {"targets": 2, "writable_reachable": 6},      # 1 (/dcap) + 5 (/dcap + 4 open DER)
    }
