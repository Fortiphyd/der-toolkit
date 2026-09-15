"""der_common.report merges multiple protocols' saved `map --output` files
into one severity-ranked view. These tests lock in the aggregation/ranking
logic without needing live targets.
"""

import json

from der_common.report import format_report, load_attack_surfaces, main, summarize
from der_common.schema import AttackSurface, AuthProfile, ControlPoint, Finding, Target


def _surface(protocol, ip, port, points, findings=None) -> AttackSurface:
    return AttackSurface(
        protocol=protocol,
        target=Target(ip=ip, port=port, protocol=protocol),
        auth_profile=AuthProfile(),
        control_points=points,
        findings=findings or [],
        generated_at="2026-01-01T00:00:00Z",
    )


def _cp(address, severity, writable=True, reachable=True, label=None, value=None):
    return ControlPoint(address=address, semantic_label=label or address, model=address,
                        readable=True, writable=writable, value=value,
                        severity=severity, reachable_unauthenticated=reachable)


def _write_surfaces(tmp_path, name, surfaces):
    path = tmp_path / name
    path.write_text(json.dumps({"attack_surfaces": [s.model_dump() for s in surfaces]}))
    return str(path)


def test_load_reads_the_shared_attack_surfaces_key(tmp_path):
    s = _surface("sunspec", "127.0.0.1", 502, [_cp("model1@68", "critical")])
    path = _write_surfaces(tmp_path, "sunspec.json", [s])
    loaded = load_attack_surfaces([path])
    assert len(loaded) == 1
    assert loaded[0].protocol == "sunspec"
    assert loaded[0].control_points[0].address == "model1@68"


def test_load_skips_files_with_no_attack_surfaces_key(tmp_path):
    path = tmp_path / "unrelated.json"
    path.write_text(json.dumps({"something_else": 1}))
    assert load_attack_surfaces([str(path)]) == []


def test_summarize_ranks_writable_points_across_protocols_by_severity():
    dnp3 = _surface("dnp3", "127.0.0.1", 20000, [
        _cp("g1v2", "low", writable=False),
        _cp("g12v2", "critical", label="Binary Output Command"),
    ])
    sunspec = _surface("sunspec", "127.0.0.1", 5503, [
        _cp("model1@68", "critical", label="Device Address"),
        _cp("model1@4", "low", writable=False, label="Manufacturer"),
    ])
    summary = summarize([dnp3, sunspec])

    assert summary["targets_assessed"] == 2
    points = summary["writable_reachable_points"]
    # Only the two critical, writable+reachable points -- not the read-only ones.
    assert len(points) == 2
    assert {p["address"] for p in points} == {"g12v2", "model1@68"}
    assert all(p["severity"] == "critical" for p in points)


def test_summarize_orders_by_severity_not_by_input_order():
    surf = _surface("dnp3", "127.0.0.1", 20000, [
        _cp("g1", "low"), _cp("g2", "critical"), _cp("g3", "high"), _cp("g4", "medium"), _cp("g5", "info"),
    ])
    summary = summarize([surf])
    severities = [p["severity"] for p in summary["writable_reachable_points"]]
    assert severities == ["critical", "high", "medium", "low", "info"]


def test_summarize_by_protocol_counts():
    dnp3 = _surface("dnp3", "127.0.0.1", 20000, [_cp("g12v2", "critical")])
    sunspec_a = _surface("sunspec", "127.0.0.1", 5503, [_cp("model1@68", "critical")])
    sunspec_b = _surface("sunspec", "127.0.0.2", 5503, [])
    summary = summarize([dnp3, sunspec_a, sunspec_b])
    assert summary["by_protocol"] == {
        "dnp3": {"targets": 1, "writable_reachable": 1},
        "sunspec": {"targets": 2, "writable_reachable": 1},
    }


def test_summarize_ranks_findings_across_surfaces():
    dnp3 = _surface("dnp3", "127.0.0.1", 20000, [], findings=[
        Finding(severity="info", title="unsolicited"),
        Finding(severity="critical", title="controllable outputs"),
    ])
    sunspec = _surface("sunspec", "127.0.0.1", 5503, [], findings=[
        Finding(severity="high", title="model map exposed"),
    ])
    summary = summarize([dnp3, sunspec])
    titles_in_order = [f["title"] for f in summary["findings"]]
    assert titles_in_order == ["controllable outputs", "model map exposed", "unsolicited"]


def test_format_report_handles_empty_results():
    summary = summarize([])
    text = format_report(summary)
    assert "(none)" in text
    assert "Targets assessed: 0" in text


def test_cli_merges_two_saved_files_and_exits_zero(tmp_path, capsys):
    dnp3 = _surface("dnp3", "127.0.0.1", 20000, [_cp("g12v2", "critical")])
    sunspec = _surface("sunspec", "127.0.0.1", 5503, [_cp("model1@68", "critical")])
    p1 = _write_surfaces(tmp_path, "dnp3.json", [dnp3])
    p2 = _write_surfaces(tmp_path, "sunspec.json", [sunspec])

    rc = main([p1, p2])
    assert rc == 0
    out = capsys.readouterr().out
    assert "g12v2" in out and "model1@68" in out


def test_cli_writes_structured_json_output(tmp_path):
    surf = _surface("dnp3", "127.0.0.1", 20000, [_cp("g12v2", "critical")])
    p1 = _write_surfaces(tmp_path, "dnp3.json", [surf])
    out_path = tmp_path / "summary.json"

    rc = main([p1, "--output", str(out_path)])
    assert rc == 0
    saved = json.loads(out_path.read_text())
    assert saved["targets_assessed"] == 1
    assert saved["writable_reachable_points"][0]["address"] == "g12v2"


def test_cli_fails_cleanly_with_no_attack_surfaces(tmp_path, capsys):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"attack_surfaces": []}))
    rc = main([str(path)])
    assert rc == 1
