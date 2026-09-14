"""der_dnp3.adapter decides which object groups are "operable output" (an
attacker can actuate them via CROB/analog-output commands) versus routine
telemetry. Locks in that severity distinction using the same object-model
shape the scanner produces against a real outstation (g10/g12/g40/g41).
"""

from der_dnp3.adapter import build_attack_surfaces


def _hdr(group: int, name: str, variation: int = 2, rng=None) -> dict:
    return {"group": group, "group_name": name, "variation": variation,
            "qualifier": "0x0", "range": rng or {"start": 0, "stop": 0}}


def _scan_doc(headers, outstation_addr=10, master_addr=1, unsolicited=None) -> dict:
    return {
        "cidr": "127.0.0.1/32", "ok": 1, "port": 20000,
        "results": [{
            "ok": True, "ip": "127.0.0.1", "port": 20000,
            "outstation_addr": outstation_addr, "master_addr": master_addr,
            "class0": {"headers": headers},
            "unsolicited_seen": unsolicited or [],
        }],
    }


def test_output_groups_are_critical_and_writable():
    headers = [
        _hdr(1, "Binary Input"), _hdr(10, "Binary Output Status"),
        _hdr(12, "Binary Output Command"), _hdr(30, "Analog Input"),
        _hdr(40, "Analog Output Status"), _hdr(41, "Analog Output Command"),
    ]
    surf = build_attack_surfaces(_scan_doc(headers))[0]
    by_addr = {cp.address: cp for cp in surf.control_points}

    assert by_addr["g1v2"].writable is False
    assert by_addr["g1v2"].severity == "low"
    assert by_addr["g30v2"].writable is False
    assert by_addr["g30v2"].severity == "low"

    for addr in ("g10v2", "g12v2", "g40v2", "g41v2"):
        cp = by_addr[addr]
        assert cp.writable is True, addr
        assert cp.severity == "critical", addr
        assert cp.reachable_unauthenticated is True, addr


def test_file_control_is_writable_but_not_conflated_with_critical_actuation():
    surf = build_attack_surfaces(_scan_doc([_hdr(70, "File Control", variation=0)]))[0]
    cp = surf.control_points[0]
    assert cp.writable is True
    assert cp.severity == "high"


def test_secure_auth_group_present_is_not_elevated_on_its_own():
    surf = build_attack_surfaces(_scan_doc([_hdr(120, "Authentication", variation=0)]))[0]
    cp = surf.control_points[0]
    assert cp.writable is False
    assert cp.severity == "info"
    assert any("Secure Authentication objects present" in f.title for f in surf.findings)


def test_operable_output_finding_only_fires_when_an_output_group_is_present():
    with_output = build_attack_surfaces(
        _scan_doc([_hdr(1, "Binary Input"), _hdr(12, "Binary Output Command")]))[0]
    assert any("Controllable output points reachable" in f.title for f in with_output.findings)

    measurement_only = build_attack_surfaces(_scan_doc([_hdr(1, "Binary Input")]))[0]
    assert not any("Controllable output points reachable" in f.title
                   for f in measurement_only.findings)


def test_writable_reachable_headline_only_includes_writable_points():
    headers = [_hdr(1, "Binary Input"), _hdr(12, "Binary Output Command")]
    surf = build_attack_surfaces(_scan_doc(headers))[0]
    assert [cp.address for cp in surf.writable_reachable()] == ["g12v2"]


def test_unreachable_outstation_is_skipped():
    doc = _scan_doc([_hdr(1, "Binary Input")])
    doc["results"][0]["ok"] = False
    assert build_attack_surfaces(doc) == []
