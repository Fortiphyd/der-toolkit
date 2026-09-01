"""der_sunspec.adapter is where the tool's actual value proposition lives:
deciding which SunSpec register is a "writable, unauthenticated, critical"
finding versus routine telemetry. A regression here silently breaks the
headline result for every SunSpec target, in either direction (missing a
real writable point, or crying wolf on read-only telemetry).
"""

from der_sunspec.adapter import build_attack_surface
from der_sunspec.mapper import DeviceMapping, SunSpecModel


def _encode_string(s: str, num_regs: int) -> list[int]:
    b = (s.encode("ascii") + b"\x00" * (num_regs * 2))[: num_regs * 2]
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)]


def _model1_registers(manufacturer: str = "Acme Corp", da: int = 5) -> list[int]:
    """Layout matches smdx_00001.xml: Mn@0(16) Md@16(16) Opt@32(8) Vr@40(8)
    SN@48(16) DA@64(1) -- the same fields/offsets seen in this session's real
    live-target capture (model1@4 == start 4 + offset 0, etc.)."""
    regs = [0] * 66
    regs[0:16] = _encode_string(manufacturer, 16)
    regs[16:32] = _encode_string("Test Inverter", 16)
    regs[32:40] = _encode_string("", 8)
    regs[40:48] = _encode_string("1.0", 8)
    regs[48:64] = _encode_string("SN123", 16)
    regs[64] = da
    return regs


def _mapping(models, common_info=None):
    return DeviceMapping(host="127.0.0.1", unit_id=1, sunspec_base=0,
                         models=models, common_info=common_info)


def test_field_level_decode_and_writable_severity():
    model1 = SunSpecModel(id=1, start=4, length=66, registers=_model1_registers())
    surf = build_attack_surface(_mapping([model1]), generated_at="2026-01-01T00:00:00Z")
    by_model = {cp.model: cp for cp in surf.control_points}

    mn = by_model["SunSpec 1.Mn"]
    assert mn.value == "Acme Corp"
    assert mn.writable is False
    assert mn.severity == "low"

    da = by_model["SunSpec 1.DA"]
    assert da.value == 5
    assert da.writable is True
    assert da.severity == "critical"
    assert da.reachable_unauthenticated is True
    assert da.address == "model1@68"  # start(4) + offset(64), matches the real capture


def test_control_model_without_smdx_def_falls_back_to_coarse_critical_point():
    # 705 (Volt-VAR) is a writable control model per SunSpec's spec, but its
    # repeating curve-table group is deliberately not vendored (see
    # der_sunspec/smdx/NOTICE.md) -- the coarse fallback must still flag it
    # critical/writable rather than silently dropping the finding because
    # field-level decode isn't available.
    model705 = SunSpecModel(id=705, start=200, length=10, registers=None)
    surf = build_attack_surface(_mapping([model705]))
    cp = surf.control_points[0]
    assert cp.writable is True
    assert cp.severity == "critical"
    assert cp.model == "SunSpec 705"
    assert cp.semantic_label == "DER Volt-VAR"


def test_non_control_model_without_smdx_def_is_low_severity_read_only():
    unknown = SunSpecModel(id=999999, start=0, length=4, registers=None)
    surf = build_attack_surface(_mapping([unknown]))
    cp = surf.control_points[0]
    assert cp.writable is False
    assert cp.severity == "low"


def test_writable_reachable_headline_matches_only_the_writable_point():
    model1 = SunSpecModel(id=1, start=4, length=66, registers=_model1_registers())
    surf = build_attack_surface(_mapping([model1]))
    headline = surf.writable_reachable()
    assert [cp.model for cp in headline] == ["SunSpec 1.DA"]


def test_model_map_exposure_finding_always_present():
    model1 = SunSpecModel(id=1, start=4, length=66, registers=_model1_registers())
    surf = build_attack_surface(_mapping([model1]))
    assert any("self-describing model map" in f.title for f in surf.findings)


def test_undecoded_control_model_gets_its_own_gap_finding():
    model705 = SunSpecModel(id=705, start=200, length=10, registers=None)
    surf = build_attack_surface(_mapping([model705]))
    titles = [f.title for f in surf.findings]
    assert any("Writable DER control models reachable" in t for t in titles)
    assert any("lack a vendored field-level definition" in t for t in titles)
