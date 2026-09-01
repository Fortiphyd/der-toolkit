"""Regression coverage for the six flat 700-series SunSpec DER models
(701, 702, 703, 704, 713, 715) vendored via scripts/vendor_smdx_from_pysunspec2.py.

These were mechanically generated from pysunspec2's own resolved offsets
(cross-checked field-by-field against pysunspec2 with zero mismatches, and
704 verified end-to-end against a real Modbus/TCP round trip -- see
der_sunspec/smdx/NOTICE.md) rather than hand-transcribed. This file doesn't
re-depend on pysunspec2 being installed; it locks in the generated SMDX
files' own structural soundness and a few known field values, and exercises
the adapter's real decode path the same way any other vendored model is
tested.
"""

from der_sunspec.adapter import build_attack_surface
from der_sunspec.mapper import DeviceMapping, SunSpecModel
from der_sunspec.models_catalog import is_control_model
from der_sunspec.smdx_parser import load_model_def

FLAT_700_SERIES = [701, 702, 703, 704, 713, 715]


def test_all_six_models_load_and_are_structurally_sound():
    for mid in FLAT_700_SERIES:
        mdef = load_model_def(mid)
        assert mdef is not None, f"model {mid} failed to load"
        max_end = 0
        for p in mdef.points:
            assert p.offset + p.length <= mdef.length, (
                f"{mid}.{p.id} overruns block ({p.offset}+{p.length} > {mdef.length})")
            max_end = max(max_end, p.offset + p.length)
        assert max_end == mdef.length, f"model {mid}: declared length {mdef.length} != actual {max_end}"


def test_704_is_a_control_model_with_the_flagship_writable_field():
    assert is_control_model(704)
    mdef = load_model_def(704)
    by_id = {p.id: p for p in mdef.points}
    wmax = by_id["WMaxLimPct"]
    assert wmax.writable is True
    assert wmax.point_type == "uint16"
    assert wmax.units == "Pct"
    assert wmax.scale_factor_ref == "WMaxLimPct_SF"


def test_704_field_level_decode_over_a_synthetic_register_map():
    """Mirrors the live Modbus round trip this was validated against: an
    ENABLED enum, a scaled uint16 setpoint, and a negative int32 setpoint all
    decode correctly and the writable ones come back critical."""
    mdef = load_model_def(704)
    registers = [0] * mdef.length
    by_id = {p.id: p for p in mdef.points}

    pf_ena = by_id["PFWInjEna"]
    registers[pf_ena.offset] = 1  # ENABLED

    wmax = by_id["WMaxLimPct"]
    registers[wmax.offset] = 42

    wset = by_id["WSet"]  # int32, 2 registers
    neg = (-4242) & 0xFFFFFFFF
    registers[wset.offset] = neg >> 16
    registers[wset.offset + 1] = neg & 0xFFFF

    model = SunSpecModel(id=704, start=4, length=mdef.length, registers=registers)
    mapping = DeviceMapping(host="127.0.0.1", unit_id=1, sunspec_base=0, models=[model])
    surf = build_attack_surface(mapping)
    by_model = {cp.model: cp for cp in surf.control_points}

    pf_cp = by_model["SunSpec 704.PFWInjEna"]
    assert pf_cp.value == "ENABLED"
    assert pf_cp.writable is True
    assert pf_cp.severity == "critical"

    wmax_cp = by_model["SunSpec 704.WMaxLimPct"]
    assert wmax_cp.value == 42
    assert wmax_cp.severity == "critical"

    wset_cp = by_model["SunSpec 704.WSet"]
    assert wset_cp.value == -4242
    assert wset_cp.severity == "critical"

    assert any("Writable DER control models reachable" in f.title for f in surf.findings)
    assert not any("lack a vendored field-level definition" in f.title for f in surf.findings)


def test_701_uint64_energy_accumulator_decodes_as_a_single_integer():
    """701 ("DER AC Measurement") is the model that needed uint64/acc64
    decode support added to _decode_point -- without it this field would
    fall through to a raw 4-register list instead of one integer."""
    mdef = load_model_def(701)
    by_id = {p.id: p for p in mdef.points}
    tot = by_id["TotWhInj"]
    assert tot.point_type == "uint64"
    assert tot.length == 4

    registers = [0] * mdef.length
    value = 0x1_0002_0003
    registers[tot.offset] = (value >> 48) & 0xFFFF
    registers[tot.offset + 1] = (value >> 32) & 0xFFFF
    registers[tot.offset + 2] = (value >> 16) & 0xFFFF
    registers[tot.offset + 3] = value & 0xFFFF

    model = SunSpecModel(id=701, start=4, length=mdef.length, registers=registers)
    mapping = DeviceMapping(host="127.0.0.1", unit_id=1, sunspec_base=0, models=[model])
    surf = build_attack_surface(mapping)
    cp = next(cp for cp in surf.control_points if cp.model == "SunSpec 701.TotWhInj")
    assert cp.value == value
