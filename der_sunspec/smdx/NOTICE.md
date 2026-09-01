# SMDX model definitions

The `smdx_*.xml` files in this directory are the SunSpec Alliance's official
per-model register definitions (SMDX format): for each model ID they give the
name, offset, size, type, and read/write access of every individual point --
e.g. model 123 ("Immediate Controls") defines `WMaxLimPct` at offset 3 as a
writable `uint16` power-limit setpoint.

`der_sunspec/smdx_parser.py` reads these to give field-level control points
(one per writable register) instead of one coarse point per model. They are
data only -- no code from that distribution is used here. Vendored from a
local copy of the SunSpec Alliance's public `sunspec-models` distribution;
`LICENSE` in this directory is the license that shipped with that copy.

Coverage is whatever that distribution included as of its vintage: the
100/200/300/400/500/600/800-series models are present, but the newer
700-series DER models postdate it and were added separately -- see below.

## 700-series DER models (701, 702, 703, 704, 713, 715)

These six `smdx_007*.xml` files were generated from
[`pysunspec2`](https://pypi.org/project/pysunspec2/) (Apache-2.0; see
`LICENSE-pysunspec2` in this directory), not hand-transcribed from a
webpage. pysunspec2 ships the current SunSpec Alliance model definitions in
a newer JSON schema (nested groups, not flat offsets) that `smdx_parser.py`
doesn't understand -- `scripts/vendor_smdx_from_pysunspec2.py` uses
pysunspec2's own `Model` class to resolve each field's real offset/length
the same way the reference implementation would, then re-encodes that as a
flat SMDX file in this directory's existing schema. Every field's offset,
length, type, access, units, scale-factor reference, and enum symbols were
cross-checked field-by-field against pysunspec2's own resolved values with
zero mismatches, and model 704 was verified end-to-end against a real
Modbus/TCP round trip (32 writable control points correctly decoded,
including enum resolution and scale factors).

**Not covered: 705, 706, 707, 708, 709, 710, 711, 712, 714.** These use a
runtime-determined *repeating* group (a Volt-VAR/Volt-Watt/trip/Freq-Watt/
Watt-VAR/Enter-Service/Frequency-Droop curve table whose point count a real
device reports at read time) that pysunspec2 itself refuses to resolve
without a live device's count, and that `der_sunspec`'s `ModelDef`/
`PointDef` has no representation for at all -- they're flat-offset-only.
Forcing a guessed fixed count through the converter would produce a file
that looks legitimate but silently misdecodes every field after the curve
table on any real device whose curve doesn't match that guessed length,
which is worse than the current coarse model-level fallback. Supporting
these properly needs an actual repeating-group representation added to
`smdx_parser.py`/`adapter.py`, not just more vendored data.
