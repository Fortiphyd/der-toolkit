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
700-series DER models (704-714, referenced by ID/name in
`der_sunspec/models_catalog.py`) are not, since they postdate it. Those
models fall back to the coarse, model-level control point until current
definitions (e.g. from github.com/sunspec/models) are vendored in.
