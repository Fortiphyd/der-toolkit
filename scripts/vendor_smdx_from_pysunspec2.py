#!/usr/bin/env python3
"""One-time vendoring script: generate der_sunspec/smdx/smdx_<id>.xml for the
flat (non-repeating-group) SunSpec 700-series DER models.

Uses pysunspec2's own Model class to resolve each field's offset/length --
not hand-transcribed from a webpage -- so the generated files carry the
reference implementation's own offset math as their source of truth. Run
with the 'sunspec' extra installed:

    python scripts/vendor_smdx_from_pysunspec2.py

Only covers models with NO runtime-determined repeating group: 701, 702,
703, 704, 713, 715. The remaining 700-series models (705-712, 714) use
repeating Crv/Ctl/Prt curve-table groups whose length pysunspec2 can't
resolve without a live device telling it the count -- der_sunspec's
ModelDef/PointDef has no concept of a repeating group at all, and forcing a
guessed fixed count through this converter would silently misdecode every
field after the curve table on any real device with a different actual
count. Deliberately not attempted here; see der_sunspec/smdx/NOTICE.md.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.sax.saxutils import escape

try:
    from sunspec2.device import Model
except ImportError:
    print("error: pip install -e '.[sunspec]' (needs pysunspec2)", file=sys.stderr)
    sys.exit(1)

FLAT_MODEL_IDS = [701, 702, 703, 704, 713, 715]
OUT_DIR = Path(__file__).resolve().parent.parent / "der_sunspec" / "smdx"

# pysunspec2 numbers offsets from the model's own ID/L header (2 registers);
# der_sunspec's convention (matching every other vendored file) numbers
# offset 0 as the first byte of the data block, i.e. right after that header
# -- see der_sunspec/mapper.py's SunSpecModel.start, which already points
# past ID/L. Skip the header points entirely and shift everything by -2.
HEADER_POINTS = {"ID", "L"}


def _points(model_id: int) -> list[tuple[str, object]]:
    m = Model(model_id=model_id)
    pts = [(name, p) for name, p in m.points.items() if name not in HEADER_POINTS]
    pts.sort(key=lambda np: np[1].offset)
    return pts


def convert(model_id: int) -> str:
    points = _points(model_id)
    block_len = max(p.offset - 2 + p.len for _, p in points)

    lines = ['<sunSpecModels v="1">',
             f'  <model id="{model_id}" len="{block_len}">',
             f'    <block len="{block_len}" type="fixed">']

    for name, p in points:
        pdef = p.pdef
        offset = p.offset - 2
        access = (pdef.get("access") or "R").lower()
        mandatory = "true" if pdef.get("mandatory") else "false"
        attrs = [f'id="{name}"', f'offset="{offset}"', f'access="{access}"',
                 f'type="{pdef.get("type")}"', f'len="{p.len}"', f'mandatory="{mandatory}"']
        units = pdef.get("units")
        if units:
            attrs.append(f'units="{escape(units)}"')
        sf = pdef.get("sf")
        if sf:
            attrs.append(f'sf="{sf}"')
        symbols = pdef.get("symbols") or []
        if symbols:
            lines.append(f'      <point {" ".join(attrs)}>')
            for s in symbols:
                lines.append(f'        <symbol id="{s["name"]}">{s["value"]}</symbol>')
            lines.append('      </point>')
        else:
            lines.append(f'      <point {" ".join(attrs)} />')

    lines += ['    </block>', '  </model>', f'  <strings id="{model_id}" locale="en">']
    for name, p in points:
        label = escape(p.pdef.get("label") or name)
        desc = escape(p.pdef.get("desc") or "")
        lines += [f'    <point id="{name}">', f'      <label>{label}</label>',
                  f'      <description>{desc}</description>', '    </point>']
    lines += ['  </strings>', '</sunSpecModels>']
    return "\n".join(lines) + "\n"


def main() -> None:
    for mid in FLAT_MODEL_IDS:
        out_path = OUT_DIR / f"smdx_{mid:05d}.xml"
        out_path.write_text(convert(mid))
        print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
