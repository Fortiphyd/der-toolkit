"""Parser for SunSpec Alliance SMDX model definitions (see der_sunspec/smdx/NOTICE.md).

SMDX gives each model's individual points: offset, register length, type,
read/write access, units, scale-factor reference, and enum symbols. This is
what lets the adapter emit one ControlPoint per writable register (e.g.
"WMaxLimPct" at model 123 offset 3) instead of one coarse point per model.

Only models with a vendored smdx_<id>.xml get field-level detail;
load_model_def() returns None for everything else so the adapter can fall
back to its existing model-level ControlPoint.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import cache
from importlib import resources


@dataclass
class PointDef:
    id: str
    offset: int
    length: int
    point_type: str
    access: str  # raw SMDX attribute, typically "r" or "rw"
    mandatory: bool
    units: str | None = None
    scale_factor_ref: str | None = None
    symbols: dict[int, str] = field(default_factory=dict)
    label: str | None = None

    @property
    def writable(self) -> bool:
        return self.access.lower() in ("rw", "w")


@dataclass
class ModelDef:
    id: int
    length: int
    points: list[PointDef]


_DOUBLE_REGISTER_TYPES = {"acc32", "uint32", "int32", "bitfield32", "float32"}


def _parse_xml(xml_bytes: bytes) -> ModelDef:
    root = ET.fromstring(xml_bytes)
    model_el = root.find("model")
    model_id = int(model_el.get("id"))
    block_el = model_el.find("block")
    block_len = int(block_el.get("len"))

    labels: dict[str, str] = {}
    strings_el = root.find("strings")
    if strings_el is not None:
        for p_el in strings_el.findall("point"):
            label_el = p_el.find("label")
            if label_el is not None and label_el.text:
                labels[p_el.get("id")] = label_el.text.strip()

    points = []
    for p_el in block_el.findall("point"):
        symbols = {}
        for s_el in p_el.findall("symbol"):
            if s_el.text and s_el.text.strip().lstrip("-").isdigit():
                symbols[int(s_el.text.strip())] = s_el.get("id")
        point_type = p_el.get("type")
        # SMDX omits len= on some 32-bit points (e.g. model 103's WH/acc32),
        # relying on the type name to imply width -- default from type, not "1".
        default_len = 2 if point_type in _DOUBLE_REGISTER_TYPES else 1
        points.append(PointDef(
            id=p_el.get("id"),
            offset=int(p_el.get("offset")),
            length=int(p_el.get("len", str(default_len))),
            point_type=point_type,
            access=p_el.get("access", "r"),
            mandatory=p_el.get("mandatory", "false").lower() == "true",
            units=p_el.get("units"),
            scale_factor_ref=p_el.get("sf"),
            symbols=symbols,
            label=labels.get(p_el.get("id")),
        ))
    return ModelDef(id=model_id, length=block_len, points=points)


@cache
def load_model_def(model_id: int) -> ModelDef | None:
    """Load and cache the SMDX definition for a model id, or None if we don't
    vendor one for it (see der_sunspec/smdx/NOTICE.md for coverage)."""
    name = f"smdx_{model_id:05d}.xml"
    try:
        data = resources.files("der_sunspec").joinpath("smdx", name).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError):
        return None
    try:
        return _parse_xml(data)
    except ET.ParseError:
        return None
