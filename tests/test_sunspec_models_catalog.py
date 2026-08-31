"""Regression test for a real gap found by auditing an MCP client's response
against a live target: models 303/304/307 had vendored SMDX field-level defs
(so real decoded values came through fine) but MODEL_NAMES had no entry for
them, so model_name() fell back to the generic "SunSpec Model N" for the
model-level part of every field's semantic_label. The AI filled that gap
correctly from its own SunSpec domain knowledge -- but the next model ID
might not get a lucky correct guess. This locks in that every model we ship
an SMDX definition for also has a real name, so the fallback path is never
silently reached for a model we can actually decode.
"""

import re
from pathlib import Path

from der_sunspec.models_catalog import MODEL_NAMES, model_name

SMDX_DIR = Path(__file__).resolve().parent.parent / "der_sunspec" / "smdx"


def _vendored_model_ids() -> set[int]:
    ids = set()
    for f in SMDX_DIR.glob("smdx_*.xml"):
        m = re.match(r"smdx_0*(\d+)\.xml$", f.name)
        if m:
            ids.add(int(m.group(1)))
    return ids


def test_vendored_smdx_bundle_is_not_empty():
    # Sanity check on the fixture-discovery glob itself, so a path/rename
    # mistake fails loudly here instead of silently passing an empty set below.
    assert len(_vendored_model_ids()) > 50


def test_every_vendored_smdx_model_has_a_real_name():
    missing = sorted(mid for mid in _vendored_model_ids() if mid not in MODEL_NAMES)
    assert not missing, f"model IDs with SMDX defs but no catalog name: {missing}"


def test_model_name_never_falls_back_for_a_vendored_id():
    for mid in _vendored_model_ids():
        assert model_name(mid) != f"SunSpec Model {mid}"


def test_model_name_falls_back_gracefully_for_a_truly_unknown_id():
    assert model_name(999999) == "SunSpec Model 999999"


def test_spot_check_labels_found_missing_this_session():
    assert model_name(303) == "Back of Module Temperature"
    assert model_name(304) == "Inclinometer"
    assert model_name(307) == "Base Met (Weather Station)"
    assert model_name(401) == "String Combiner"
