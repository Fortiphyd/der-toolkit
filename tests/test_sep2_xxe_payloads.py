"""Regression test for a real false-negative found by live-testing der-sep2
fuzz against a server with XXE deliberately enabled: xxe_file_payloads() only
ever wrapped the entity in a LogEvent/details field, which that server's
routes never read back, so entity resolution happened but nothing echoed it
-- 390 payloads sent, zero detections, despite a confirmed real vulnerability
(verified manually with curl). Every file target must now be tried in every
shape a real 2030.5 "resource created" response commonly echoes back.
"""

from der_sep2.fuzzing.xml_payloads import VulnClass, xxe_file_payloads

REFLECTED_FIELD_BY_SHAPE = {
    "logevent": b"<details>",
    "enddevice": b"<lFDI>",
    "subscription": b"<subscribedResource>",
}


def _shape_of(name: str) -> str:
    for shape in REFLECTED_FIELD_BY_SHAPE:
        if f"_{shape}_" in name or name.endswith(f"_{shape}"):
            return shape
    raise AssertionError(f"payload name has no recognizable shape: {name!r}")


def test_all_payloads_are_xxe_file_class():
    for p in xxe_file_payloads():
        assert p.vuln_class == VulnClass.XXE_FILE


def test_every_shape_is_represented():
    shapes_seen = {_shape_of(p.name) for p in xxe_file_payloads()}
    assert shapes_seen == set(REFLECTED_FIELD_BY_SHAPE)


def test_body_actually_contains_the_field_its_shape_claims_to_reflect():
    """The real bug wasn't a missing shape name -- it was the entity landing
    in a field nobody reads back. This checks the payload body itself, not
    just its label."""
    for p in xxe_file_payloads():
        shape = _shape_of(p.name)
        assert REFLECTED_FIELD_BY_SHAPE[shape] in p.body, (
            f"{p.name} is labeled {shape!r} but its body doesn't contain "
            f"{REFLECTED_FIELD_BY_SHAPE[shape]!r}"
        )


def test_entity_reference_survives_unescaped():
    """If payload construction ever starts XML-escaping the entity reference
    (e.g. via a templating change), the parser would see literal text instead
    of an entity to resolve, and the vulnerability becomes untestable."""
    for p in xxe_file_payloads():
        assert b"&amp;xxe;" not in p.body
        assert b"&amp;exfil;" not in p.body
        assert (b"&xxe;" in p.body) or (b"&exfil;" in p.body)


def test_every_target_file_covered_in_every_shape():
    file_payloads = [p for p in xxe_file_payloads() if p.name.startswith("xxe_file_")]
    targets = {p.name.split("_", 3)[-1] for p in file_payloads}
    assert len(targets) >= 5  # /etc/passwd, /etc/hosts, environ, TLS key, win.ini
    for target in targets:
        shapes_for_target = {_shape_of(p.name) for p in file_payloads if p.name.endswith(target)}
        assert shapes_for_target == set(REFLECTED_FIELD_BY_SHAPE), (
            f"target {target!r} is missing shape(s): "
            f"{set(REFLECTED_FIELD_BY_SHAPE) - shapes_for_target}"
        )
