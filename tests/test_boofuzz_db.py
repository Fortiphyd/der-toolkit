"""der_common.boofuzz_db is shared by der_dnp3 and der_sunspec to turn a
boofuzz result sqlite db into structured FuzzFinding[]. This session validated
it manually against real result DBs (including a 500MB/460k-case one, and one
with real crashes); this builds a tiny synthetic db matching boofuzz's own
schema so the same parsing logic is checked on every run without needing
boofuzz installed or a multi-hundred-MB fixture checked into the repo.
"""

import sqlite3

from der_common.boofuzz_db import parse_boofuzz_db, summarize_boofuzz_db


def _make_db(path, cases):
    """cases: list of (name, steps) where steps is a list of
    (type, description, data) tuples, e.g. ("fail", "target unresponsive", None)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE cases (number INTEGER, name TEXT, timestamp TEXT)")
        conn.execute("""CREATE TABLE steps (test_case_index INTEGER, type TEXT,
                         description TEXT, data BLOB, timestamp TEXT, is_truncated INTEGER)""")
        for idx, (name, steps) in enumerate(cases, start=1):
            conn.execute("INSERT INTO cases VALUES (?, ?, ?)", (idx, name, "2026-01-01"))
            for step_type, desc, data in steps:
                conn.execute("INSERT INTO steps VALUES (?, ?, ?, ?, ?, ?)",
                             (idx, step_type, desc, data, "2026-01-01", 0))
        conn.commit()
    finally:
        conn.close()


def test_summarize_counts_total_and_crashed_cases(tmp_path):
    db = tmp_path / "run.db"
    _make_db(db, [
        ("case_a:[x:1]", [("send", None, b"\x01"), ("receive", None, b"\x02"), ("pass", None, None)]),
        ("case_b:[x:2]", [("send", None, b"\x03"), ("receive", None, b"\x04"), ("pass", None, None)]),
        ("case_c:[x:3]", [("send", None, b"\xde\xad"), ("fail", "target unresponsive", None)]),
    ])
    summary = summarize_boofuzz_db(db)
    assert summary == {"total_cases": 3, "crashed_cases": 1}


def test_parse_extracts_finding_details(tmp_path):
    db = tmp_path / "run.db"
    _make_db(db, [
        ("case_a:[x:1]", [("send", None, b"\x01"), ("receive", None, b"\x02"), ("pass", None, None)]),
        ("case_c:[x:3]", [("send", None, b"\xde\xad\xbe\xef"),
                          ("receive", None, b"\x00"),
                          ("fail", "target unresponsive", None)]),
    ])
    findings = parse_boofuzz_db(db)
    assert len(findings) == 1

    f = findings[0]
    assert f.crashed is True
    assert f.severity == "critical"
    assert "case_c:[x:3]" in f.title
    assert "deadbeef" in f.input_summary
    assert "target unresponsive" in f.input_summary
    assert f.artifact_ref == f"{db}#case=2"


def test_no_crashes_returns_no_findings(tmp_path):
    db = tmp_path / "run.db"
    _make_db(db, [
        ("case_a:[x:1]", [("send", None, b"\x01"), ("receive", None, b"\x02"), ("pass", None, None)]),
    ])
    assert parse_boofuzz_db(db) == []
    assert summarize_boofuzz_db(db) == {"total_cases": 1, "crashed_cases": 0}


def test_max_crashes_truncates_findings_without_hiding_the_true_count(tmp_path):
    """The CLI/MCP layers rely on diffing summarize()'s crashed_cases against
    len(parse_boofuzz_db(..., max_crashes=N)) to report "N more not parsed" --
    truncation must never be silent."""
    db = tmp_path / "run.db"
    cases = [
        (f"case_{i}:[x:{i}]", [("send", None, bytes([i])), ("fail", "crash", None)])
        for i in range(5)
    ]
    _make_db(db, cases)

    summary = summarize_boofuzz_db(db)
    assert summary["crashed_cases"] == 5

    truncated = parse_boofuzz_db(db, max_crashes=2)
    assert len(truncated) == 2
    dropped = summary["crashed_cases"] - len(truncated)
    assert dropped == 3
