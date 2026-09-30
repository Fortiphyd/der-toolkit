"""Parse boofuzz result databases into structured der_common.FuzzFinding records.

boofuzz's FuzzLoggerDb (boofuzz/fuzz_logger_db.py) logs every test case to sqlite:
a `cases` table (name, number, timestamp) and a `steps` table (test_case_index,
type, description, data, timestamp, is_truncated) where `type` is one of
step/check/info/send/receive/pass/fail/error. A `fail` step means a target
monitor (process/connection monitor) flagged the target as unresponsive or
crashed after that case's send -- that is boofuzz's own crash signal, not
something inferred here.

Only sqlite is required; boofuzz itself is not imported, so this can run
without the optional 'dnp3'/'sunspec' extras installed. Opened read-only so a
still-being-written db (e.g. inspected mid-run) is never corrupted.

Shared by der_dnp3 (outstation fuzzing) and der_sunspec (Modbus server
fuzzing) -- boofuzz's result schema is protocol-agnostic.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from der_common.schema import FuzzFinding

# Marker der_common.fuzz_monitor puts in its crash synopsis. boofuzz has one
# notion of failure, but "a process monitor watched the target die" and "the
# target hung up on us, which MIGHT be a dead handler" are very different
# levels of certainty, and only the first deserves to be called a crash.
# Defined here rather than in fuzz_monitor so this module stays importable
# without boofuzz; fuzz_monitor imports it from here.
CONNECTION_DROP_MARKER = "closed the connection without responding"


def _hex_preview(data: object, limit: int = 64) -> str:
    if not data:
        return ""
    b = bytes(data)
    return b[:limit].hex() + ("..." if len(b) > limit else "")


def _first(cur: sqlite3.Cursor, sql: str, params: tuple) -> object | None:
    row = cur.execute(sql, params).fetchone()
    return row[0] if row else None


def parse_boofuzz_db(db_path: str | Path, max_crashes: int | None = None) -> list[FuzzFinding]:
    """Return one FuzzFinding per test case boofuzz flagged with a `fail` step.

    The case name (e.g. "dnp3_qual_08_count_2b:[...count:65535]") already
    identifies which fuzzed field triggered the crash. `artifact_ref` points
    back at the specific case inside the db so the full send/receive/step
    trail can be pulled up without inlining it here.
    """
    db_path = Path(db_path)
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = conn.cursor()
        fail_idxs = [row[0] for row in cur.execute(
            "SELECT DISTINCT test_case_index FROM steps WHERE type='fail' ORDER BY test_case_index"
        )]
        if max_crashes is not None:
            fail_idxs = fail_idxs[:max_crashes]

        findings = []
        for idx in fail_idxs:
            case_name = _first(cur, "SELECT name FROM cases WHERE number=?", (idx,)) or f"case #{idx}"
            fail_desc = _first(
                cur, "SELECT description FROM steps WHERE test_case_index=? AND type='fail' LIMIT 1", (idx,)
            ) or "target monitor reported a failure"
            send = _first(
                cur, "SELECT data FROM steps WHERE test_case_index=? AND type='send' ORDER BY rowid LIMIT 1", (idx,)
            )
            recv = _first(
                cur, "SELECT data FROM steps WHERE test_case_index=? AND type='receive' ORDER BY rowid LIMIT 1",
                (idx,)
            )
            dropped = CONNECTION_DROP_MARKER in str(fail_desc)
            findings.append(FuzzFinding(
                title=(f"target dropped connection: {case_name}" if dropped
                       else f"boofuzz crash: {case_name}"),
                input_summary=f"send={_hex_preview(send)} -- {fail_desc}",
                response_summary=_hex_preview(recv) or None,
                # A dropped connection is evidence, not a confirmed crash: a
                # well-built server may hang up on malformed input by design
                # (pymodbus does). Worth investigating, not worth claiming.
                crashed=not dropped,
                severity="high" if dropped else "critical",
                artifact_ref=f"{db_path}#case={idx}",
            ))
        return findings
    finally:
        conn.close()


def summarize_boofuzz_db(db_path: str | Path) -> dict:
    """Cheap totals without materializing every case: how many cases ran and
    how many were flagged as crashes."""
    db_path = Path(db_path)
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = conn.cursor()
        total = _first(cur, "SELECT COUNT(*) FROM cases", ()) or 0
        crashed = _first(
            cur, "SELECT COUNT(DISTINCT test_case_index) FROM steps WHERE type='fail'", ()
        ) or 0
        return {"total_cases": total, "crashed_cases": crashed}
    finally:
        conn.close()
