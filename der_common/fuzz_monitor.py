"""A boofuzz Monitor that detects a target dropping connections, without
needing any access to the target host.

The problem this solves: boofuzz only records a crash when a Monitor says the
target failed, and its built-in monitors all need something running on or
beside the target (ProcessMonitor needs local process access, NetworkMonitor
is an RPC proxy to an agent you'd have to install). Against a real DER device
on someone else's network you have neither, so a fuzz run reports zero
crashes no matter what it actually did to the target.

What this watches instead is the difference between two kinds of silence,
which is visible from the client side alone:

  - The target ignores the input and leaves the connection open. Reading
    times out. This is normal and expected -- a DNP3 CONFIRM draws no reply
    by design, a frame addressed to another outstation is correctly ignored,
    and a mutation that mangles the framing gets dropped by any healthy
    device. Fuzzing produces a lot of this.

  - The target drops the connection without answering. Reading hits EOF.
    It accepted the request and then stopped talking mid-exchange, which is
    what a handler falling over looks like from the outside.

Only the second is flagged, and deliberately NOT as a confirmed crash. It is
evidence worth chasing, not proof: a well-built server is entitled to hang up
on input it doesn't like, and some do. Measured across the demo targets:

    defensive DNP3 outstation   0 drops / 45 cases   (times out instead)
    deliberately fragile DNP3   ~all cases dropped   (handler dies)
    pymodbus (healthy, mature)  28 drops / 1651      (hangs up by design)

That pymodbus number is why these are reported as "target dropped connection"
at high severity rather than a critical crash -- from the client side alone
those 28 are indistinguishable from a fragile device failing on 1.7% of
inputs, and claiming otherwise would be guessing. der_common.boofuzz_db keys
off CONNECTION_DROP_MARKER to label them accordingly.

This depends on the connection recording WHY a read came back empty, since a
plain socket read returns b"" for both cases. Connections that want to be
watched by this monitor set `last_recv_closed` after each read; see
`RecvReasonMixin` below.
"""

from __future__ import annotations

from boofuzz.monitors import BaseMonitor

from der_common.boofuzz_db import CONNECTION_DROP_MARKER


class RecvReasonMixin:
    """Record whether the last read came back empty because the peer closed
    the connection, as opposed to timing out with it still open.

    Connection classes mix this in and call `_note_recv` from `recv()`.
    ResponseAnomalyMonitor reads `last_recv_closed` off the connection.
    """

    last_recv_closed: bool = False

    def _note_recv(self, data: bytes, closed: bool) -> bytes:
        self.last_recv_closed = closed and not data
        return data


class ResponseAnomalyMonitor(BaseMonitor):
    """Flag a test case where the target closed the connection instead of
    answering."""

    def __init__(self):
        super().__init__()
        self._synopsis = ""

    def __str__(self) -> str:
        return "ResponseAnomalyMonitor"

    def post_send(self, target=None, fuzz_data_logger=None, session=None) -> bool:
        if session.last_recv:
            return True

        conn = getattr(target, "_target_connection", None)
        if not getattr(conn, "last_recv_closed", False):
            # Timed out with the connection still open: the target ignored
            # this input, which is normal.
            return True

        sent = session.last_send or b""
        node = getattr(session.fuzz_node, "name", "<unknown>")
        self._synopsis = (
            f"target {CONNECTION_DROP_MARKER} while fuzzing "
            f"'{node}' -- sent {len(sent)} bytes: {sent[:32].hex()}"
        )
        return False

    def get_crash_synopsis(self) -> str:
        return self._synopsis
