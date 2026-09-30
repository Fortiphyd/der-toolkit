"""ResponseAnomalyMonitor decides, from the client side alone, whether a
silent test case is worth reporting. Getting this wrong in either direction
is costly: flag too eagerly and every fuzz run against a healthy device is
full of noise, flag too little and a remote run reports nothing no matter
what it did to the target.

The distinction it relies on is timeout (target ignored us, connection still
open) versus EOF (target hung up mid-exchange).
"""

import pytest

pytest.importorskip("boofuzz")

from der_common.boofuzz_db import CONNECTION_DROP_MARKER  # noqa: E402
from der_common.fuzz_monitor import RecvReasonMixin, ResponseAnomalyMonitor  # noqa: E402


class _Conn(RecvReasonMixin):
    pass


class _Target:
    def __init__(self, conn):
        self._target_connection = conn


class _Node:
    name = "some_field"


class _Session:
    def __init__(self, last_recv, last_send=b"\x01\x02"):
        self.last_recv = last_recv
        self.last_send = last_send
        self.fuzz_node = _Node()


def _check(recv_data, closed):
    conn = _Conn()
    conn._note_recv(recv_data, closed=closed)
    monitor = ResponseAnomalyMonitor()
    alive = monitor.post_send(target=_Target(conn), session=_Session(recv_data))
    return alive, monitor


def test_a_normal_response_is_not_flagged():
    alive, _ = _check(b"\x05\x64response", closed=False)
    assert alive is True


def test_silence_with_the_connection_still_open_is_not_flagged():
    # The target ignored the input -- a DNP3 CONFIRM, a frame for another
    # outstation, or mangled framing. Fuzzing produces a lot of this and it
    # is not a finding.
    alive, _ = _check(b"", closed=False)
    assert alive is True


def test_the_target_hanging_up_without_answering_is_flagged():
    alive, monitor = _check(b"", closed=True)
    assert alive is False
    assert CONNECTION_DROP_MARKER in monitor.get_crash_synopsis()
    assert "some_field" in monitor.get_crash_synopsis()


def test_a_closed_connection_that_still_returned_data_is_not_flagged():
    # We got what we asked for; the peer closing afterwards is irrelevant.
    alive, _ = _check(b"data", closed=True)
    assert alive is True
