#!/usr/bin/env python3
"""INTENTIONALLY VULNERABLE DNP3 outstation -- built for the fuzzing example
in demo/README.md, not part of the demo cluster (see demo/cluster.py). Not a
real bug in der_dnp3, in common.py's Outstation class, or in either of the
two outstations the main cluster actually uses (protection_relay.py,
setpoint_controller.py) -- neither of those implements this code path.

The bug: this outstation trusts the last byte of any application-layer
payload as a raw index into its point list, with no bounds check. Real DNP3
range/count/index fields (qualifiers 0x00/0x07/etc., see der_dnp3/fuzzer.py)
routinely land as the last byte or two of a short request, so this is a
close analog of a real, common DNP3 implementation bug class -- a
wire-supplied count/index used unsafely -- without trying to be a
byte-perfect reconstruction of one specific qualifier's framing (verified
empirically: der-dnp3 fuzz's per-message boofuzz definitions each carry a
short, self-contained payload -- their own first 3 bytes get consumed by
Dnp3TcpWrappedConnection's send_mode/len_mode/len_value header, not
delivered on the wire -- so a handler that insists on a specific,
byte-exact "valid-looking" request shape mostly never gets exercised. This
one deliberately doesn't care what the request means, only what its last
byte is, which is exactly the sloppy-but-realistic behavior this exists to
demonstrate.)

    python3 demo/dnp3_outstations/vulnerable_outstation.py [host] [port]
    # default 127.0.20.3:20000, outstation addr 10 (matches der-dnp3 fuzz's
    # own --outstation default, so the example command needs no extra flags)
"""

import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import _build_link_frame, _parse_link_frame

from der_dnp3.scanner import APP_FUNC_RESPONSE, build_app_control, build_transport_header

DEFAULT_HOST = "127.0.20.3"
DEFAULT_PORT = 20000
OUTSTATION_ADDR = 10

POINTS = [1, 0, 1, 0]  # deliberately small, fixed-size


def _response_VULNERABLE(req_seq: int, user_data: bytes) -> bytes:
    app_ctrl = build_app_control(fin=1, fir=1, con=0, uns=0, seq=req_seq)
    # VULNERABLE: the last byte of whatever arrived is used to index
    # POINTS with no bounds check -- no validation that it's even meant
    # as a count/index field, just "last byte in, list index out."
    value = POINTS[user_data[-1]]
    return bytes([app_ctrl, APP_FUNC_RESPONSE, value])


def _handle_request(conn: socket.socket, dest: int, src: int, user_data: bytes) -> None:
    if dest != OUTSTATION_ADDR or not user_data:
        return
    req_seq = user_data[0] & 0x0F
    app_pdu = _response_VULNERABLE(req_seq, user_data)
    transport = bytes([build_transport_header(fin=1, fir=1, seq=0)])
    frame = _build_link_frame(dest=src, src=OUTSTATION_ADDR, user_data=transport + app_pdu)
    conn.sendall(frame)


def _serve_client(conn: socket.socket) -> None:
    buf = bytearray()
    with conn:
        while True:
            try:
                chunk = conn.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while True:
                parsed = _parse_link_frame(bytes(buf))
                if parsed is None:
                    break
                result, total_len = parsed
                if result is None:
                    if len(buf) >= total_len:
                        del buf[:total_len]
                        continue
                    break
                dest, src, ud = result
                del buf[:total_len]
                _handle_request(conn, dest, src, ud)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f"*** INTENTIONALLY VULNERABLE DNP3 outstation (addr={OUTSTATION_ADDR}) "
          f"on {host}:{port} -- fuzzing example only, see demo/README.md ***", flush=True)
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=_serve_client, args=(conn,), daemon=True).start()
    finally:
        srv.close()


if __name__ == "__main__":
    main()
