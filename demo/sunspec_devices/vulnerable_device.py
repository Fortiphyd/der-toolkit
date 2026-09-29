#!/usr/bin/env python3
"""INTENTIONALLY VULNERABLE Modbus/TCP device -- built for the fuzzing
example in demo/README.md, not part of the demo cluster (see
demo/cluster.py). Has nothing to do with pymodbus, which the three "real"
demo SunSpec devices use (see demo/sunspec_devices/common.py) -- pymodbus
is a mature, widely-deployed library and isn't a realistic fuzzing target
in a short demo. This is instead a small, hand-rolled Modbus/TCP server,
exactly the kind of naive implementation real cheap/embedded devices often
actually run.

The bug(s) -- two independent instances of the same root cause, trusting a
wire-supplied length/count field with no validation:
  - The MBAP header's `length` field is used to size the read of the PDU
    with no minimum check; a short/zero length leaves an empty PDU, and
    the very next line (`pdu[0]`) throws an unhandled IndexError. Fuzzing
    finds this one first, since `der-sunspec fuzz` mutates `length` before
    it gets to the fields below.
  - Handling Read Holding Registers (function code 0x03) itself, the
    request's start_add + number_of_regs fields directly index the
    register array with no bounds check -- request a range past the end
    of the 20-register array and it's the same IndexError, one level
    deeper.
Both are real, common classes of Modbus implementation bug (a wire-supplied
length/count used as a raw index or read size), not something pymodbus (or
this demo's other three SunSpec devices) does.

    python3 demo/sunspec_devices/vulnerable_device.py [host] [port]
    # default 127.0.10.4:502, unit_id 1 -- port 502 needs authbind, see
    # demo/README.md (same as the three real demo SunSpec devices)
"""

import socket
import struct
import sys
import threading

DEFAULT_HOST = "127.0.10.4"
DEFAULT_PORT = 502
UNIT_ID = 1

REGISTERS = list(range(20))  # deliberately small, fixed-size


def _read_holding_VULNERABLE(pdu: bytes) -> bytes:
    start_add, number_of_regs = struct.unpack(">HH", pdu[1:5])
    # VULNERABLE: start_add/number_of_regs came straight off the wire and
    # are used to index REGISTERS directly, with no bounds check.
    values = [REGISTERS[start_add + i] for i in range(number_of_regs)]
    payload = b"".join(struct.pack(">H", v) for v in values)
    return bytes([0x03, len(payload)]) + payload


def _handle_client(conn: socket.socket) -> None:
    with conn:
        while True:
            header = conn.recv(7)  # transaction(2) + protocol(2) + length(2) + unit_id(1)
            if len(header) < 7:
                return
            trans_id, _proto_id, length = struct.unpack(">HHH", header[:6])
            unit_id = header[6]

            pdu = b""
            while len(pdu) < length - 1:
                chunk = conn.recv(length - 1 - len(pdu))
                if not chunk:
                    return
                pdu += chunk

            func = pdu[0]
            if func == 0x03:
                resp_pdu = _read_holding_VULNERABLE(pdu)
            else:
                resp_pdu = bytes([func | 0x80, 0x01])  # illegal function

            mbap = struct.pack(">HHHB", trans_id, 0, len(resp_pdu) + 1, unit_id)
            conn.sendall(mbap + resp_pdu)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f"*** INTENTIONALLY VULNERABLE Modbus/TCP device on {host}:{port} "
          f"-- fuzzing example only, see demo/README.md ***", flush=True)
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()
    finally:
        srv.close()


if __name__ == "__main__":
    main()
