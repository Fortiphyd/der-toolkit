"""Minimal, config-driven DNP3 outstation simulator.

Reuses der_dnp3.scanner's own tested link/transport/app framing primitives
(CRC, frame building, request/response parsing) rather than reimplementing
them, so the simulator and the real scanner/mapper agree on the wire format
by construction. Implements just enough of a real outstation to answer the
three reads der_dnp3/scanner.py's map/discover flow actually sends (g0v254,
g0v255, Class 0 / g60v1) with a static object-group database -- no link-layer
RESET_LINK_STATES handshake is needed for this flow (der_dnp3/scanner.py
sends its reads as unconfirmed link frames), matching what a live opendnp3
outstation was observed doing in this project's own live-target validation.
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from der_dnp3.scanner import (
    APP_FUNC_READ,
    APP_FUNC_RESPONSE,
    DNP3_START,
    QUAL_RANGE8,
    append_crc_le,
    build_app_control,
    build_link_control,
    build_transport_header,
    expected_total_frame_len,
    verify_crc_le,
)

LINK_FUNC_UNCONFIRMED_USER_DATA = 0x04


class Group:
    """One object group's static data: `count` points of `variation`, whose
    point size (bytes/point) is fixed by the DNP3 spec for that (group,
    variation) pair -- see der_dnp3.scanner.POINT_SIZE for the ones the
    mapper already knows how to skip over."""

    def __init__(self, group: int, variation: int, count: int, point_size: int, fill: int = 0x01):
        self.group = group
        self.variation = variation
        self.count = count
        self.point_size = point_size
        self.fill = fill

    def object_block(self) -> bytes:
        header = bytes([self.group, self.variation, QUAL_RANGE8, 0, self.count - 1])
        payload = bytes([self.fill]) * (self.count * self.point_size)
        return header + payload


def _build_link_frame(dest: int, src: int, user_data: bytes) -> bytes:
    ctrl = build_link_control(prm=1, dir_master_to_out=0, fcb=0, fcv=0,
                              func=LINK_FUNC_UNCONFIRMED_USER_DATA)
    length = 5 + len(user_data)
    header = DNP3_START + bytes([length & 0xFF, ctrl & 0xFF]) + struct.pack("<HH", dest & 0xFFFF, src & 0xFFFF)
    out = bytearray(append_crc_le(header))
    for i in range(0, len(user_data), 16):
        out += append_crc_le(user_data[i:i + 16])
    return bytes(out)


def _parse_link_frame(buf: bytes):
    if len(buf) < 10 or buf[0:2] != DNP3_START:
        return None
    length = buf[2]
    total_len = expected_total_frame_len(length)
    if len(buf) < total_len:
        return None, total_len
    hdr = buf[:10]
    if not verify_crc_le(hdr):
        return None, total_len
    dest, src = struct.unpack("<HH", buf[4:8])
    data_len = length - 5
    offset = 10
    remaining = data_len
    user_data = bytearray()
    while remaining > 0:
        take = min(16, remaining)
        block = buf[offset:offset + take + 2]
        if len(block) != take + 2 or not verify_crc_le(block):
            return None, total_len
        user_data += block[:-2]
        offset += take + 2
        remaining -= take
    return (dest, src, bytes(user_data)), total_len


class Outstation:
    def __init__(self, name: str, outstation_addr: int, groups: list[Group]):
        self.name = name
        self.outstation_addr = outstation_addr
        self.groups = groups

    def _class0_response(self, app_seq: int) -> bytes:
        app_ctrl = build_app_control(fin=1, fir=1, con=0, uns=0, seq=app_seq)
        iin = struct.pack("<H", 0)
        objects = b"".join(g.object_block() for g in self.groups)
        return bytes([app_ctrl, APP_FUNC_RESPONSE]) + iin + objects

    def _empty_response(self, app_seq: int) -> bytes:
        """For g0v254/g0v255 (device attribute list reads) -- respond
        immediately with no objects rather than let the scanner time out
        waiting for something we don't model."""
        app_ctrl = build_app_control(fin=1, fir=1, con=0, uns=0, seq=app_seq)
        return bytes([app_ctrl, APP_FUNC_RESPONSE]) + struct.pack("<H", 0)

    def _handle_request(self, conn: socket.socket, dest: int, src: int, user_data: bytes) -> None:
        if dest != self.outstation_addr:
            return  # not addressed to us
        if len(user_data) < 3:
            return
        # user_data = 1-byte transport header + app layer
        app = user_data[1:]
        app_ctrl, func = app[0], app[1]
        req_seq = app_ctrl & 0x0F
        if func != APP_FUNC_READ or len(app) < 5:
            return
        group, variation, qualifier = app[2], app[3], app[4]

        if (group, variation) == (60, 1):
            app_pdu = self._class0_response(req_seq)
        elif group == 0 and variation in (254, 255):
            app_pdu = self._empty_response(req_seq)
        else:
            app_pdu = self._empty_response(req_seq)

        transport = bytes([build_transport_header(fin=1, fir=1, seq=0)])
        frame = _build_link_frame(dest=src, src=self.outstation_addr, user_data=transport + app_pdu)
        conn.sendall(frame)

    def _serve_client(self, conn: socket.socket) -> None:
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
                    dest, src, user_data = result
                    del buf[:total_len]
                    self._handle_request(conn, dest, src, user_data)

    def serve(self, port: int, host: str = "127.0.0.1") -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        print(f"{self.name} -- DNP3 outstation (addr={self.outstation_addr}) "
              f"on {host}:{port} -- Ctrl-C to stop", flush=True)
        try:
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=self._serve_client, args=(conn,), daemon=True).start()
        finally:
            srv.close()
