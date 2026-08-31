#!/usr/bin/env python3
from __future__ import annotations
import socket, struct, time
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Any, Iterable
import json
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


DNP3_GROUP_NAMES: Dict[int, str] = {
    0:   "Device Attributes",
    1:   "Binary Input",
    2:   "Binary Input Event",
    3:   "Double-bit Binary Input",
    4:   "Double-bit Binary Input Event",
    10:  "Binary Output",
    11:  "Binary Output Event",
    12:  "Binary Output Command",
    20:  "Counter",
    21:  "Frozen Counter",
    22:  "Counter Event",
    23:  "Frozen Counter Event",
    30:  "Analog Input",
    31:  "Frozen Analog Input",
    32:  "Analog Input Event",
    33:  "Frozen Analog Input Event",
    40:  "Analog Output Status",
    41:  "Analog Output Command",
    42:  "Analog Output Event",
    50:  "Time and Date",
    51:  "Time and Date CTO",
    52:  "Time Delay",
    60:  "Class Objects",
    70:  "File Control",
    80:  "Internal Indications",
    81:  "Buffer Ready",
    82:  "Object Count",
    83:  "Clear Restart",
    110: "Octet String",
    111: "Octet String Event",
    112: "Virtual Terminal Output",
    113: "Virtual Terminal Event",
    120: "Authentication",
    121: "Security Statistics",
    122: "Security Statistics Event",
}

def describe_header(group: int, var: int, qual: int, prefix: dict) -> dict:
    return {
        "group": group,
        "group_name": DNP3_GROUP_NAMES.get(group, f"Unknown Group {group}"),
        "variation": var,
        "qualifier": hex(qual),
        "range": prefix,
    }

# -------------------------
# CRC-16-DNP
# -------------------------

_CRC16_DNP_TABLE = None

def _build_crc16_dnp_table() -> List[int]:
    # CRC-16/DNP: poly=0x3D65 refin/refout=True => reflected poly 0xA6BC
    poly = 0xA6BC
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
        table.append(crc & 0xFFFF)
    return table

def crc16_dnp(data: bytes) -> int:
    global _CRC16_DNP_TABLE
    if _CRC16_DNP_TABLE is None:
        _CRC16_DNP_TABLE = _build_crc16_dnp_table()
    crc = 0x0000
    for b in data:
        crc = (crc >> 8) ^ _CRC16_DNP_TABLE[(crc ^ b) & 0xFF]
    return (crc ^ 0xFFFF) & 0xFFFF

def append_crc_le(block: bytes) -> bytes:
    return block + struct.pack("<H", crc16_dnp(block))

def verify_crc_le(block_with_crc: bytes) -> bool:
    if len(block_with_crc) < 3:
        return False
    got = struct.unpack("<H", block_with_crc[-2:])[0]
    return crc16_dnp(block_with_crc[:-2]) == got

# -------------------------
# Link / Transport / App helpers
# -------------------------

DNP3_START = b"\x05\x64"

LINK_FUNC_UNCONFIRMED_USER_DATA = 0x04
LINK_FUNC_CONFIRMED_USER_DATA   = 0x03

APP_FUNC_CONFIRM     = 0x00
APP_FUNC_READ        = 0x01
APP_FUNC_RESPONSE    = 0x81
APP_FUNC_UNSOLICITED = 0x82

# Qualifier codes (subset we care about)
QUAL_RANGE8     = 0x00
QUAL_RANGE16    = 0x01
QUAL_ALL_OBJECTS= 0x06
QUAL_COUNT8     = 0x07
QUAL_COUNT16    = 0x08

def build_link_control(prm: int, dir_master_to_out: int, fcb: int, fcv: int, func: int) -> int:
    # bit7 DIR, bit6 PRM, bit5 FCB, bit4 FCV, bits0-3 FUNC
    return ((dir_master_to_out & 1) << 7) | ((prm & 1) << 6) | ((fcb & 1) << 5) | ((fcv & 1) << 4) | (func & 0x0F)

def build_transport_header(fin: int, fir: int, seq: int) -> int:
    # bit7 FIR, bit6 FIN, bits0-5 SEQ
    return ((fir & 1) << 7) | ((fin & 1) << 6) | (seq & 0x3F)

def build_app_control(fin: int, fir: int, con: int, uns: int, seq: int) -> int:
    # bit7 FIR, bit6 FIN, bit5 CON, bit4 UNS, bits0-3 SEQ
    return ((fir & 1) << 7) | ((fin & 1) << 6) | ((con & 1) << 5) | ((uns & 1) << 4) | (seq & 0x0F)

def app_ctrl_bits(app_ctrl: int) -> Dict[str, int]:
    return {
        "FIR": (app_ctrl >> 7) & 1,
        "FIN": (app_ctrl >> 6) & 1,
        "CON": (app_ctrl >> 5) & 1,
        "UNS": (app_ctrl >> 4) & 1,
        "SEQ": app_ctrl & 0x0F,
    }

def build_object_header(group: int, variation: int, qualifier: int, prefix: bytes = b"") -> bytes:
    return bytes([group & 0xFF, variation & 0xFF, qualifier & 0xFF]) + prefix

def build_read_request_app_pdu(object_headers: bytes, app_seq: int) -> bytes:
    app_ctrl = build_app_control(fin=1, fir=1, con=0, uns=0, seq=app_seq)
    return bytes([app_ctrl, APP_FUNC_READ]) + object_headers

def build_confirm_app_pdu(app_seq: int) -> bytes:
    # Confirm uses same SEQ as the message being confirmed
    app_ctrl = build_app_control(fin=1, fir=1, con=0, uns=0, seq=app_seq)
    return bytes([app_ctrl, APP_FUNC_CONFIRM])

def build_dnp3_link_frame(dest: int, src: int, user_data: bytes, confirmed: bool = False,
                          dir_master_to_out: int = 1, prm: int = 1, fcb: int = 0, fcv: int = 0) -> bytes:
    func = LINK_FUNC_CONFIRMED_USER_DATA if confirmed else LINK_FUNC_UNCONFIRMED_USER_DATA
    ctrl = build_link_control(prm=prm, dir_master_to_out=dir_master_to_out, fcb=fcb, fcv=fcv, func=func)
    length = 5 + len(user_data)
    if length > 255:
        raise ValueError("Link length too large for single link frame; implement fragmentation.")
    header_wo_crc = DNP3_START + bytes([length & 0xFF, ctrl & 0xFF]) + struct.pack("<HH", dest & 0xFFFF, src & 0xFFFF)
    out = bytearray(append_crc_le(header_wo_crc))
    for i in range(0, len(user_data), 16):
        out += append_crc_le(user_data[i:i+16])
    return bytes(out)

def expected_total_frame_len(link_length_field: int) -> int:
    data_len = link_length_field - 5
    blocks = (data_len + 15) // 16
    return 10 + data_len + 2 * blocks

def parse_transport_ctl(b: int) -> Dict[str, int]:
    return {
        "FIR": (b >> 6) & 1,
        "FIN": (b >> 7) & 1,
        "SEQ": b & 0x3F,
    }

class TransportReassembler:
    """
    Reassembles transport-fragmented application bytes.
    DNP3 transport is per-direction/per-session; for a mapper, one active stream per TCP socket is typical.

    Policy:
      - Start new message on FIR=1
      - If we get a non-FIR fragment without an active message -> drop
      - If SEQ jumps -> reset (you can make this more tolerant if you want)
      - On FIN=1 -> yield the complete app bytes
    """
    def __init__(self):
        self.active = False
        self.expected_seq: Optional[int] = None
        self.buf = bytearray()

    def reset(self) -> None:
        self.active = False
        self.expected_seq = None
        self.buf.clear()

    def push(self, transport_ctl: int, app_slice: bytes) -> Optional[bytes]:
        t = parse_transport_ctl(transport_ctl)
        fir, fin, seq = t["FIR"], t["FIN"], t["SEQ"]

        if fir:
            # Start new message
            self.active = True
            self.expected_seq = (seq + 1) & 0x3F
            self.buf = bytearray(app_slice)
        else:
            if not self.active:
                print("no active transport assembly")
                return None
            if self.expected_seq is not None and seq != self.expected_seq:
                # Out-of-order / missing fragment -> reset
                self.reset()
                print("out of order transport seq")
                return None
            self.expected_seq = (seq + 1) & 0x3F
            self.buf += app_slice

        if fin and self.active:
            complete = bytes(self.buf)
            self.reset()
            return complete

        return None

# -------------------------
# Parsing
# -------------------------

@dataclass
class DNP3Frame:
    dest: int
    src: int
    link_control: int
    user_data: bytes  # transport + app

@dataclass
class DNP3App:
    app_ctrl: int
    func: int
    seq: int
    uns: int
    con: int
    iin: Optional[int]
    raw_objects: bytes
    object_headers: List[Tuple[int, int, int, Dict[str, int]]]

def qualifier_prefix_len(q: int) -> int:
    # length of the qualifier prefix (after g,v,q) *for the object block*
    if q == QUAL_ALL_OBJECTS:
        return 0
    if q == QUAL_RANGE8:
        return 2
    if q == QUAL_RANGE16:
        return 4
    if q == QUAL_COUNT8:
        return 1
    if q == QUAL_COUNT16:
        return 2
    # add more qualifiers as you encounter them
    return -1  # unknown

def qualifier_extract_count(q: int, prefix: bytes) -> Optional[int]:
    if q == QUAL_COUNT8:
        return prefix[0]
    if q == QUAL_COUNT16:
        return struct.unpack("<H", prefix[:2])[0]
    if q == QUAL_RANGE8:
        start, stop = prefix[0], prefix[1]
        return (stop - start + 1) if stop >= start else None
    if q == QUAL_RANGE16:
        start, stop = struct.unpack("<HH", prefix[:4])
        return (stop - start + 1) if stop >= start else None
    # QUAL_ALL_OBJECTS has no prefix -> cannot compute count without decoding payload structure
    return None

# Bytes per point for common STATIC variations (not events)
# This is intentionally incomplete; extend as you see new variations.
POINT_SIZE: Dict[Tuple[int, int], int] = {
    # Binary Input static
    (1, 1): 0,  # packed (special handling)
    (1, 2): 1,  # flags (1 byte)
    # Double bit binary input
    (3, 2): 1,  # flags (1 byte)
    # Binary Output Status static
    (10, 2): 1, # flags
    # Counter static
    (20, 1): 5, # flags(1) + 32-bit count(4)
    (20, 2): 3, # flags + 16-bit count 
    # Frozen counters
    (21, 1): 5, # flags(1) + 32-bit count(4)
    (21, 2): 3, # flags + 16-bit count 
    # Analog Input static
    (30, 1): 5, # flags(1) + 32-bit (4) (common)
    (30, 2): 3, # flags(1) + 16-bit (2) (common)
    (30, 3): 4, # 32-bit signed int 
    (30, 4): 2, # 16-bit signed int
    (30, 5): 5, # flag + 32-bit float
    # Frozen analog input
    (31, 1): 5, # flag + value
    (31, 2): 3, # flag + value
    (31, 3): 11, # flag + value + time
    (31, 4): 9, # flag + value + time
    (31, 5): 4, # value
    # Analog Output Status static
    (40, 1): 5,
    (40, 2): 3,
    # Time and date
    (50, 1): 6,
    (50, 2): 10,
    (50, 3): 6,
    (50, 4): 11,
    # Octet strings
    (110, 1): 1,
    # Security stats
    (121, 1): 7,
}

def parse_object_blocks(data: bytes) -> List[Dict[str, Any]]:
    """
    Attempts to iterate through multiple object blocks in the response.
    Returns a list of dicts with (group, var, qual, prefix_info, offset, payload_len).
    Stops if it can't safely skip a block.
    """
    blocks: List[Dict[str, Any]] = []
    i = 0
    n = len(data)

    while i + 3 <= n:
        start_off = i
        g, v, q = data[i], data[i+1], data[i+2]
        i += 3

        pref_len = qualifier_prefix_len(q)
        if pref_len < 0 or i + pref_len > n:
            blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "error": "unknown_or_truncated_qualifier"})
            break

        prefix = data[i:i+pref_len]
        i += pref_len

        count = qualifier_extract_count(q, prefix)
        prefix_info: Dict[str, Any] = {}
        if q == QUAL_RANGE8 and len(prefix) == 2:
            prefix_info["start"], prefix_info["stop"] = prefix[0], prefix[1]
        elif q == QUAL_RANGE16 and len(prefix) == 4:
            prefix_info["start"], prefix_info["stop"] = struct.unpack("<HH", prefix)
        elif q in (QUAL_COUNT8, QUAL_COUNT16) and count is not None:
            prefix_info["count"] = count

        # Special case: packed binaries (e.g., g1v1)
        if (g, v) == (1, 1):
            if count is None:
                # With "all objects" you can't know how many packed bytes; need spec-aware parse.
                blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "prefix": prefix_info,
                               "error": "packed_binary_needs_count_or_range"})
                break
            packed_len = (count + 7) // 8
            if i + packed_len > n:
                blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "prefix": prefix_info,
                               "error": "truncated_payload"})
                break
            payload_len = packed_len
            blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "prefix": prefix_info,
                           "count": count, "payload_len": payload_len})
            i += payload_len
            continue

        # Normal fixed-size points
        point_size = POINT_SIZE.get((g, v))
        if point_size is None:
            blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "prefix": prefix_info,
                           "error": "unknown_point_size"})
            break

        if count is None:
            # For QUAL_ALL_OBJECTS, you can't skip without knowing count.
            blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "prefix": prefix_info,
                           "error": "unknown_count_for_all_objects"})
            break

        payload_len = count * point_size
        if i + payload_len > n:
            blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "prefix": prefix_info,
                           "count": count, "payload_len": payload_len, "error": "truncated_payload"})
            break

        blocks.append({"group": g, "var": v, "qual": q, "offset": start_off, "prefix": prefix_info,
                       "count": count, "payload_len": payload_len})
        i += payload_len

    return blocks


def parse_link_frame(buf: bytes) -> Optional[DNP3Frame]:
    if len(buf) < 10 or buf[0:2] != DNP3_START:
        return None
    length = buf[2]
    total_len = expected_total_frame_len(length)
    if len(buf) < total_len:
        return None
    hdr = buf[:10]
    if not verify_crc_le(hdr):
        return None
    link_control = buf[3]
    dest, src = struct.unpack("<HH", buf[4:8])

    data_len = length - 5
    offset = 10
    remaining = data_len
    user_data = bytearray()
    while remaining > 0:
        take = min(16, remaining)
        block = buf[offset:offset + take + 2]
        if len(block) != take + 2 or not verify_crc_le(block):
            return None
        user_data += block[:-2]
        offset += take + 2
        remaining -= take

    return DNP3Frame(dest=dest, src=src, link_control=link_control, user_data=bytes(user_data))

def parse_object_headers_minimal(data: bytes) -> List[Tuple[int, int, int, Dict[str, int]]]:
    """
    Minimal header parser that can keep going for qualifiers with known prefix sizes.
    It does NOT decode object payloads; it only parses (g,v,q,prefix) for inventory.
    """
    out = []
    i = 0
    while i + 3 <= len(data):
        print("parsing header")
        g, v, q = data[i], data[i+1], data[i+2]
        i += 3
        info: Dict[str, int] = {}

        if q == QUAL_ALL_OBJECTS:
            # no prefix bytes
            out.append((g, v, q, info))
            # payload follows; without decoding payload length, we must stop here
            break

        elif q == QUAL_RANGE16:
            if i + 4 > len(data): break
            start, stop = struct.unpack("<HH", data[i:i+4])
            info = {"start": start, "stop": stop}
            i += 4
            out.append((g, v, q, info))
            break

        elif q == QUAL_RANGE8:
            if i + 2 > len(data): break
            start, stop = data[i], data[i+1]
            info = {"start": start, "stop": stop}
            i += 2
            out.append((g, v, q, info))
            break

        elif q == QUAL_COUNT8:
            if i + 1 > len(data): break
            info = {"count": data[i]}
            i += 1
            out.append((g, v, q, info))
            break

        elif q == QUAL_COUNT16:
            if i + 2 > len(data): break
            info = {"count": struct.unpack("<H", data[i:i+2])[0]}
            i += 2
            out.append((g, v, q, info))
            break

        else:
            out.append((g, v, q, info))
            break

    return out

def parse_app(user_data: bytes) -> Optional[DNP3App]:
    if len(user_data) < 3:
        return None
    # transport header is 1 byte
    app = user_data[1:]
    if len(app) < 2:
        return None

    app_ctrl = app[0]
    func = app[1]
    bits = app_ctrl_bits(app_ctrl)

    # Only RESPONSE / UNSOLICITED include IIN (2 bytes) immediately after func
    idx = 2
    iin = None
    if func in (APP_FUNC_RESPONSE, APP_FUNC_UNSOLICITED):
        if len(app) < 4:
            return None
        iin = struct.unpack("<H", app[2:4])[0]
        idx = 4

    raw_objects = app[idx:]
    blocks = parse_object_blocks(raw_objects)
    headers = [(b["group"], b["var"], b["qual"], b.get("prefix", {})) for b in blocks]

    return DNP3App(
        app_ctrl=app_ctrl,
        func=func,
        seq=bits["SEQ"],
        uns=bits["UNS"],
        con=bits["CON"],
        iin=iin,
        raw_objects=raw_objects,
        object_headers=headers
    )

def parse_app_from_bytes(app: bytes) -> Optional[DNP3App]:
    """
    app bytes begin at Application Control (no Transport header included).
    Response/Unsolicited layout:
      app_ctrl(1), func(1), [IIN(2)], objects...
    """
    if len(app) < 2:
        return None

    app_ctrl = app[0]
    func = app[1]
    bits = app_ctrl_bits(app_ctrl)

    idx = 2
    iin = None
    if func in (APP_FUNC_RESPONSE, APP_FUNC_UNSOLICITED):
        if len(app) < 4:
            return None
        iin = struct.unpack("<H", app[2:4])[0]
        idx = 4

    raw_objects = app[idx:]
    blocks = parse_object_blocks(raw_objects)
    headers = [(b["group"], b["var"], b["qual"], b.get("prefix", {})) for b in blocks]

    return DNP3App(
        app_ctrl=app_ctrl,
        func=func,
        seq=bits["SEQ"],
        uns=bits["UNS"],
        con=bits["CON"],
        iin=iin,
        raw_objects=raw_objects,
        object_headers=headers
    )


def infer_addresses_from_frame(fr: DNP3Frame) -> Optional[Tuple[int, int]]:
    """
    For any inbound frame (outstation->master), assume:
      outstation = src, master = dest
    This is correct for unsolicited and for solicited responses.
    """
    if not fr or fr.src is None or fr.dest is None:
        return None
    return (fr.dest, fr.src)  # (master, outstation)

def listen_for_inbound_addresses(client: DNP3TCPClient, seconds: float = 1.5) -> Optional[Tuple[int, int]]:
    end = time.time() + seconds
    while time.time() < end:
        fr = client.recv_one_link_frame(timeout=max(0.1, end - time.time()))
        if not fr:
            continue
        if len(fr.user_data) < 3:
            continue
        addrs = infer_addresses_from_frame(fr)
        if addrs:
            master_addr, outstation_addr = addrs
            print(f"[discover] inbound frame observed -> master={master_addr} outstation={outstation_addr}")
            return addrs
    return None

def build_probe_request(app_seq: int) -> bytes:
    """
    'Device info' probe: pick something small that often yields any response.
    You can swap this to build_read_g0v254/app_seq or g0v255 if you prefer.
    """
    return build_read_class0(app_seq)  # g60v1 qual=0x06

def discover_outstation_address(
    host: str,
    port: int = 20000,
    # When we don't know the master address, we still need *some* src address to send probes.
    # This list is tried as the link-layer source (master) address during probing.
    typical_master_addrs: Iterable[int] = (1, 1024, 100, 10),
    typical_outstation_addrs: Iterable[int] = (1, 2, 3, 10, 11, 12, 100, 101, 102, 1000, 1024, 2000),
    listen_seconds: float = 1.5,
    per_probe_timeout: float = 1.5,
    confirmed_link: bool = False,
) -> Optional[Tuple[int, int]]:
    """
    Returns (master_addr, outstation_addr) or None.

    Strategy:
      1) Connect and listen for inbound frames (unsolicited/solicited). If seen, infer addresses.
      2) Else, probe typical outstation addresses. For each candidate dest address, try
         sending a small READ with a few candidate master source addresses.

    Notes:
      - Many outstations ignore requests from an unexpected master address.
      - If the outstation sends unsolicited after any probe (even with wrong dest),
        step (1) would have found it, but we repeat lightweight listening during probing too.
    """
    client = DNP3TCPClient(host, port, timeout=max(3.0, per_probe_timeout))
    try:
        client.connect()

        # 1) Passive/unsolicited fast-path
        got = listen_for_inbound_addresses(client, seconds=listen_seconds)
        if got:
            return got

        # 2) Active probing
        print("[discover] no inbound frames; starting active address probes...")
        unsolicited: List[Dict[str, Any]] = []

        for out_addr in typical_outstation_addrs:
            for master_addr in typical_master_addrs:
                # Use a unique app seq per probe attempt (0..15). Wrap is fine.
                app_seq = (hash((out_addr, master_addr)) & 0x0F)

                app_pdu = build_probe_request(app_seq)
                # send request
                t = bytes([build_transport_header(fin=1, fir=1, seq=0)])
                frame = build_dnp3_link_frame(
                    dest=out_addr,
                    src=master_addr,
                    user_data=t + app_pdu,
                    confirmed=confirmed_link
                )
                client.send(frame)

                # After sending, wait briefly for either:
                #  - any inbound frame we can use to infer addresses, or
                #  - a solicited Response matching the probe seq
                reasm = TransportReassembler()
                end = time.time() + per_probe_timeout

                while time.time() < end:
                    fr = client.recv_one_link_frame(timeout=max(0.1, end - time.time()))
                    if not fr:
                        continue

                    # If ANY inbound frame arrives, infer link addrs (works great if unsolicited enabled)
                    inferred = infer_addresses_from_frame(fr)
                    if inferred:
                        inf_master, inf_out = inferred
                        print(f"[discover] inferred from inbound during probing -> master={inf_master} outstation={inf_out}")
                        return inferred

                    # Otherwise, try to parse/reassemble and match app seq
                    if len(fr.user_data) < 2:
                        continue
                    complete_app = reasm.push(fr.user_data[0], fr.user_data[1:])
                    if complete_app is None:
                        continue
                    app = parse_app_from_bytes(complete_app)
                    if not app:
                        continue

                    is_unsol = (app.func == APP_FUNC_UNSOLICITED) or (app.uns == 1)
                    if is_unsol:
                        unsolicited.append({"seq": app.seq, "con": app.con, "iin": app.iin})
                        # optional confirm unsolicited if needed
                        if app.con == 1:
                            confirm_pdu = build_confirm_app_pdu(app.seq)
                            client.send(build_dnp3_link_frame(dest=out_addr, src=master_addr, user_data=t + confirm_pdu))
                        continue

                    if app.func == APP_FUNC_RESPONSE and app.seq == (app_seq & 0x0F):
                        # We got a valid response to our probe -> addresses are the ones we used
                        print(f"[discover] probe succeeded -> master={master_addr} outstation={out_addr}")
                        return (master_addr, out_addr)

        print("[discover] probing failed; no address discovered")
        return None

    finally:
        client.close()



# -------------------------
# TCP client with unsolicited-safe receive
# -------------------------

class DNP3TCPClient:
    def __init__(self, host: str, port: int = 20000, timeout: float = 7.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._rxbuf = bytearray()

    def connect(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        self.sock = s

    def close(self) -> None:
        if self.sock:
            try: self.sock.close()
            finally: self.sock = None

    def send(self, data: bytes) -> None:
        assert self.sock is not None
        self.sock.sendall(data)

    def recv_one_link_frame(self, timeout: float) -> Optional[DNP3Frame]:
        assert self.sock is not None
        end = time.time() + timeout

        while time.time() < end:
            fr = self._try_parse()
            if fr:
                return fr
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return None
            self._rxbuf += chunk
        print("**** Link response timed out ***")
        return None

    def _try_parse(self) -> Optional[DNP3Frame]:
        buf = self._rxbuf
        start = buf.find(DNP3_START)
        if start < 0:
            if len(buf) > 4096:
                del buf[:-2]
            return None
        if start > 0:
            del buf[:start]
        if len(buf) < 3:
            return None
        length = buf[2]
        total = expected_total_frame_len(length)
        if len(buf) < total:
            return None

        candidate = bytes(buf[:total])
        fr = parse_link_frame(candidate)
        if fr is None:
            del buf[0:1]
            return None
        del buf[:total]
        return fr

# -------------------------
# Mapper requests
# -------------------------

def build_read_all_objects(group: int, variation: int, app_seq: int) -> bytes:
    # qualifier 0x06 = all objects, no range bytes
    oh = build_object_header(group, variation, QUAL_ALL_OBJECTS)
    return build_read_request_app_pdu(oh, app_seq=app_seq)

def build_read_g0v254(app_seq: int) -> bytes:
    return build_read_all_objects(0, 254, app_seq)

def build_read_g0v255(app_seq: int) -> bytes:
    return build_read_all_objects(0, 255, app_seq)

def build_read_class0(app_seq: int) -> bytes:
    # Group 60 Var 1 = Class 0, qualifier 0x06 = all objects
    return build_read_all_objects(60, 1, app_seq)


def recv_one_app_message(
    client: DNP3TCPClient,
    reasm: TransportReassembler,
    timeout: float,
) -> Optional[DNP3App]:
    """
    Reads link frames until it can reassemble a complete Application message.
    Returns a parsed DNP3App or None on timeout.
    """
    end = time.time() + timeout
    while time.time() < end:
        fr = client.recv_one_link_frame(timeout=max(0.1, end - time.time()))
        if not fr:
            continue
        if len(fr.user_data) < 2:
            continue

        transport_ctl = fr.user_data[0]
        app_slice = fr.user_data[1:]

        complete_app = reasm.push(transport_ctl, app_slice)
        if complete_app is None:
            continue

        app = parse_app_from_bytes(complete_app)
        if app:
            return app
    print("*** App response timed out")

    return None



# -------------------------
# txrx that filters unsolicited + matches expected app seq
# -------------------------

def txrx_expect_response(
    client: DNP3TCPClient,
    master_addr: int,
    outstation_addr: int,
    app_pdu: bytes,
    expected_app_seq: int,
    confirmed_link: bool = False,
    timeout: float = 7.0,
    auto_confirm_unsolicited: bool = True,
    unsolicited_sink: Optional[List[Dict[str, Any]]] = None,
) -> Optional[DNP3App]:
    # send request (still single transport fragment on TX)
    t = bytes([build_transport_header(fin=1, fir=1, seq=0)])
    frame = build_dnp3_link_frame(
        dest=outstation_addr, src=master_addr,
        user_data=t + app_pdu, confirmed=confirmed_link
    )
    client.send(frame)

    reasm = TransportReassembler()
    end = time.time() + timeout

    while time.time() < end:
        app = recv_one_app_message(client, reasm, timeout=max(0.1, end - time.time()))
        if not app:
            continue

        is_unsolicited = (app.func == APP_FUNC_UNSOLICITED) or (app.uns == 1)
        if is_unsolicited:
            if unsolicited_sink is not None:
                unsolicited_sink.append({
                    "app_seq": app.seq,
                    "con": app.con,
                    "iin": app.iin,
                    "func": app.func,
                })

            if auto_confirm_unsolicited and app.con == 1:
                # confirm uses same app sequence
                confirm_pdu = build_confirm_app_pdu(app.seq)
                confirm_frame = build_dnp3_link_frame(
                    dest=outstation_addr, src=master_addr,
                    user_data=t + confirm_pdu, confirmed=confirmed_link
                )
                client.send(confirm_frame)
            continue

        if app.func == APP_FUNC_RESPONSE and app.seq == (expected_app_seq & 0x0F):
            return app

        # otherwise ignore and keep reading

    return None


# -------------------------
# Example probe
# -------------------------

def mapper_probe(host: str, port: int, master_addr: int, outstation_addr: int) -> Dict[str, Any]:
    client = DNP3TCPClient(host, port, timeout=7.0)
    unsolicited: List[Dict[str, Any]] = []

    results: Dict[str, Any] = {
        "target": f"{host}:{port}",
        "master_addr": master_addr,
        "outstation_addr": outstation_addr,
        "unsolicited_seen": unsolicited,
        "g0v254": None,
        "g0v255": None,
        "class0": None,
    }

    # Use the link-layer addresses the caller already discovered. (The original
    # code re-ran discovery here with a hardcoded outstation list and a buggy
    # `(1)` master "tuple" that is actually an int, which could crash the active
    # probe path or map the wrong outstation. scan_one_ip already discovered the
    # correct pair, so probe those directly.)

    try:
        client.connect()

        # Pick sequences 0,1,2 for our three requests
        a254 = txrx_expect_response(client, master_addr, outstation_addr, build_read_g0v254(0), expected_app_seq=0,
                                   unsolicited_sink=unsolicited)
        a255 = txrx_expect_response(client, master_addr, outstation_addr, build_read_g0v255(1), expected_app_seq=1,
                                   unsolicited_sink=unsolicited)
        c0   = txrx_expect_response(client, master_addr, outstation_addr, build_read_class0(2), expected_app_seq=2,
                                   unsolicited_sink=unsolicited, timeout=7.0)

        results["g0v254"] = {
            "ok": a254 is not None,
            "iin": a254.iin if a254 else None,
            "headers": [describe_header(*h) for h in a254.object_headers] if a254 else None,
        }
        results["g0v255"] = {
            "ok": a255 is not None,
            "iin": a255.iin if a255 else None,
            "headers": [describe_header(*h) for h in a255.object_headers] if a255 else None,
        }
        results["class0"] = {
            "ok": c0 is not None,
            "iin": c0.iin if c0 else None,
            "headers": [describe_header(*h) for h in c0.object_headers] if c0 else None,
        }

        return results

    finally:
        client.close()

def scan_one_ip(
    ip: str,
    port: int,
    listen_seconds: float,
    per_probe_timeout: float,
    typical_master_addrs: Tuple[int, ...],
    typical_outstation_addrs: Tuple[int, ...],
) -> Dict[str, Any]:
    # First: discover link-layer addresses (or fail fast)
    discovered = discover_outstation_address(
        host=ip,
        port=port,
        typical_master_addrs=typical_master_addrs,
        typical_outstation_addrs=typical_outstation_addrs,
        listen_seconds=listen_seconds,
        per_probe_timeout=per_probe_timeout,
        confirmed_link=False,
    )

    if not discovered:
        return {
            "ip": ip,
            "port": port,
            "ok": False,
            "error": "no_dnp3_or_address_not_discovered",
        }

    master_addr, outstation_addr = discovered

    # Then: run your existing probe/mapping logic
    try:
        res = mapper_probe(ip, port, master_addr=master_addr, outstation_addr=outstation_addr)
        res["ok"] = True
        res["ip"] = ip
        res["port"] = port
        return res
    except Exception as e:
        return {
            "ip": ip,
            "port": port,
            "ok": False,
            "error": f"exception: {type(e).__name__}: {e}",
            "master_addr": master_addr,
            "outstation_addr": outstation_addr,
        }

def parse_int_list(s: str) -> Tuple[int, ...]:
    # "1,10,100,1024"
    vals = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        vals.append(int(part, 0))
    return tuple(vals)

def main():
    ap = argparse.ArgumentParser(description="DNP3 mapper: scan CIDR and inventory outstations")
    ap.add_argument("cidr", help="CIDR range to scan, e.g. 192.168.1.0/24")
    ap.add_argument("--port", type=int, default=20000, help="TCP port (default: 20000)")
    ap.add_argument("--workers", type=int, default=8, help="Number of concurrent workers (default: 8)")
    ap.add_argument("--listen-seconds", type=float, default=3, help="Seconds to listen for unsolicited (default: 3)")
    ap.add_argument("--probe-timeout", type=float, default=3, help="Timeout per probe attempt (default: 3)")
    ap.add_argument("--masters", type=str, default="1", help="Typical master addrs (csv, default: 1)")
    ap.add_argument("--outstations", type=str, default="1,2,3,10,11,12,20,100,101,102,1000,1002,1024",
                    help="Typical outstation addrs (csv)")
    ap.add_argument("--out", type=str, default="dnp3_map.json", help="Output JSON file (default: dnp3_map.json)")
    ap.add_argument("--include-network-broadcast", action="store_true",
                    help="Include network and broadcast addresses (normally skipped)")

    args = ap.parse_args()

    net = ipaddress.ip_network(args.cidr, strict=False)
    ips = list(net.hosts())  # skips network/broadcast for IPv4
    if args.include_network_broadcast:
        ips = list(net)

    typical_master_addrs = parse_int_list(args.masters)
    typical_outstation_addrs = parse_int_list(args.outstations)

    results: List[Dict[str, Any]] = []
    total = len(ips)
    print(f"[scan] scanning {total} IPs in {net} on TCP/{args.port} with {args.workers} workers")

    # Keep ordering stable-ish by storing per-IP results in a dict then emitting sorted
    result_by_ip: Dict[str, Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(
                scan_one_ip,
                str(ip),
                args.port,
                args.listen_seconds,
                args.probe_timeout,
                typical_master_addrs,
                typical_outstation_addrs,
            ): str(ip)
            for ip in ips
        }

        done = 0
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"ip": ip, "port": args.port, "ok": False, "error": f"exception: {type(e).__name__}: {e}"}

            result_by_ip[ip] = r
            done += 1
            if done % 10 == 0 or done == total:
                ok_count = sum(1 for v in result_by_ip.values() if v.get("ok"))
                print(f"[scan] progress {done}/{total} (ok={ok_count})")

    # Emit results sorted by IP
    for ip in sorted(result_by_ip.keys(), key=lambda x: ipaddress.ip_address(x)):
        results.append(result_by_ip[ip])

    out_doc = {
        "cidr": str(net),
        "port": args.port,
        "scanned": total,
        "ok": sum(1 for r in results if r.get("ok")),
        "results": results,
    }

    with open(args.out, "w") as f:
        json.dump(out_doc, f, indent=2, sort_keys=True)

    print(f"[scan] wrote {args.out} (ok={out_doc['ok']}/{total})")

if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# Library entry points (used by der_dnp3.cli and der_dnp3.adapter)
# ---------------------------------------------------------------------------

def expand_targets(cidr_or_host: str, include_network_broadcast: bool = False) -> List[str]:
    """Expand a CIDR or a single host/IP into a list of IP strings."""
    try:
        net = ipaddress.ip_network(cidr_or_host, strict=False)
    except ValueError:
        return [cidr_or_host]  # bare hostname
    ips = list(net) if include_network_broadcast else list(net.hosts())
    if not ips:                 # /32 (single host) or /31
        ips = [net.network_address]
    return [str(ip) for ip in ips]


def run_scan(
    targets: List[str],
    port: int = 20000,
    workers: int = 8,
    listen_seconds: float = 3.0,
    probe_timeout: float = 3.0,
    typical_master_addrs: Tuple[int, ...] = (1,),
    typical_outstation_addrs: Tuple[int, ...] = (1, 2, 3, 10, 11, 12, 20, 100, 101, 102, 1000, 1002, 1024),
) -> Dict[str, Any]:
    """Scan host IPs for DNP3 outstations and inventory their objects.

    Returns the same document shape the CLI writes to dnp3_map.json:
      {"port", "scanned", "ok", "results": [per-host dict, ...]}
    """
    result_by_ip: Dict[str, Dict[str, Any]] = {}
    total = len(targets)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(scan_one_ip, ip, port, listen_seconds, probe_timeout,
                      typical_master_addrs, typical_outstation_addrs): ip
            for ip in targets
        }
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                result_by_ip[ip] = fut.result()
            except Exception as e:
                result_by_ip[ip] = {"ip": ip, "port": port, "ok": False,
                                    "error": f"exception: {type(e).__name__}: {e}"}
    results = [result_by_ip[ip] for ip in sorted(result_by_ip, key=lambda x: ipaddress.ip_address(x))]
    return {"port": port, "scanned": total,
            "ok": sum(1 for r in results if r.get("ok")), "results": results}
