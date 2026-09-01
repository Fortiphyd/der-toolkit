#!/usr/bin/env python3
import socket
from typing import Optional
from boofuzz import Session, Target, s_initialize, s_byte, s_static, s_get, s_group, s_word
from boofuzz.connections.itarget_connection import ITargetConnection  # ITargetConnection interface :contentReference[oaicite:6]{index=6}
import random
from typing import Iterable

# ----------------------------
# CRC-16/DNP + link-frame packer
# ----------------------------

def _reflect8(x: int) -> int:
    y = 0
    for i in range(8):
        y = (y << 1) | ((x >> i) & 1)
    return y

def crc16_dnp(data: bytes) -> int:
    """
    CRC-16/DNP (refin/refout) as commonly implemented in tooling; matches the Quick Reference example frame.
    """
    poly = 0x3D65
    crc = 0x0000
    for b in data:
        b = _reflect8(b)
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF

    # reflect 16-bit
    r = 0
    for i in range(16):
        r = (r << 1) | ((crc >> i) & 1)
    r ^= 0xFFFF
    return r & 0xFFFF

def u16le(x: int) -> bytes:
    return bytes((x & 0xFF, (x >> 8) & 0xFF))

def build_dnp3_link_frame(
    user_data: bytes,
    dst: int = 10,
    src: int = 1,
    link_ctrl: int = 0xC4,
    forced_len: int | None = None,
) -> bytes:
    start = b"\x05\x64"

    computed_len = 1 + 2 + 2 + len(user_data)  # CTRL + DST + SRC + user_data
    length = computed_len if forced_len is None else (forced_len & 0xFF)

    # IMPORTANT: even if length is "invalid", we still build/sent it to fuzz parser paths.
    header_8 = start + bytes([length, link_ctrl]) + u16le(dst) + u16le(src)
    header_crc = u16le(crc16_dnp(header_8))  # header CRC must match the bytes we send

    out = bytearray(header_8 + header_crc)

    # Payload CRCs are computed over the actual bytes we transmit (even if LEN lies).
    for i in range(0, len(user_data), 16):
        block = user_data[i:i + 16]
        out += block
        out += u16le(crc16_dnp(block))

    return bytes(out)


def define_len_and_sendmode_fuzzed_integrity_poll():
    s_initialize("dnp3_len_then_user_data")

    # OOB: 0=normal, 1=split(boundaries), 2=split(random), 3=coalesce
    s_group(name="send_mode", values=[b"\x00", b"\x01", b"\x02", b"\x03"], default_value=b"\x00")

    s_group(name="len_mode", values=[b"\x00",b"\x01"], default_value=b"\x00")      # 0 = computed, 1 = forced
    s_byte(0x14, name="len_value", fuzzable=True)
    # Then the real DNP3 user_data (transport+app+objects), initially static/valid:
    s_group(
        name="transport",
        values=[b"\xC0", b"\x80", b"\x40", b"\x00", b"\xFF", b"\xC1", b"\xCF"],
        default_value=b"\xC0"
        )
    s_group(name="app_ctrl", values=[
        b"\xC0",  # FIR/FIN, seq 0
        b"\xC1", b"\xC2", b"\xC3", b"\xC4",
        b"\x40",  # FIN only
        b"\x80",  # FIR only
        b"\x00",  # neither
        b"\xFF",
    ], default_value=b"\xC3")
    s_byte(0x01, name="app_func",  fuzzable=False)   # READ

    # Class poll objects (60.2, 60.3, 60.4, 60.1) qualifier 0x06 (all objects)
    for var in (0x02, 0x03, 0x04, 0x01):
        s_byte(0x3C, name=f"group60_{var}_g", fuzzable=False)
        s_byte(var,  name=f"group60_{var}_v", fuzzable=False)
        s_byte(0x06, name=f"group60_{var}_q", fuzzable=False)


def chunk_bytes(buf: bytes, cuts: Iterable[int]) -> list[bytes]:
    cuts = [c for c in cuts if 0 < c < len(buf)]
    cuts = sorted(set(cuts))
    out = []
    last = 0
    for c in cuts:
        out.append(buf[last:c])
        last = c
    out.append(buf[last:])
    return [c for c in out if c]

# ----------------------------
# boofuzz connection: wraps fuzzed "user_data" into a valid DNP3 frame
# ----------------------------

class Dnp3TcpWrappedConnection(ITargetConnection):
    def __init__(self, host: str, port: int = 20000, timeout: float = 2.0,
                 dst: int = 10, src: int = 1, link_ctrl: int = 0xC4,
                 send_mode: str = "normal",          # normal|split|coalesce
                 split_strategy: str = "boundaries", # boundaries|random
                 split_parts: int = 4,
                 coalesce_count: int = 3,
                 seed: int = 0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.dst = dst
        self.src = src
        self.link_ctrl = link_ctrl
        self._sock: Optional[socket.socket] = None
        self.split_strategy = split_strategy
        self.split_parts = split_parts
        self.coalesce_count = coalesce_count
        self._rng = random.Random(seed)
        self._coalesce_buf = bytearray()

    @property
    def info(self) -> str:
        return f"{self.host}:{self.port}"

    def _send_reset_link(self):
        """Send RESET_LINK_STATES (FC=0x00) and wait for ACK before fuzzing."""
        # link_ctrl=0xC0: DIR=1, PRM=1, FCB=0, FCV=0, FC=0 (RESET_LINK_STATES)
        reset_frame = build_dnp3_link_frame(
            user_data=b"",
            dst=self.dst,
            src=self.src,
            link_ctrl=0xC0,
        )
        self._sock.sendall(reset_frame)
        try:
            # Wait for ACK (secondary FC=0x00 = ACK)
            self._sock.recv(4096)
        except socket.timeout:
            pass  # proceed anyway — we're fuzzing, not guaranteeing delivery


    def open(self):
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)
        self._send_reset_link()

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _send_split(self, frame: bytes, strategy: str):
        if strategy == "boundaries":
            # Byte offsets chosen to hit common parsing boundaries:
            # 2: after 05 64
            # 3: after LEN
            # 10: after header+CRC (05 64 LEN CTRL DST SRC + CRC16 = 10 bytes)
            # then every 18 bytes after that (16 data + 2 CRC) to land near block/CRC boundaries
            cuts = [2, 3, 10]
            i = 10
            step = 18
            while i + step < len(frame):
                i += step
                cuts.append(i)        # boundary between blocks
                cuts.append(i - 2)    # boundary just before CRC
            chunks = chunk_bytes(frame, cuts)
        else:
            # random split into N parts (deterministic due to seed)
            n = max(2, int(self.split_parts))
            if len(frame) <= n:
                chunks = [frame]
            else:
                # choose n-1 cut points
                cuts = sorted(self._rng.sample(range(1, len(frame)), k=n-1))
                chunks = chunk_bytes(frame, cuts)

        for part in chunks:
            self._sock.sendall(part)

    def _send_coalesce(self, frame: bytes, count: int = 3):
        self._sock.sendall(frame * count)

    def send(self, data: bytes) -> int:
        if len(data) < 3:
            return 0

        send_mode = data[0]
        len_mode  = int(data[1])
        len_value = data[2]
        user_data = data[3:]

        forced_len = len_value if (len_mode == 1) else None
        frame = build_dnp3_link_frame(
            user_data=user_data,
            dst=self.dst,
            src=self.src,
            link_ctrl=self.link_ctrl,
            forced_len=forced_len,
        )

        # Optional debug
        # true_len = 1 + 2 + 2 + len(user_data)
        # print(f"LEN override={len_override:02x} forced={forced_len} true={true_len} frame={len(frame)}")


        mode = send_mode % 4
        if mode == 1:
            self._send_split(frame, strategy="boundaries")
        elif mode == 2:
            self._send_split(frame, strategy="random")
        elif mode == 3:
            count = 2 + (send_mode % 3)
            self._send_coalesce(frame, count)
        else:
            self._sock.sendall(frame)

        return len(data)

    def recv(self, max_bytes: int = 4096) -> bytes:
        try:
            return self._sock.recv(max_bytes)
        except socket.timeout:
            return b""

# ----------------------------
# boofuzz model: "user_data" for integrity/class poll (READ class 1/2/3/0)
# ----------------------------

def define_dnp3_integrity_poll():
    s_initialize("dnp3_user_data")

    # Transport header: FIN/FIR/SEQ. Single fragment => 0xC0 per reference. :contentReference[oaicite:12]{index=12}
    s_byte(0xC0, name="transport", fuzzable=False)

    # Application control. The Quick Reference example uses 0xC3 (FIR/FIN + SEQ=3). :contentReference[oaicite:13]{index=13}
    # OpenDNP3 doesn't require SEQ=3 specifically; keep it static at first.
    s_byte(0xC3, name="app_ctrl", fuzzable=False)

    # Application function code: READ = 0x01. :contentReference[oaicite:14]{index=14}
    s_byte(0x01, name="app_func", fuzzable=False)

    # Object headers: Group 60 (0x3C), Variations 2/3/4/1, Qualifier 0x06 ("all objects"). :contentReference[oaicite:15]{index=15}
    # Start fully-valid. Later, turn fuzzable=True for variation/qualifier/range to go deeper.
    for (var, label) in [(0x02, "class1"), (0x03, "class2"), (0x04, "class3"), (0x01, "class0")]:
        s_byte(0x3C, name=f"obj_{label}_group", fuzzable=False)
        s_byte(var,   name=f"obj_{label}_var",   fuzzable=False)
        s_byte(0x06,  name=f"obj_{label}_qual",  fuzzable=False)

def _preamble(msg_name: str) -> None:
    """Open a new message and write the transport + app-layer fixed header."""
    s_initialize(msg_name)
    s_byte(0xC0, name="transport", fuzzable=False)  # FIR | FIN | SEQ=0
    s_byte(0xC0, name="app_ctrl",  fuzzable=False)  # FIR | FIN | SEQ=0
    s_byte(0x01, name="app_func",  fuzzable=False)  # READ
 
 
def _obj_gv(group: int, var: int, tag: str) -> None:
    """Emit a fixed Group/Variation pair. tag keeps boofuzz field names unique."""
    s_byte(group, name=f"g_{tag}", fuzzable=False)
    s_byte(var,   name=f"v_{tag}", fuzzable=False)
 
 
# ---------------------------------------------------------------------------
# Qualifier 0x00 — Start / Stop, 1-byte indices
# ---------------------------------------------------------------------------
# Attack surface:
#   • Inverted range (start > stop) — some parsers loop forever or underflow
#   • start == stop == 0xFF — single-object range at max index
#   • start == stop == 0x00 — index-zero edge case
 
def define_qual_00() -> str:
    name = "dnp3_qual_00_start_stop_1b"
    _preamble(name)
    _obj_gv(0x3C, 0x02, "q00")         # Group 60 Var 2 (Class 1)
    s_byte(0x00, name="qualifier", fuzzable=False)
    s_group(name="range_start", default_value=b"\x00", values=[
        b"\x00", b"\x01", b"\x7F", b"\x80", b"\xFE", b"\xFF",
    ])
    s_group(name="range_stop", default_value=b"\x00", values=[
        b"\x00", b"\x01", b"\x7F", b"\x80", b"\xFE", b"\xFF",
    ])
    return name
 
 
# ---------------------------------------------------------------------------
# Qualifier 0x01 — Start / Stop, 2-byte LE indices
# ---------------------------------------------------------------------------
# Attack surface:
#   • 0xFFFF / 0x0000 — inverted range with max-width indices
#   • 0xFFFF / 0xFFFF — boundary-max stop (may drive pointer arithmetic OOB)
#   • boofuzz will also walk through its standard word mutation set
 
def define_qual_01() -> str:
    name = "dnp3_qual_01_start_stop_2b"
    _preamble(name)
    _obj_gv(0x3C, 0x02, "q01")
    s_byte(0x01, name="qualifier", fuzzable=False)
    s_word(0x0000, name="range_start", fuzzable=True, endian="<")
    s_word(0x0000, name="range_stop",  fuzzable=True, endian="<")
    return name
 
 
# ---------------------------------------------------------------------------
# Qualifier 0x07 — Count, 1-byte
# ---------------------------------------------------------------------------
# Attack surface:
#   • count=0   — zero-object request; many parsers skip the loop but still
#                 allocate a buffer proportional to count
#   • count=255 — parser tries to read 255 objects with zero bytes following;
#                 classic out-of-bounds read
 
def define_qual_07() -> str:
    name = "dnp3_qual_07_count_1b"
    _preamble(name)
    _obj_gv(0x3C, 0x02, "q07")
    s_byte(0x07, name="qualifier", fuzzable=False)
    s_group(name="count", default_value=b"\x01", values=[
        b"\x00",   # zero — allocation-then-no-read
        b"\x01",
        b"\x02",
        b"\x7F",
        b"\x80",
        b"\xFE",
        b"\xFF",   # 255 objects claimed, zero bytes sent
    ])
    # No object data follows — this is the truncated-payload case.
    # Add a fuzzable trailer byte so boofuzz also tests "a little data but not enough".
    s_byte(0xAB, name="trailer", fuzzable=True)
    return name
 
 
# ---------------------------------------------------------------------------
# Qualifier 0x08 — Count, 2-byte LE
# ---------------------------------------------------------------------------
# Attack surface:
#   • count=0xFFFF drives integer-overflow bugs in count * sizeof(object)
#     allocations (e.g., 65535 * 4 wraps to a small buffer on 16-bit math)
#   • boofuzz word mutations also hit 0x8000, 0x0100, etc.
 
def define_qual_08() -> str:
    name = "dnp3_qual_08_count_2b"
    _preamble(name)
    _obj_gv(0x3C, 0x02, "q08")
    s_byte(0x08, name="qualifier", fuzzable=False)
    s_word(0x0001, name="count", fuzzable=True, endian="<")
    # Again intentionally send no object data after the count.
    s_byte(0xAB, name="trailer", fuzzable=True)
    return name
 
 
# ---------------------------------------------------------------------------
# Qualifier 0x17 — Count (1-byte) + Variable-Length objects
# ---------------------------------------------------------------------------
# Format: [count_1b] then `count` objects each structured as:
#           [size_1b][size bytes of data]
#
# Attack surface:
#   • count=N but only 1 object's worth of bytes follows — parser over-reads
#   • obj_size=0   — zero-size object; may cause a divide-by-zero or infinite loop
#   • obj_size=255 — claims 255 bytes but only 1-2 bytes follow
#   • count * obj_size overflows parser's internal length accumulator
 
def define_qual_17() -> str:
    name = "dnp3_qual_17_varlen_1b"
    _preamble(name)
    # Group 110 Var 0 is the spec's "Octet String" — the canonical variable-length
    # object type. Using it makes the group/qualifier combination plausible,
    # exercising the variable-length code path rather than an immediate reject.
    _obj_gv(0x6E, 0x00, "q17")         # Group 110 Var 0 (Octet String)
    s_byte(0x17, name="qualifier", fuzzable=False)
 
    # Count: how many objects the parser will try to iterate over
    s_group(name="count", default_value=b"\x01", values=[
        b"\x00",   # zero-count — buffer allocated but never written?
        b"\x01",
        b"\x02",
        b"\x7F",
        b"\xFF",   # 255 objects claimed
    ])
    # First (and only) object: a 1-byte size prefix + actual data
    s_group(name="obj0_size", default_value=b"\x01", values=[
        b"\x00",   # zero-length object body
        b"\x01",
        b"\x02",
        b"\x7F",
        b"\xFF",   # claims 255-byte body; we only send 2 bytes
    ])
    s_byte(0xDE, name="obj0_b0", fuzzable=True)
    s_byte(0xAD, name="obj0_b1", fuzzable=True)
    # Deliberately omit the remaining (obj0_size - 2) bytes — truncated payload.
    return name
 
 
# ---------------------------------------------------------------------------
# Qualifier 0x28 — Count (2-byte LE) + Variable-Length objects
# ---------------------------------------------------------------------------
# Same structure as 0x17, but count is 2 bytes.
# The critical overflow: count=0xFFFF, obj_size=0xFF → 65535 * 255 ≈ 16 MB
# allocation attempt (or integer wraparound to near-zero on 16-bit targets).
 
def define_qual_28() -> str:
    name = "dnp3_qual_28_varlen_2b"
    _preamble(name)
    _obj_gv(0x6E, 0x00, "q28")
    s_byte(0x28, name="qualifier", fuzzable=False)
 
    s_word(0x0001, name="count", fuzzable=True, endian="<")  # hits 0xFFFF, 0x8000 …
    s_group(name="obj0_size", default_value=b"\x01", values=[
        b"\x00", b"\x01", b"\x02", b"\x7F", b"\xFF",
    ])
    s_byte(0xDE, name="obj0_b0", fuzzable=True)
    s_byte(0xAD, name="obj0_b1", fuzzable=True)
    return name
 
 
# ---------------------------------------------------------------------------
# Qualifier 0x5B — Free-Format (length-prefixed block)
# ---------------------------------------------------------------------------
# Format: [count_1b] then `count` blocks each structured as:
#           [len_lo][len_hi][len bytes of data]
#
# Attack surface:
#   • block_len=0xFFFF with 2 actual bytes — massive over-read
#   • block_len=0 — zero-size block; parser may dereference empty pointer
#   • count=0 — no blocks but parser may still read len field
 
def define_qual_5b() -> str:
    name = "dnp3_qual_5b_free_format"
    _preamble(name)
    _obj_gv(0x6E, 0x00, "q5b")
    s_byte(0x5B, name="qualifier", fuzzable=False)
 
    s_group(name="count", default_value=b"\x01", values=[
        b"\x00",   # no blocks — does parser still peek at len?
        b"\x01",
        b"\x02",
        b"\xFF",
    ])
    # 2-byte LE block length for the first block
    s_group(name="block_len", default_value=b"\x02\x00", values=[
        b"\x00\x00",   # len=0
        b"\x01\x00",   # len=1
        b"\x02\x00",   # len=2 — exactly matches real data below
        b"\xFF\x00",   # len=255 — claims 255, sends 2
        b"\x00\x01",   # len=256
        b"\xFF\xFF",   # len=65535 — maximum claimed, minimum sent
    ])
    # Actual data — always just 2 bytes regardless of block_len claim
    s_byte(0xDE, name="data_b0", fuzzable=True)
    s_byte(0xAD, name="data_b1", fuzzable=True)
    return name
 
 
# ---------------------------------------------------------------------------
# Invalid / Reserved qualifier bytes
# ---------------------------------------------------------------------------
# Tests the parser's error/default path. Many implementations have no
# default case in their qualifier switch statement — undefined behaviour.
# Some reserved values share nibble patterns with valid ones and may slip
# past a nibble-only check.
 
def define_qual_invalid() -> str:
    name = "dnp3_qual_invalid"
    _preamble(name)
    _obj_gv(0x3C, 0x02, "qinv")
    s_group(name="qualifier", default_value=b"\xFF", values=[
        # Undefined in the lower nibble
        b"\x02", b"\x04", b"\x05",
        # Undefined combos in the 0x10–0x50 range
        b"\x10", b"\x11", b"\x12",
        b"\x20", b"\x21",
        b"\x30", b"\x40", b"\x50",
        b"\x60", b"\x70",
        # Near-valid: one bit flip away from 0x06 / 0x07 / 0x5B
        b"\x0E", b"\x0F",
        b"\x4B", b"\x5A", b"\x5C",
        # Full-invalid
        b"\xFE", b"\xFF",
    ])
    # A few trailing bytes — parser may try to read range even for invalid qualifiers
    s_byte(0x00, name="junk_b0", fuzzable=True)
    s_byte(0x00, name="junk_b1", fuzzable=True)
    s_byte(0x00, name="junk_b2", fuzzable=True)
    s_byte(0x00, name="junk_b3", fuzzable=True)
    return name
 
 
# ---------------------------------------------------------------------------
# Bonus: multi-object-header message
# ---------------------------------------------------------------------------
# Some parsers loop over multiple object headers per APDU.  Sending two headers
# with mismatched qualifier/range in the second one tests loop-continuation logic.
 
def define_two_headers_second_fuzzed() -> str:
    name = "dnp3_two_obj_headers"
    _preamble(name)
 
    # First header: valid Class 1 poll, qualifier 0x06 (all objects) — no range bytes
    _obj_gv(0x3C, 0x02, "hdr1")
    s_byte(0x06, name="qual_hdr1", fuzzable=False)
 
    # Second header: same group, fuzzed qualifier + range
    _obj_gv(0x3C, 0x03, "hdr2")          # Class 2 this time
    s_group(name="qual_hdr2", default_value=b"\x01", values=[
        b"\x00", b"\x01",                # start/stop variants
        b"\x07", b"\x08",                # count variants
        b"\x17", b"\x28", b"\x5B",       # variable-length variants
        b"\xFF",                          # invalid
    ])
    # Range bytes — intentionally ambiguous size; parser must use qualifier to know how many to consume
    s_byte(0x00, name="r0", fuzzable=True)
    s_byte(0x00, name="r1", fuzzable=True)
    s_byte(0x00, name="r2", fuzzable=True)
    s_byte(0x00, name="r3", fuzzable=True)
    return name

def main():
    target_ip   = "127.0.0.1"
    target_port = 20000
 
    # ── Your existing message (keep it) ──────────────────────────────────
    define_len_and_sendmode_fuzzed_integrity_poll()   # from original file
 
    # ── New qualifier/range messages ─────────────────────────────────────
    qual_messages = [
        define_qual_00(),
        define_qual_01(),
        define_qual_07(),
        define_qual_08(),
        define_qual_17(),
        define_qual_28(),
        define_qual_5b(),
        define_qual_invalid(),
        define_two_headers_second_fuzzed(),
    ]
 
    conn = Dnp3TcpWrappedConnection(target_ip, target_port)   # from original file
    session = Session(
        target=Target(connection=conn),
        receive_data_after_fuzz=True,
        ignore_connection_reset=True,
        reuse_target_connection=False,
    )
 
    # Original message
    session.connect(s_get("dnp3_len_then_user_data"))
 
    # Qualifier/range messages
    for msg_name in qual_messages:
        session.connect(s_get(msg_name))
 
    session.fuzz(max_depth=2)
 
 
if __name__ == "__main__":
    main()



# ---------------------------------------------------------------------------
# Library entry point (used by der_dnp3.cli / the MCP fuzz job).
# DISRUPTIVE. Requires the optional 'dnp3' extra (boofuzz).
# ---------------------------------------------------------------------------

def run_fuzz(host: str, port: int = 20000, max_depth: int = 2,
             dst: int = 10, src: int = 1):
    """Run the DNP3 boofuzz session against host:port.

    boofuzz writes its results database under ./boofuzz-results/ in the current
    working directory; the MCP layer runs this inside a per-job run dir.
    """
    define_len_and_sendmode_fuzzed_integrity_poll()
    qual_messages = [
        define_qual_00(), define_qual_01(), define_qual_07(), define_qual_08(),
        define_qual_17(), define_qual_28(), define_qual_5b(),
        define_qual_invalid(), define_two_headers_second_fuzzed(),
    ]
    conn = Dnp3TcpWrappedConnection(host, port, dst=dst, src=src)
    session = Session(
        target=Target(connection=conn),
        receive_data_after_fuzz=True,
        ignore_connection_reset=True,
        reuse_target_connection=False,
        # Prune old passing (non-crash) cases as the run goes so the result db
        # doesn't grow unbounded over a long campaign -- crashes are never
        # pruned, so no finding evidence is lost. der_sunspec/fuzzer.py has
        # had this since it was ported from the original tool; dnp3's never
        # did, letting its dbs balloon (~500MB+ in real campaigns).
        fuzz_db_keep_only_n_pass_cases=1,
        # Without this, boofuzz blocks on input() after fuzzing completes to
        # keep its webinterface open -- fatal (EOFError) when run headless
        # from der-toolkit's CLI or the MCP job subprocess (no stdin).
        keep_web_open=False,
    )
    session.connect(s_get("dnp3_len_then_user_data"))
    for msg_name in qual_messages:
        session.connect(s_get(msg_name))
    session.fuzz(max_depth=max_depth)
    return session
