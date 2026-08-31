#!/usr/bin/env python3
"""boofuzz-based server fuzzer -- targets a Modbus/TCP device (SunSpec speaks
Modbus, so this fuzzes the DER inverter/gateway itself, as opposed to
client_fuzzer/ which fuzzes SunSpec masters/clients).

DISRUPTIVE. Requires the optional 'sunspec' extra's boofuzz dependency.

Migrated from ~/DER/boofuzz/modbus.py: generic Modbus function-code request
definitions (read holding/input regs, write multiple coils/holding regs,
read/write file record, read/write multiple) with boofuzz's standard
mutations plus a length/byte-count boundary primitive. Kept generic rather
than SunSpec-model-aware since the interesting bugs here are in the Modbus
parser itself, which every SunSpec device implements identically.
"""

from __future__ import annotations

from boofuzz import Block, Word, Byte, Size, Repeat, RandomData, Request, Session, Target, TCPSocketConnection


def _build_function_codes(unit_id: int):
    read_holding = Block("read_holding", children=(
        Word("transaction", 1, endian='>', fuzzable=False),
        Word("protocol", 0, endian='>', fuzzable=False),
        Size("length", "read_holding_body", length=2, endian='>'),
        Block("read_holding_body", children=(
            Byte("unit_id", unit_id, endian='>', fuzzable=False),
            Byte("function", 0x03, endian='>', fuzzable=False),
            Word("start_add", 1, endian='>'),
            Word("number_of_regs", 1, endian='>', max_num=512),
        )),
    ))

    read_inputs = Block("read_inputs", children=(
        Word("transaction", 1, endian='>', fuzzable=False),
        Word("protocol", 0, endian='>', fuzzable=False),
        Size("length", "read_inputs_body", length=2, endian='>'),
        Block("read_inputs_body", children=(
            Byte("unit_id", unit_id, endian='>', fuzzable=False),
            Byte("function", 0x04, endian='>', fuzzable=False),
            Word("start_add", 1, endian='>'),
            Word("number_of_inputs", 1, endian='>', max_num=512),
        )),
    ))

    write_multiple_coils = Block("write_multiple_coils", children=(
        Word("transaction", 1, endian='>', fuzzable=False),
        Word("protocol", 0, endian='>', fuzzable=False),
        Size("length", "write_multiple_coils_body", length=2, endian='>'),
        Block("write_multiple_coils_body", children=(
            Byte("unit_id", unit_id, endian='>', fuzzable=False),
            Byte("function", 0x0f, endian='>', fuzzable=False),
            Word("start_add", 1, endian='>'),
            Size("number_of_coils", "multiple_coils_data", length=2, endian='>', math=lambda x: x * 8),
            Size("byte_count", "multiple_coils_data", length=1, endian='>'),
            Block("multiple_coils_data", children=(
                RandomData("data", b'0', max_length=512, step=64),
            )),
        )),
    ))

    write_holding = Block("write_holding", children=(
        Word("transaction", 1, endian='>', fuzzable=False),
        Word("protocol", 0, endian='>', fuzzable=False),
        Size("length", "write_holding_body", length=2, endian='>'),
        Block("write_holding_body", children=(
            Byte("unit_id", unit_id, endian='>', fuzzable=False),
            Byte("function", 0x10, endian='>', fuzzable=False),
            Word("start_add", 1, endian='>'),
            Size("number_of_regs", "holding_data", length=2, endian='>', math=lambda x: int(x / 2)),
            Size("byte_count", "holding_data", length=1, endian='>'),
            Block("holding_data", children=(
                RandomData("data", b'0', max_length=512, step=64),
            )),
        )),
    ))

    read_file = Block("read_file", children=(
        Word("transaction", 1, endian='>', fuzzable=False),
        Word("protocol", 0, endian='>', fuzzable=False),
        Size("length", "read_file_body", length=2, endian='>'),
        Block("read_file_body", children=(
            Byte("unit_id", unit_id, endian='>', fuzzable=False),
            Byte("function", 0x14, endian='>', fuzzable=False),
            Size("byte_count", "subrequests", length=1, endian='>'),
            Block("read_sub", children=(
                Byte("type", 6, fuzzable=False),
                Word("file_number", 0, endian='>'),
                Word("record_number", 0, endian='>', max_num=20000),
                Word("record_length", 1, endian='>', max_num=500),
            )),
            Repeat("subrequests", "read_sub", max_reps=10),
        )),
    ))

    write_file = Block("write_file", children=(
        Word("transaction", 1, endian='>', fuzzable=False),
        Word("protocol", 0, endian='>', fuzzable=False),
        Size("length", "write_file_body", length=2, endian='>'),
        Block("write_file_body", children=(
            Byte("unit_id", unit_id, endian='>', fuzzable=False),
            Byte("function", 0x15, endian='>', fuzzable=False),
            Size("byte_count", "write_file_subs", length=1, endian='>'),
            Block("write_sub", children=(
                Byte("type", 6, fuzzable=False),
                Word("file_number", 0, endian='>'),
                Word("record_number", 0, endian='>', max_num=20000),
                Size("record_length", "file_data", length=2, endian='>', math=lambda x: int(x / 2)),
                RandomData("file_data", b'0', max_length=500, step=50),
            )),
            Repeat("write_file_subs", "write_sub", max_reps=10),
        )),
    ))

    read_write = Block("read_write", children=(
        Word("transaction", 1, endian='>', fuzzable=False),
        Word("protocol", 0, endian='>', fuzzable=False),
        Size("length", "read_write_body", length=2, endian='>', fuzzable=False),
        Block("read_write_body", children=(
            Byte("unit_id", unit_id, endian='>', fuzzable=False),
            Byte("function", 0x17, endian='>', fuzzable=False),
            Word("read_addr", 1, endian='>', fuzzable=False),
            Word("number_of_reads", 1, endian='>', max_num=512),
            Word("write_addr", 1, endian='>', fuzzable=False),
            Size("number_of_writes", "write_data", length=2, endian='>', math=lambda x: int(x / 2), fuzzable=False),
            Size("byte_count", "write_data", length=1, endian='>', fuzzable=False),
            Block("write_data", children=(
                RandomData("data", b'00', max_length=512, step=64, fuzzable=False),
            )),
        )),
    ))

    return [read_holding, read_inputs, write_multiple_coils, write_holding, read_file, write_file, read_write]


def run_fuzz(host: str, port: int = 502, unit_id: int = 1, max_depth: int = 3) -> None:
    """Run the Modbus/SunSpec boofuzz session against host:port.

    One Session per Modbus function code (matching the original tool), each
    writing its own db under ./boofuzz-results/ in the current working
    directory; the MCP layer runs this inside a per-job run dir.
    """
    for i, fc in enumerate(_build_function_codes(unit_id)):
        session = Session(
            target=Target(
                connection=TCPSocketConnection(host, port),
            ),
            receive_data_after_fuzz=True,
            reuse_target_connection=False,
            restart_sleep_time=2,
            fuzz_db_keep_only_n_pass_cases=1,
            # Without this, boofuzz blocks on input() after fuzzing completes to
            # keep its webinterface open -- fatal (EOFError) when run headless
            # from der-toolkit's CLI or the MCP job subprocess (no stdin).
            keep_web_open=False,
        )
        req = Request(f"{fc.name}_req_{i}", children=(fc,))
        session.connect(req)
        session.fuzz(max_depth=max_depth)
