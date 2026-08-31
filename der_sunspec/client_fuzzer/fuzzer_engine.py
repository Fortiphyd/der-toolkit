import random
import struct

from der_sunspec.client_fuzzer.mutators.header_mutators import mutate_protocol_id, mutate_unit_id
from der_sunspec.client_fuzzer.mutators.length_mutators import mutate_length_field
from der_sunspec.client_fuzzer.mutators.function_mutators import mutate_function_code
from der_sunspec.client_fuzzer.mutators.bytecount_mutators import mutate_bytecount
from der_sunspec.client_fuzzer.mutators.payload_mutators import mutate_payload


def mutate_response(resp_bytes, req):
    """
    Full mutation pipeline (excluding TxID + random bit flips)
    """

    # --------------------------
    # Parse original response
    # --------------------------

    trans_id = resp_bytes[0:2]                # left unchanged
    proto_id = resp_bytes[2:4]
    length   = resp_bytes[4:6]
    unit_id  = resp_bytes[6:7]

    mbap = resp_bytes[:7]
    pdu  = resp_bytes[7:]
    func = pdu[0]
    payload = pdu[1:]

    mutated_mbap = mbap
    mutated_pdu = pdu

    # --------------------------
    # Apply header mutations
    # --------------------------

    if random.random() < 0.3:
        mutated_mbap = mutate_protocol_id(mutated_mbap)

    if random.random() < 0.2:
        mutated_mbap = mutate_unit_id(mutated_mbap)

    # --------------------------
    # Apply function code mutation
    # --------------------------

    if random.random() < 0.3:
        new_fc = mutate_function_code(func)
    else:
        new_fc = func

    # --------------------------
    # Apply payload mutation
    # --------------------------

    if random.random() < 0.3:
        new_payload = mutate_payload(payload)
    else:
        new_payload = payload

    # --------------------------
    # Apply bytecount mutation (if applicable)
    # --------------------------

    if new_fc in (1,2,3,4):  # read functions
        if len(new_payload) > 0:
            mutated_bytecount = mutate_bytecount(new_payload[0], len(new_payload))
            new_pdu = bytes([new_fc]) + bytes([mutated_bytecount]) + new_payload
        else:
            new_pdu = bytes([new_fc, 0])  # empty
    else:
        new_pdu = bytes([new_fc]) + new_payload

    # --------------------------
    # Recalculate or fuzz length
    # --------------------------

    new_length = len(new_pdu) + 1
    normal_mbap = (
        trans_id
        + b"\x00\x00"                # protocol id (may be overwritten below)
        + struct.pack(">H", new_length)
        + mutated_mbap[6:7]
    )

    # Sometimes mutate the length field too
    if random.random() < 0.3:
        mutated_mbap_final = mutate_length_field(normal_mbap, len(new_pdu))
    else:
        mutated_mbap_final = normal_mbap

    # Put protocol-id and unit-id mutations back
    mutated_mbap_final = (
        trans_id
        + mutated_mbap_final[2:7]   # keep mutations
    )

    return mutated_mbap_final + new_pdu
