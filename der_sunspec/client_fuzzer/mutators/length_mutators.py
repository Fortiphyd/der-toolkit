import struct
import random

def mutate_length_field(mbap, payload_len):
    """
    Produce incorrect length calculations.
    Real length = 1 (unit id) + payload_len.
    """

    incorrect_lengths = [
        0,                          # zero length
        1,                          # too small
        payload_len,                # missing unit ID
        payload_len + 10,           # too large
        0xFFFF                      # max uint16
    ]

    bad_len = random.choice(incorrect_lengths)
    return mbap[0:4] + struct.pack(">H", bad_len) + mbap[6:]
