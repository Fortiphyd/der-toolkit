import random


def mutate_bytecount(bytecount, payload_len):
    """
    Return a mismatched bytecount.
    """

    pool = [
        0,                      # zero
        1,                      # too small
        payload_len - 1,        # off by one small
        payload_len + 1,        # off by one big
        payload_len + 10,       # way too big
        255                     # max
    ]

    return random.choice(pool)
