import random
import os

def mutate_payload(payload):
    """
    Structured (not random-byte-flip) payload mutations.
    """

    options = []

    # truncate payload
    if len(payload) > 1:
        options.append(payload[:1])

    # empty payload
    options.append(b"")

    # incorrect size pattern
    options.append(b"\x00" * (len(payload) + 5))

    # maximum size block
    options.append(os.urandom(32))  # allowed: not random *bit flips*

    # repeated pattern
    options.append(b"\xAA" * len(payload))

    return random.choice(options)
