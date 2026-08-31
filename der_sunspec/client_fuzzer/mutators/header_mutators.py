import struct
import random

def mutate_protocol_id(mbap):
    proto_id = random.choice([0xFFFF, 0x0001, 0x00FF, 0x1234])
    return mbap[0:2] + struct.pack(">H", proto_id) + mbap[4:]

def mutate_unit_id(mbap):
    uid = random.choice([0x00, 0xFF, 0x7F])
    return mbap[:6] + bytes([uid])
