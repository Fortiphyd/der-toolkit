import random

def mutate_function_code(func):
    """
    Replace the function code with:
    - Reserved codes
    - Unsupported codes
    - Exception codes
    """
    mutation_pool = [
        0x00,              # invalid
        0x07, 0x09, 0x0B,  # reserved in Modbus
        0x11,              # Report Server ID
        0x2B,              # Encapsulated Interface
        func | 0x80,       # exception version
        random.randint(0x40, 0x7F),   # mid-range undefined
        random.randint(0x81, 0xFF)    # undefined exception FCs
    ]
    return random.choice(mutation_pool)
