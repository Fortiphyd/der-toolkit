"""SunSpec model catalog: model ID -> human-readable name, and which models are
writable control/settings surfaces.

This is the self-describing property the project centers on: a SunSpec device
hands you its model chain, and the model ID alone tells you what each block does
("704 = DER AC Controls", "123 = Immediate Controls"). No vendor documentation
required. CONTROL_MODELS are the blocks whose registers an unauthenticated
Modbus client could *write* to actuate or reconfigure the DER (power limits,
connect/disconnect, ride-through curves).
"""

from __future__ import annotations

MODEL_NAMES: dict[int, str] = {
    1: "Common", 2: "Basic Aggregator",
    # Secure comms / device management
    3: "Secure Dataset Read Request", 4: "Secure Dataset Read Response",
    5: "Secure Write Request", 6: "Secure Write Sequential Request",
    7: "Secure Write Response", 8: "Get Device Security Certificate",
    9: "Set Operator Security Certificate",
    # Communication interfaces
    10: "Communication Interface Header", 11: "Ethernet Link", 12: "IPv4", 13: "IPv6",
    14: "Proxy Server", 15: "Interface Counters", 16: "Simple IP Network",
    17: "Serial Interface", 18: "Cellular Link", 19: "PPP Link",
    # Inverter measurement models
    101: "Inverter (single phase)", 102: "Inverter (split phase)", 103: "Inverter (three phase)",
    111: "Inverter (single phase, float)", 112: "Inverter (split phase, float)",
    113: "Inverter (three phase, float)",
    120: "Nameplate", 121: "Basic Settings", 122: "Measurements/Status",
    123: "Immediate Controls", 124: "Storage Controls", 125: "Pricing",
    126: "Static Volt-VAR", 127: "Freq-Watt Parameterized", 128: "Dynamic Reactive Current",
    129: "LVRT", 130: "HVRT", 131: "Watt-PF", 132: "Volt-Watt", 133: "Basic Scheduling",
    134: "Freq-Watt Curve", 135: "LFRT Curve", 136: "HFRT Curve",
    137: "LVRT Curve", 138: "HVRT Curve",
    139: "LVRT (Extended)", 140: "HVRT (Extended)", 141: "LFRT Curve (Extended)",
    142: "HFRT Curve (Extended)", 143: "LFRT (Extended)", 144: "HFRT (Extended)",
    145: "Extended Settings",
    160: "Multiple MPPT",
    # Meter models
    201: "Meter (single phase)", 202: "Meter (split phase)", 203: "Meter (three phase)",
    204: "Meter (three phase, delta)",
    211: "Meter (single phase, float)", 212: "Meter (split phase, float)",
    213: "Meter (three phase, float)", 214: "Meter (three phase, delta, float)",
    220: "Secure AC Meter Selected Readings",
    # Environmental / met sensors
    302: "Irradiance", 303: "Back of Module Temperature", 304: "Inclinometer",
    305: "GPS", 306: "Reference Point", 307: "Base Met (Weather Station)",
    308: "Mini Met",
    # Combiners / panels / tracker
    401: "String Combiner", 402: "String Combiner (advanced)",
    403: "String Combiner (v2)", 404: "String Combiner (advanced, v2)",
    501: "Panel", 502: "Panel (float)", 601: "Tracker",
    # New DER (SunSpec 700-series)
    701: "DER AC Measurement", 702: "DER Capacity", 703: "Enter Service",
    704: "DER AC Controls", 705: "DER Volt-VAR", 706: "DER Volt-Watt",
    707: "DER Trip LV", 708: "DER Trip HV", 709: "DER Trip LF", 710: "DER Trip HF",
    711: "DER Freq-Watt", 712: "DER Watt-VAR", 713: "DER Enter Service Curve",
    714: "DER Frequency Droop", 715: "DER Capacity Status",
    # Storage
    801: "Energy Storage Base", 802: "Battery Base", 803: "Lithium-Ion Bank",
    804: "Lithium-Ion String", 805: "Lithium-Ion Module", 806: "Flow Battery",
    807: "Flow Battery String", 808: "Flow Battery Module", 809: "Flow Battery Stack",
    # Test / vendor-specific extensions present in the vendored SMDX bundle
    63001: "SunSpec Test Model 1", 63002: "SunSpec Test Model 2",
    64001: "Veris Status and Configuration", 64020: "Mersen GreenString",
    64101: "Eltek Inverter Extension", 64110: "OutBack AXS Device",
    64111: "Basic Charge Controller", 64112: "OutBack FM Charge Controller",
}

# Writable control / settings models — the security-relevant surface.
CONTROL_MODELS: set[int] = {
    121, 123, 124, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 145,
    704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714,
    802,
}


def model_name(model_id: int) -> str:
    return MODEL_NAMES.get(model_id, f"SunSpec Model {model_id}")


def is_control_model(model_id: int) -> bool:
    return model_id in CONTROL_MODELS
