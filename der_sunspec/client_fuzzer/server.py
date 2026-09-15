import socket
import struct
import threading

from der_sunspec.client_fuzzer.fuzzer_engine import mutate_response


# -----------------------------
# Minimal MBAP + Request Parser
# -----------------------------
def parse_modbus_request(data):
    """
    Parses MBAP header + PDU.
    Returns a dict with all useful fields.
    """

    if len(data) < 8:
        return None

    trans_id = struct.unpack(">H", data[0:2])[0]
    proto_id = struct.unpack(">H", data[2:4])[0]
    length   = struct.unpack(">H", data[4:6])[0]
    unit_id  = data[6]
    func     = data[7]

    return {
        "trans_id": trans_id,
        "proto_id": proto_id,
        "length": length,
        "unit_id": unit_id,
        "func": func,
        "payload": data[8:],  # pdu minus FC
        "raw": data
    }

# ---------------------------------------
# Build a minimally correct Modbus reply
# ---------------------------------------
def build_normal_response(req):
    """
    Builds a syntactically valid Modbus response for the given request.
    This ensures your client proceeds far enough for mutation to matter.
    """

    trans_id = req["trans_id"]
    proto_id = 0
    unit_id  = req["unit_id"]
    func     = req["func"]

    # --- Simple default responses based on function --- #

    if func in (1, 2):  # Read Coils / Read Discrete Inputs
        byte_count = 1
        coil_data = b"\x00"
        pdu = bytes([func, byte_count]) + coil_data

    elif func in (3, 4):  # Read Holding / Input Registers
        byte_count = 2
        reg_data = b"\x12\x34"  # dummy register
        pdu = bytes([func, byte_count]) + reg_data

    elif func == 5:  # Write Single Coil
        # Echo original request PDU
        pdu = bytes([func]) + req["payload"][:4]

    elif func == 6:  # Write Single Register
        pdu = bytes([func]) + req["payload"][:4]

    elif func == 15 or func == 16:  # Write Multiple Coils
        # Echo starting address + quantity
        pdu = bytes([func]) + req["payload"][:4]

    else:
        # Unsupported → exception response
        pdu = bytes([func | 0x80, 0x01])  # illegal function

    length = len(pdu) + 1  # unit id + pdu len
    mbap = struct.pack(">HHHB", trans_id, proto_id, length, unit_id)

    return mbap + pdu



# -------------------------------
# Client Handler
# -------------------------------
def handle_client(conn, addr):
    print(f"[+] Client connected: {addr}")

    try:
        while True:
            # Read MBAP header first (7 bytes)
            header = conn.recv(7)
            if not header:
                print("[-] Client disconnected")
                break

            if len(header) < 7:
                print("[-] Short MBAP header received")
                break

            # Parse length field to know how many more bytes to read
            _, _, length = struct.unpack(">HHH", header[:6])
            pdu_length = length - 1  # minus unit ID

            body = conn.recv(pdu_length)
            if not body:
                print("[-] Client disconnected mid-PDU")
                break

            request = parse_modbus_request(header + body)
            if not request:
                print("[-] Failed to parse request")
                break

            print(f"[REQ] FC={request['func']} length={request['length']}")

            # Build a normal response
            resp = build_normal_response(request)

            # Give the fuzzer a chance to mutate it
            mutated_resp = mutate_response(resp, request)

            # Send back to client under test
            conn.sendall(mutated_resp)

    except Exception as e:
        print(f"[!] Exception: {e}")

    finally:
        conn.close()


# -------------------------------
# Main Server Loop
# -------------------------------
def start_fake_server(host="0.0.0.0", port=502):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)

    print(f"[+] Fake Modbus server listening on {host}:{port}")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_fake_server()
