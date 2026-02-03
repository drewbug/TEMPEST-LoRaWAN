#!/usr/bin/env python3
"""Listen for and decrypt Meshtastic LoRa packets from the Wio Tracker L1."""

import serial, time, glob, sys, re, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as cmodes

# Meshtastic default AES-128 key (PSK #1, "AQ==" / the default channel key)
DEFAULT_KEY = bytes([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
])

HEADER_LEN = 16  # to[4] + from[4] + id[4] + flags[1] + channel[1] + next_hop[1] + relay[1]

PORTNUM_NAMES = {
    0: "UNKNOWN",          1: "TEXT_MESSAGE",      2: "REMOTE_HARDWARE",
    3: "POSITION",         4: "NODEINFO",          5: "ROUTING",
    6: "ADMIN",            7: "TEXT_COMPRESSED",    8: "WAYPOINT",
    32: "REPLY",           33: "IP_TUNNEL",        34: "PAXCOUNTER",
    64: "SERIAL",          65: "STORE_FORWARD",    66: "RANGE_TEST",
    67: "TELEMETRY",       68: "ZPS",              69: "SIMULATOR",
    70: "TRACEROUTE",      71: "NEIGHBORINFO",     72: "ATAK_PLUGIN",
    73: "MAP_REPORT",
}

# ── AES-CTR matching Meshtastic's nonce layout ──────────────────────────

def decrypt(key, from_node, packet_id, ciphertext):
    """AES-128-CTR with Meshtastic nonce: [id:8 LE][from:4 LE][0:4]."""
    nonce = struct.pack("<QI", packet_id, from_node) + b"\x00\x00\x00\x00"
    cipher = Cipher(algorithms.AES(key), cmodes.CTR(nonce))
    return cipher.decryptor().update(ciphertext)

# ── minimal protobuf decoder ────────────────────────────────────────────

def decode_varint(buf, pos):
    val, shift = 0, 0
    while pos < len(buf):
        b = buf[pos]; pos += 1
        val |= (b & 0x7F) << shift; shift += 7
        if not (b & 0x80):
            return val, pos
    return val, pos

def decode_protobuf(buf):
    """Return dict of {field_number: value} for a simple protobuf message."""
    fields, i = {}, 0
    while i < len(buf):
        tag, i = decode_varint(buf, i)
        fnum, wtype = tag >> 3, tag & 7
        if wtype == 0:          # varint
            val, i = decode_varint(buf, i)
        elif wtype == 2:        # length-delimited
            length, i = decode_varint(buf, i)
            val = buf[i : i + length]; i += length
        elif wtype == 5:        # fixed32
            val = struct.unpack_from("<i", buf, i)[0]; i += 4
        elif wtype == 1:        # fixed64
            val = struct.unpack_from("<q", buf, i)[0]; i += 8
        else:
            break
        fields[fnum] = val
    return fields

# ── packet parsing + display ────────────────────────────────────────────

def format_node(n):
    return f"!{n:08x}"

def handle_packet(raw):
    if len(raw) <= HEADER_LEN:
        return
    to_node   = struct.unpack_from("<I", raw, 0)[0]
    from_node = struct.unpack_from("<I", raw, 4)[0]
    packet_id = struct.unpack_from("<I", raw, 8)[0]
    flags     = raw[12]
    channel   = raw[13]
    hop_limit = flags & 0x07
    hop_start = (flags >> 5) & 0x07

    encrypted = raw[HEADER_LEN:]
    plain = decrypt(DEFAULT_KEY, from_node, packet_id, encrypted)

    data = decode_protobuf(plain)
    portnum = data.get(1, 0)
    payload = data.get(2, b"")
    port_name = PORTNUM_NAMES.get(portnum, f"PORT_{portnum}")

    dest = "broadcast" if to_node == 0xFFFFFFFF else format_node(to_node)
    print(f"\n{'─'*60}")
    print(f"  From: {format_node(from_node)}  To: {dest}  Hops: {hop_start - hop_limit}/{hop_start}")
    print(f"  Port: {port_name} ({portnum})  ID: 0x{packet_id:08x}  Ch: {channel}")

    if portnum == 1:  # TEXT_MESSAGE
        try:
            print(f"  Message: {payload.decode('utf-8')}")
        except Exception:
            print(f"  Message (raw): {payload.hex()}")

    elif portnum == 4 and isinstance(payload, (bytes, bytearray)):  # NODEINFO
        user = decode_protobuf(payload)
        long_name  = user.get(2, b"").decode("utf-8", errors="replace") if isinstance(user.get(2), (bytes, bytearray)) else "?"
        short_name = user.get(3, b"").decode("utf-8", errors="replace") if isinstance(user.get(3), (bytes, bytearray)) else "?"
        hw_model   = user.get(4, "?")
        print(f"  Node: {long_name} ({short_name})  hw_model: {hw_model}")

    elif portnum == 3 and isinstance(payload, (bytes, bytearray)):  # POSITION
        pos = decode_protobuf(payload)
        lat = pos.get(1, 0) / 1e7 if isinstance(pos.get(1), int) else None
        lon = pos.get(2, 0) / 1e7 if isinstance(pos.get(2), int) else None
        alt = pos.get(3, None)
        parts = []
        if lat is not None: parts.append(f"lat={lat:.6f}")
        if lon is not None: parts.append(f"lon={lon:.6f}")
        if alt is not None: parts.append(f"alt={alt}m")
        print(f"  Position: {', '.join(parts) if parts else payload.hex()}")

    elif portnum == 67 and isinstance(payload, (bytes, bytearray)):  # TELEMETRY
        print(f"  Telemetry: {payload.hex()}")

    else:
        if isinstance(payload, (bytes, bytearray)) and len(payload) > 0:
            print(f"  Payload: {payload.hex()}")

# ── serial reader ───────────────────────────────────────────────────────

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else None
    if not port:
        acm = glob.glob("/dev/ttyACM*")
        if not acm:
            print("No /dev/ttyACM* found. Pass port as argument.")
            sys.exit(1)
        port = acm[0]

    print(f"Listening on {port} at 115200 baud…  Ctrl+C to stop.")

    ser = serial.Serial(port, 115200, timeout=1)
    ser.dtr = True

    line_buf = ""
    current_hex = None
    current_rssi = None
    current_snr = None

    try:
        while True:
            chunk = ser.read(ser.in_waiting or 1)
            if not chunk:
                time.sleep(0.05)
                continue
            line_buf += chunk.decode("utf-8", errors="replace")
            while "\n" in line_buf:
                line, line_buf = line_buf.split("\n", 1)
                line = line.strip()

                m = re.match(r"\[SX1262\] Data \(hex\):\s+(.*)", line)
                if m:
                    try:
                        current_hex = bytes.fromhex(m.group(1).replace(" ", ""))
                    except ValueError:
                        current_hex = None
                    continue

                m = re.match(r"\[SX1262\] RSSI:\s+(-?[\d.]+)", line)
                if m:
                    current_rssi = m.group(1)
                    continue

                m = re.match(r"\[SX1262\] SNR:\s+(-?[\d.]+)", line)
                if m:
                    current_snr = m.group(1)
                    # SNR is the last field — process the packet
                    if current_hex:
                        print(f"  RSSI: {current_rssi} dBm  SNR: {current_snr} dB", end="")
                        try:
                            handle_packet(current_hex)
                        except Exception as e:
                            print(f"\n  [decode error: {e}]")
                    current_hex = current_rssi = current_snr = None
                    continue

                # pass through other lines (boot messages etc.)
                if line:
                    print(line)

    except KeyboardInterrupt:
        pass
    finally:
        ser.close()
        print("\n--- stopped ---")

if __name__ == "__main__":
    main()
