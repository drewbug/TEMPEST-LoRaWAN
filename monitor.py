#!/usr/bin/env python3
"""Stream serial console output from the TEMPEST-LoRa relay."""

import serial
import sys
import glob
import time

BAUD = 115200

def find_port():
    ports = sorted(glob.glob("/dev/ttyACM*"))
    if not ports:
        print("No /dev/ttyACM* device found. Is the board plugged in?")
        sys.exit(1)
    return ports[0]

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else find_port()
    print(f"Connecting to {port} @ {BAUD} baud  (Ctrl-C to quit)")

    ser = serial.Serial(port, BAUD, timeout=1)
    ser.dtr = True
    try:
        while True:
            line = ser.readline()
            if line:
                print(line.decode("utf-8", errors="replace"), end="")
    except KeyboardInterrupt:
        print("\nDisconnected.")
    finally:
        ser.close()

if __name__ == "__main__":
    main()
