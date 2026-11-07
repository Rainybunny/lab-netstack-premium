import argparse
import socket
import struct
import time

ETH_P_ALL = 3

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("iface")
    parser.add_argument("output")
    parser.add_argument("--seconds", type=float, default=10.0)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    sock.bind((args.iface, 0))
    sock.settimeout(0.2)

    start = time.monotonic()
    with open(args.output, "wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 262144, 1))
        while time.monotonic() - start < args.seconds:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            now = time.time()
            seconds = int(now)
            micros = int((now - seconds) * 1000000)
            output.write(struct.pack("<IIII", seconds, micros, len(data),
                                     len(data)))
            output.write(data)
            output.flush()


if __name__ == "__main__":
    main()
