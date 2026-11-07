"""Print IPv4 fragments of one protocol from a pcap."""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcap_tcp


def main():
    path = sys.argv[1]
    protocol = int(sys.argv[2]) if len(sys.argv) > 2 else 253
    total_payload = 0
    for number, when, ether_type, packet in pcap_tcp.frames(path):
        if ether_type != 0x0800 or len(packet) < 20:
            continue
        if packet[0] >> 4 != 4 or packet[9] != protocol:
            continue
        ihl = (packet[0] & 15) * 4
        length = struct.unpack_from("!H", packet, 2)[0]
        identification = struct.unpack_from("!H", packet, 4)[0]
        field = struct.unpack_from("!H", packet, 6)[0]
        more = 1 if field & 0x2000 else 0
        offset = (field & 0x1FFF) * 8
        payload = length - ihl
        total_payload += payload
        print("frame %d t=%.6f id=%d mf=%d offset=%d payload=%d" %
              (number, when, identification, more, offset, payload))
    print("total fragment payload bytes: %d" % total_payload)


if __name__ == "__main__":
    main()
