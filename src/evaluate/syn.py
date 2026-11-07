"""Print SYN, SYN-ACK, FIN and RST segments from a pcap."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcap_tcp


def main():
    path = sys.argv[1]
    for number, when, ether_type, packet in pcap_tcp.frames(path):
        if ether_type != 0x0800:
            continue
        segment = pcap_tcp.ipv4_tcp(packet)
        if segment is None:
            continue
        flags = segment["flags"]
        if not flags & 0x07:
            continue
        names = []
        for bit, name in ((0x02, "SYN"), (0x01, "FIN"), (0x04, "RST"),
                          (0x10, "ACK")):
            if flags & bit:
                names.append(name)
        print("frame %d t=%.6f %s:%d -> %s:%d seq=%u ack=%u flags=%s" %
              (number, when, segment["src"], segment["sport"],
               segment["dst"], segment["dport"], segment["seq"],
               segment["ack"], "|".join(names)))


if __name__ == "__main__":
    main()
