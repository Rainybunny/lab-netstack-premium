"""Summarize advertised TCP windows in a pcap and show zero-window events."""

import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcap_tcp


def main():
    path = sys.argv[1]
    ack_segments = collections.defaultdict(list)
    for number, when, ether_type, packet in pcap_tcp.frames(path):
        if ether_type != 0x0800:
            continue
        segment = pcap_tcp.ipv4_tcp(packet)
        if segment is None or not segment["flags"] & 0x10:
            continue
        key = (segment["src"], segment["sport"], segment["dst"],
               segment["dport"])
        ack_segments[key].append((number, when, segment["window"]))

    for key, items in ack_segments.items():
        windows = [item[2] for item in items]
        zeros = [item for item in items if item[2] == 0]
        print("%s:%d -> %s:%d: %d ACKs, window min=%d max=%d zero=%d" %
              (key[0], key[1], key[2], key[3], len(items), min(windows),
               max(windows), len(zeros)))
        for number, when, window in zeros[:5]:
            print("  zero window at frame %d t=%.6f" % (number, when))
        if zeros:
            first_zero = next(index for index, item in enumerate(items)
                              if item[2] == 0)
            start = max(0, first_zero - 3)
            end = min(len(items), first_zero + 8)
            print("  window timeline around the first zero:")
            for number, when, window in items[start:end]:
                print("    frame %d t=%.6f window=%d" %
                      (number, when, window))


if __name__ == "__main__":
    main()
