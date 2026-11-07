"""Count TCP data segments that were sent more than once in a pcap."""

import collections
import struct
import sys


def parse(path):
    data = open(path, "rb").read()
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        endian = ">"
    offset = 24
    frame = 0
    while offset + 16 <= len(data):
        seconds, micros, caplen, _ = struct.unpack_from(
            endian + "IIII", data, offset)
        offset += 16
        packet = data[offset:offset + caplen]
        offset += caplen
        frame += 1
        if len(packet) < 14:
            continue
        if struct.unpack_from("!H", packet, 12)[0] != 0x0800:
            continue
        ip = packet[14:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        total = struct.unpack_from("!H", ip, 2)[0]
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, offset_flags = struct.unpack_from(
            "!HHIIH", tcp, 0)
        doff = (offset_flags >> 12) * 4
        payload = total - ihl - doff
        yield {
            "frame": frame,
            "time": seconds + micros / 1e6,
            "src": ".".join(str(b) for b in ip[12:16]),
            "dst": ".".join(str(b) for b in ip[16:20]),
            "sport": sport,
            "dport": dport,
            "seq": seq,
            "len": payload,
            "flags": offset_flags & 0x1FF,
        }


def main():
    segments = list(parse(sys.argv[1]))
    directions = collections.defaultdict(list)
    for segment in segments:
        directions[(segment["src"], segment["sport"],
                    segment["dst"], segment["dport"])].append(segment)

    for key, items in directions.items():
        data = [item for item in items if item["len"] > 0]
        if not data:
            continue
        seen = collections.defaultdict(list)
        for item in data:
            seen[(item["seq"], item["len"])].append(item)
        repeats = {k: v for k, v in seen.items() if len(v) > 1}
        unique_bytes = sum(length for (_, length) in seen)
        print("%s:%d -> %s:%d" % (key[0], key[1], key[2], key[3]))
        print("  data segments: %d, unique payload bytes: %d" %
              (len(data), unique_bytes))
        print("  retransmitted segments: %d, repeated payload bytes: %d" %
              (sum(len(v) - 1 for v in repeats.values()),
               sum((len(v) - 1) * k[1] for k, v in repeats.items())))
        for (seq, length), copies in list(repeats.items())[:8]:
            when = ", ".join("frame %d at %.6f" % (c["frame"], c["time"])
                             for c in copies)
            print("    seq=%d len=%d sent %d times: %s" %
                  (seq, length, len(copies), when))
        fin = sum(1 for item in items if item["flags"] & 0x01)
        syn = sum(1 for item in items if item["flags"] & 0x02)
        rst = sum(1 for item in items if item["flags"] & 0x04)
        print("  SYN=%d FIN=%d RST=%d" % (syn, fin, rst))


if __name__ == "__main__":
    main()
