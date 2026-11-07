"""Shared minimal pcap/TCP parser used by the Lab 3 analysis scripts."""

import struct


def frames(path):
    data = open(path, "rb").read()
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        endian = ">"
    offset = 24
    number = 0
    while offset + 16 <= len(data):
        seconds, micros, caplen, _ = struct.unpack_from(
            endian + "IIII", data, offset)
        offset += 16
        packet = data[offset:offset + caplen]
        offset += caplen
        number += 1
        if len(packet) < 14:
            continue
        ether_type = struct.unpack_from("!H", packet, 12)[0]
        yield number, seconds + micros / 1e6, ether_type, packet[14:]


def ipv4_tcp(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != 6:
        return None
    ihl = (packet[0] & 15) * 4
    total = struct.unpack_from("!H", packet, 2)[0]
    if len(packet) < total or total < ihl + 20:
        return None
    tcp = packet[ihl:total]
    sport, dport, seq, ack, offset_flags, window, checksum, urgent = \
        struct.unpack_from("!HHIIHHHH", tcp, 0)
    doff = (offset_flags >> 12) * 4
    return {
        "src": ".".join(str(b) for b in packet[12:16]),
        "dst": ".".join(str(b) for b in packet[16:20]),
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "flags": offset_flags & 0x1FF,
        "window": window,
        "payload": total - ihl - doff,
        "checksum_offset": ihl + 16,
        "segment": tcp,
    }
