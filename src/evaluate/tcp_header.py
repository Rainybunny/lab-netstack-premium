"""Print a hexdump and a field-by-field explanation of one TCP header."""

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
        sport, dport, seq, ack, offset_flags, window, checksum, urgent = \
            struct.unpack_from("!HHIIHHHH", tcp, 0)
        doff = (offset_flags >> 12) * 4
        flags = offset_flags & 0x1FF
        payload = total - ihl - doff
        yield (frame, seconds, micros, packet, ip, ihl, total, tcp, doff,
               sport, dport, seq, ack, flags, window, checksum, urgent,
               payload)


def flag_text(flags):
    names = []
    for bit, name in ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                      (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
                      (0x40, "ECE"), (0x80, "CWR")):
        if flags & bit:
            names.append(name)
    return "|".join(names) if names else "none"


def ip_text(raw):
    return ".".join(str(b) for b in raw)


def main():
    path = sys.argv[1]
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 10086
    selected = None
    for entry in parse(path):
        if entry[9] != server_port and entry[17] > 0:
            selected = entry
            break
    if selected is None:
        raise SystemExit("no client data segment found")

    (frame, seconds, micros, packet, ip, ihl, total, tcp, doff, sport, dport,
     seq, ack, flags, window, checksum, urgent, payload) = selected

    print("frame: %d  time: %d.%06d" % (frame, seconds, micros))
    print("client -> server: %s:%d -> %s:%d" %
          (ip_text(ip[12:16]), sport, ip_text(ip[16:20]), dport))
    print("IPv4: version/IHL=0x%02x total=%d id=0x%04x flags/offset=0x%04x "
          "ttl=%d proto=%d checksum=0x%04x" %
          (ip[0], total, struct.unpack_from("!H", ip, 4)[0],
           struct.unpack_from("!H", ip, 6)[0], ip[8], ip[9],
           struct.unpack_from("!H", ip, 10)[0]))
    print("TCP header (%d bytes):" % doff)
    for row in range(0, doff, 16):
        chunk = tcp[row:min(row + 16, doff)]
        print("  %04x  %s" % (row, " ".join("%02x" % b for b in chunk)))
    if payload > 0:
        chunk = tcp[doff:doff + min(payload, 16)]
        print("first payload bytes:")
        print("  %04x  %s" % (doff, " ".join("%02x" % b for b in chunk)))

    print("byte 0-1   source port       = %d (0x%04x)" % (sport, sport))
    print("byte 2-3   destination port  = %d (0x%04x)" % (dport, dport))
    print("byte 4-7   sequence number   = %d (0x%08x)" % (seq, seq))
    print("byte 8-11  acknowledgment    = %d (0x%08x)" % (ack, ack))
    print("byte 12    data offset       = %d nibbles = %d bytes; "
          "reserved = 0x%x" % (tcp[12] >> 4, doff, tcp[12] & 0x0F))
    print("byte 13    flags             = 0x%02x (%s)" %
          (flags, flag_text(flags)))
    print("byte 14-15 window            = %d (0x%04x)" % (window, window))
    if doff > 20:
        print("byte 20..  options           = %s" %
              " ".join("%02x" % b for b in tcp[20:doff]))
    print("byte 16-17 checksum          = 0x%04x" % checksum)
    print("byte 18-19 urgent pointer    = %d" % urgent)

    pseudo = ip[12:20] + b"\x00\x06" + struct.pack("!H", total - ihl)
    data = pseudo + tcp
    if len(data) % 2:
        data += b"\x00"
    total_sum = 0
    for index in range(0, len(data), 2):
        total_sum += (data[index] << 8) | data[index + 1]
    while total_sum >> 16:
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)
    print("checksum input: pseudo-header %s + TCP segment (%d bytes)" %
          (pseudo.hex(" "), total - ihl))
    print("checksum verification: 0x%04x (0xffff means valid)" % total_sum)
    print("payload length: %d bytes" % payload)


if __name__ == "__main__":
    main()
