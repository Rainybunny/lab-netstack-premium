/**
 * @file ip_tool.cpp
 * @brief CL2 fragmentation sender and receiver.
 *
 *   fragsend SRC DST BYTES   send one large IPv4 datagram (protocol 253)
 *   fragrecv                 print the reassembled datagram and stop
 */

#include "ip.h"
#include "netstack.h"
#include "packetio.h"
#include "utils.h"

#include <arpa/inet.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

constexpr int FRAGMENT_PROTOCOL = 253;

bool patternOk(const uint8_t* payload, int length) {
    if (length < 4 || std::memcmp(payload, "FRAG", 4) != 0) {
        return false;
    }
    for (int index = 4; index < length; ++index) {
        if (payload[index] != uint8_t(index * 7 + 3)) {
            return false;
        }
    }
    return true;
}

int onPacket(const void* buffer, int len) {
    const auto* packet = static_cast<const uint8_t*>(buffer);
    if (len < int(IP_HEADER_LEN) || packet[9] != FRAGMENT_PROTOCOL) {
        return 0;
    }
    const int ihl = (packet[0] & 0x0f) * 4;
    const int payloadLength = len - ihl;
    printf("RECEIVED length=%d payload=%d pattern=%s\n", len, payloadLength,
           patternOk(packet + ihl, payloadLength) ? "ok" : "bad");
    fflush(stdout);
    stopReceiveLoop();
    return 0;
}

bool parseAddress(const char* text, in_addr& address) {
    return inet_pton(AF_INET, text, &address) == 1;
}

} // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (netstackInit() < 0) {
        fprintf(stderr, "netstack initialization failed\n");
        return 1;
    }

    if (argc == 2 && std::strcmp(argv[1], "fragrecv") == 0) {
        setIPPacketReceiveCallback(onPacket);
        return netstackRun() == 0 ? 0 : 1;
    }

    if (argc == 5 && std::strcmp(argv[1], "fragsend") == 0) {
        in_addr source{};
        in_addr destination{};
        if (!parseAddress(argv[2], source) ||
            !parseAddress(argv[3], destination)) {
            fprintf(stderr, "invalid address\n");
            return 1;
        }
        const int length = std::atoi(argv[4]);
        if (length < 4 || length > 60000) {
            fprintf(stderr, "invalid length\n");
            return 1;
        }
        std::vector<uint8_t> payload(static_cast<size_t>(length));
        std::memcpy(payload.data(), "FRAG", 4);
        for (int index = 4; index < length; ++index) {
            payload[size_t(index)] = uint8_t(index * 7 + 3);
        }
        const int result = sendIPPacket(source, destination, FRAGMENT_PROTOCOL,
                                        payload.data(), length);
        printf("SENT bytes=%d result=%d\n", length, result);
        // Drive ARP and the fragment transmissions.
        for (int tick = 0; tick < 200; ++tick) {
            netstackPump(10);
        }
        return result == 0 ? 0 : 1;
    }

    fprintf(stderr, "usage: %s fragsend SRC DST BYTES | fragrecv\n", argv[0]);
    return 1;
}
