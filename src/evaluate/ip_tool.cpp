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

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

constexpr int FRAGMENT_PROTOCOL = 253;

std::string ipText(in_addr address) {
    char buffer[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &address, buffer, sizeof(buffer));
    return buffer;
}

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

std::map<uint32_t, uint64_t> rawCounts;

int onRawPacket(const void* buffer, int len) {
    const auto* packet = static_cast<const uint8_t*>(buffer);
    if (len < int(IP_HEADER_LEN) || packet[9] != FRAGMENT_PROTOCOL) {
        return 0;
    }
    const int ihl = (packet[0] & 0x0f) * 4;
    in_addr source{};
    std::memcpy(&source, packet + 12, sizeof(source));
    rawCounts[source.s_addr] += uint64_t(len - ihl);
    return 0;
}

int runRawSink(int seconds) {
    setIPPacketReceiveCallback(onRawPacket);
    auto start = std::chrono::steady_clock().now();
    auto last = start;
    while (true) {
        const auto now = std::chrono::steady_clock().now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - start)
                .count() >= seconds) {
            break;
        }
        netstackPump(10);
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last)
                .count() >= 1000) {
            last = now;
            for (const auto& [address, bytes] : rawCounts) {
                in_addr value{};
                value.s_addr = address;
                printf("FLOW %s %llu\n", ipText(value).c_str(),
                       static_cast<unsigned long long>(bytes));
            }
        }
    }
    for (const auto& [address, bytes] : rawCounts) {
        in_addr value{};
        value.s_addr = address;
        printf("TOTAL %s %llu\n", ipText(value).c_str(),
               static_cast<unsigned long long>(bytes));
    }
    fflush(stdout);
    return 0;
}

int runRawSend(const char* sourceText, const char* destinationText,
               int seconds) {
    in_addr source{};
    in_addr destination{};
    if (!parseAddress(sourceText, source) ||
        !parseAddress(destinationText, destination)) {
        fprintf(stderr, "invalid address\n");
        return 1;
    }
    std::vector<uint8_t> payload(1000);
    payload[0] = 'R';
    payload[1] = 'A';
    payload[2] = 'W';
    payload[3] = 'F';
    for (size_t index = 4; index < payload.size(); ++index) {
        payload[index] = uint8_t(index * 11 + 5);
    }
    const auto deadline = std::chrono::steady_clock().now() +
                          std::chrono::seconds(seconds);
    uint64_t packets = 0;
    while (std::chrono::steady_clock().now() < deadline) {
        if (sendIPPacket(source, destination, FRAGMENT_PROTOCOL,
                         payload.data(), int(payload.size())) < 0) {
            netstackPump(10); // wait for the route or ARP resolution
            continue;
        }
        ++packets;
        // Pace at roughly 500 packets/s and keep the control plane alive.
        netstackPump(2);
    }
    printf("SENT packets=%llu bytes=%llu\n",
           static_cast<unsigned long long>(packets),
           static_cast<unsigned long long>(packets * payload.size()));
    return 0;
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

    if (argc == 3 && std::strcmp(argv[1], "rawsink") == 0) {
        return runRawSink(std::atoi(argv[2]));
    }

    if (argc == 5 && std::strcmp(argv[1], "rawsend") == 0) {
        return runRawSend(argv[2], argv[3], std::atoi(argv[4]));
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
