/**
 * @file unit_tests.cpp
 * @brief Self-contained unit tests for the Lab 3 stack.
 *
 * The tests cover checksums, sequence arithmetic, routing, getaddrinfo and
 * IPv4 reassembly. They do not require network devices or pcap handles.
 */

#include "ipfrag.h"
#include "routing.h"
#include "tcp.h"
#include "utils.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <cstdio>
#include <cstring>
#include <vector>

namespace {

int failures = 0;
int tests = 0;

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                         #condition);                                        \
            ++failures;                                                      \
        }                                                                    \
    } while (false)

#define TEST(name)                                                           \
    void name();                                                             \
    struct name##Runner {                                                    \
        name##Runner() {                                                     \
            ++tests;                                                         \
            std::fprintf(stderr, "RUN %s\n", #name);                          \
            name();                                                          \
        }                                                                    \
    } name##Instance;                                                        \
    void name()

in_addr address(const char* text) {
    in_addr value{};
    inet_pton(AF_INET, text, &value);
    return value;
}

uint16_t ipChecksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t index = 0; index + 1 < length; index += 2) {
        sum += (uint16_t(data[index]) << 8) | data[index + 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return uint16_t(~sum);
}

std::vector<uint8_t> fragment(uint16_t id, int offset, bool more,
                              const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> packet(IP_HEADER_LEN + payload.size());
    packet[0] = 0x45;
    writeU16(packet.data() + 2, uint16_t(packet.size()));
    writeU16(packet.data() + 4, id);
    writeU16(packet.data() + 6,
             uint16_t((more ? 0x2000 : 0) | (offset / 8)));
    packet[8] = 64;
    packet[9] = 253;
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 2;
    std::memcpy(packet.data() + IP_HEADER_LEN, payload.data(),
                payload.size());
    writeU16(packet.data() + 10,
             ipChecksum(packet.data(), IP_HEADER_LEN));
    return packet;
}

TEST(ipChecksumDetectsCorruption) {
    uint8_t header[20] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
                          0x40, 0x06, 0x00, 0x00, 10,   0,    0,    1,
                          10,   0,    0,    2};
    const uint16_t checksum = ipChecksum(header, sizeof(header));
    header[10] = uint8_t(checksum >> 8);
    header[11] = uint8_t(checksum & 0xff);
    CHECK(ipChecksum(header, sizeof(header)) == 0);
    header[9] ^= 0x01;
    CHECK(ipChecksum(header, sizeof(header)) != 0);
}

TEST(tcpChecksumValidSegment) {
    uint8_t segment[24] = {};
    writeU16(segment, 12345);
    writeU16(segment + 2, 80);
    writeU32(segment + 4, 1000);
    writeU32(segment + 8, 2000);
    segment[12] = 0x50;
    segment[13] = 0x10;
    writeU16(segment + 14, 65535);
    segment[20] = 'h';
    segment[21] = 'i';
    const in_addr source = address("10.0.0.1");
    const in_addr destination = address("10.0.0.2");
    writeU16(segment + 16,
             tcpChecksum(source, destination, segment, sizeof(segment)));
    CHECK(tcpChecksum(source, destination, segment, sizeof(segment)) == 0);
    segment[21] ^= 0x01;
    CHECK(tcpChecksum(source, destination, segment, sizeof(segment)) != 0);
}

TEST(tcpChecksumDependsOnPseudoHeader) {
    uint8_t segment[20] = {};
    writeU16(segment, 1234);
    writeU16(segment + 2, 80);
    writeU32(segment + 4, 7);
    segment[12] = 0x50;
    segment[13] = 0x10;
    const uint16_t first =
        tcpChecksum(address("10.0.0.1"), address("10.0.0.2"), segment, 20);
    const uint16_t second =
        tcpChecksum(address("10.0.0.3"), address("10.0.0.2"), segment, 20);
    CHECK(first != second);
}

TEST(sequenceComparisonWraps) {
    CHECK(tcpSeqLess(0, 1));
    CHECK(tcpSeqLess(0xfffffffeu, 3));
    CHECK(!tcpSeqLess(3, 0xfffffffeu));
    CHECK(!tcpSeqLess(7, 7));
}

TEST(routingConnectedRoute) {
    routingInit();
    CHECK(routingAddConnected(address("10.1.0.1"),
                              address("255.255.255.0"), 3) == 0);
    RouteResult result{};
    CHECK(routingLookup(address("10.1.0.77"), result));
    CHECK(result.kind == RouteKind::Connected);
    CHECK(result.deviceId == 3);
    CHECK(result.nextHopIp.s_addr == address("10.1.0.77").s_addr);
}

TEST(routingLongestPrefix) {
    routingInit();
    CHECK(routingAddConnected(address("10.0.0.0"),
                              address("255.255.0.0"), 1) == 0);
    macaddr_t mac{1, 2, 3, 4, 5, 6};
    CHECK(routingAddStatic(address("10.0.7.0"), address("255.255.255.0"),
                           mac, 2) == 0);
    RouteResult result{};
    CHECK(routingLookup(address("10.0.7.9"), result));
    CHECK(result.kind == RouteKind::Static);
    CHECK(result.prefixLength == 24);
    CHECK(routingLookup(address("10.0.8.9"), result));
    CHECK(result.kind == RouteKind::Connected);
    CHECK(result.prefixLength == 16);
}

TEST(routingKindPriority) {
    routingInit();
    macaddr_t mac{9, 8, 7, 6, 5, 4};
    CHECK(routingAddStatic(address("10.2.0.0"), address("255.255.255.0"),
                           mac, 1) == 0);
    CHECK(routingAddConnected(address("10.2.0.0"), address("255.255.255.0"),
                              2) == 0);
    RouteResult result{};
    CHECK(routingLookup(address("10.2.0.5"), result));
    CHECK(result.kind == RouteKind::Connected);
}

TEST(routingRejectsNonContiguousMask) {
    routingInit();
    macaddr_t mac{};
    CHECK(routingAddStatic(address("10.3.0.0"), address("255.0.255.0"),
                           mac, 0) < 0);
}

TEST(routingNoRoute) {
    routingInit();
    RouteResult result{};
    CHECK(!routingLookup(address("192.168.1.1"), result));
}

TEST(getaddrinfoNumeric) {
    addrinfo* result = nullptr;
    CHECK(getaddrinfo("10.4.5.6", "8080", nullptr, &result) == 0);
    CHECK(result != nullptr);
    CHECK(result->ai_family == AF_INET);
    CHECK(result->ai_socktype == SOCK_STREAM);
    CHECK(result->ai_protocol == IPPROTO_TCP);
    CHECK(result->ai_addrlen == sizeof(sockaddr_in));
    const auto* name = reinterpret_cast<const sockaddr_in*>(result->ai_addr);
    CHECK(name->sin_addr.s_addr == address("10.4.5.6").s_addr);
    CHECK(ntohs(name->sin_port) == 8080);
    freeaddrinfo(result);
}

TEST(getaddrinfoNullNodeAndService) {
    addrinfo* result = nullptr;
    CHECK(getaddrinfo(nullptr, nullptr, nullptr, &result) == 0);
    CHECK(result != nullptr);
    const auto* name = reinterpret_cast<const sockaddr_in*>(result->ai_addr);
    CHECK(name->sin_addr.s_addr == htonl(INADDR_ANY));
    CHECK(name->sin_port == 0);
    freeaddrinfo(result);
}

TEST(getaddrinfoRejectsBadNode) {
    addrinfo* result = nullptr;
    CHECK(getaddrinfo("not-an-address", "80", nullptr, &result) ==
          EAI_NONAME);
}

TEST(getaddrinfoRejectsBadService) {
    addrinfo* result = nullptr;
    CHECK(getaddrinfo("10.4.5.6", "http", nullptr, &result) == EAI_SERVICE);
}

TEST(getaddrinfoRejectsBadFamily) {
    addrinfo hints{};
    hints.ai_family = AF_INET6;
    addrinfo* result = nullptr;
    CHECK(getaddrinfo("10.4.5.6", "80", &hints, &result) == EAI_FAMILY);
}

TEST(getaddrinfoRejectsBadSocktype) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* result = nullptr;
    CHECK(getaddrinfo("10.4.5.6", "80", &hints, &result) == EAI_SOCKTYPE);
}

TEST(reassemblyInOrder) {
    IpReassembler reassembler;
    std::vector<uint8_t> payload(3000);
    for (size_t index = 0; index < payload.size(); ++index) {
        payload[index] = uint8_t(index * 3 + 1);
    }
    const auto first = fragment(7, 0, true,
                                std::vector<uint8_t>(payload.begin(),
                                                     payload.begin() + 1480));
    const auto second = fragment(7, 1480, true,
                                 std::vector<uint8_t>(payload.begin() + 1480,
                                                      payload.begin() + 2960));
    const auto third = fragment(7, 2960, false,
                                std::vector<uint8_t>(payload.begin() + 2960,
                                                     payload.end()));
    std::vector<uint8_t> assembled;
    CHECK(!reassembler.add(first.data(), int(first.size()), assembled));
    CHECK(!reassembler.add(second.data(), int(second.size()), assembled));
    CHECK(reassembler.add(third.data(), int(third.size()), assembled));
    CHECK(assembled.size() == IP_HEADER_LEN + payload.size());
    CHECK(readU16(assembled.data() + 2) ==
          IP_HEADER_LEN + payload.size());
    CHECK(std::memcmp(assembled.data() + IP_HEADER_LEN, payload.data(),
                      payload.size()) == 0);
}

TEST(reassemblyOutOfOrder) {
    IpReassembler reassembler;
    std::vector<uint8_t> payload(3000);
    for (size_t index = 0; index < payload.size(); ++index) {
        payload[index] = uint8_t(index * 5 + 2);
    }
    const auto first = fragment(8, 0, true,
                                std::vector<uint8_t>(payload.begin(),
                                                     payload.begin() + 1480));
    const auto second = fragment(8, 1480, true,
                                 std::vector<uint8_t>(payload.begin() + 1480,
                                                      payload.begin() + 2960));
    const auto third = fragment(8, 2960, false,
                                std::vector<uint8_t>(payload.begin() + 2960,
                                                     payload.end()));
    std::vector<uint8_t> assembled;
    CHECK(!reassembler.add(third.data(), int(third.size()), assembled));
    CHECK(!reassembler.add(first.data(), int(first.size()), assembled));
    CHECK(reassembler.add(second.data(), int(second.size()), assembled));
    CHECK(assembled.size() == IP_HEADER_LEN + payload.size());
    CHECK(std::memcmp(assembled.data() + IP_HEADER_LEN, payload.data(),
                      payload.size()) == 0);
}

TEST(reassemblyIncomplete) {
    IpReassembler reassembler;
    std::vector<uint8_t> payload(3000, 0x5a);
    const auto first = fragment(9, 0, true,
                                std::vector<uint8_t>(payload.begin(),
                                                     payload.begin() + 1480));
    const auto third = fragment(9, 2960, false,
                                std::vector<uint8_t>(payload.begin() + 2960,
                                                     payload.end()));
    std::vector<uint8_t> assembled;
    CHECK(!reassembler.add(first.data(), int(first.size()), assembled));
    CHECK(!reassembler.add(third.data(), int(third.size()), assembled));
    CHECK(assembled.empty());
}

TEST(tcpChecksumOddLength) {
    uint8_t segment[21] = {};
    writeU16(segment, 4321);
    writeU16(segment + 2, 80);
    writeU32(segment + 4, 11);
    segment[12] = 0x50;
    segment[13] = 0x10;
    writeU16(segment + 14, 1024);
    segment[20] = 0x7f;
    const in_addr source = address("10.0.0.1");
    const in_addr destination = address("10.0.0.2");
    writeU16(segment + 16,
             tcpChecksum(source, destination, segment, sizeof(segment)));
    CHECK(tcpChecksum(source, destination, segment, sizeof(segment)) == 0);
}

TEST(routingDynamicRemoval) {
    routingInit();
    CHECK(routingAddDynamic(address("10.9.0.0"), address("255.255.255.0"),
                            address("10.9.0.1"), 0, 1) == 0);
    RouteResult result{};
    CHECK(routingLookup(address("10.9.0.7"), result));
    routingClearDynamic();
    CHECK(!routingLookup(address("10.9.0.7"), result));
}

TEST(reassemblyDuplicateFragment) {
    IpReassembler reassembler;
    std::vector<uint8_t> payload(1600, 0x33);
    const auto first = fragment(10, 0, true,
                                std::vector<uint8_t>(payload.begin(),
                                                     payload.begin() + 1480));
    const auto second = fragment(10, 1480, false,
                                 std::vector<uint8_t>(payload.begin() + 1480,
                                                      payload.end()));
    std::vector<uint8_t> assembled;
    CHECK(!reassembler.add(first.data(), int(first.size()), assembled));
    CHECK(!reassembler.add(first.data(), int(first.size()), assembled));
    CHECK(reassembler.add(second.data(), int(second.size()), assembled));
    CHECK(assembled.size() == IP_HEADER_LEN + payload.size());
}

} // namespace

int main() {
    if (failures == 0) {
        std::printf("ALL %d TESTS PASSED\n", tests);
        return 0;
    }
    std::printf("%d FAILURE(S) IN %d TESTS\n", failures, tests);
    return 1;
}
