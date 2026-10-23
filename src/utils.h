#pragma once

#include "pcap/pcap.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <chrono>

#define ASSERT(expr) \
    do { \
        if (!static_cast<bool>(expr)) { \
            PANIC("assertion failed: %s", #expr); \
        } \
    } while (false)

#define WARN(fmt, ...) \
    fprintf(stderr, "warning " __FILE__ ": %d: " fmt, \
            __LINE__ __VA_OPT__(,) __VA_ARGS__)

#define PANIC(fmt, ...) \
    do { \
        fprintf(stderr, "panic " __FILE__ ": %d: " fmt, \
                __LINE__ __VA_OPT__(,) __VA_ARGS__); \
        exit(1); \
    } while (false)

constexpr size_t ETH_HEADER_LEN = 14;
constexpr size_t ETH_PAYLOAD_MAX = 1500;
constexpr size_t ETH_BUFFER_LEN = ETH_HEADER_LEN + ETH_PAYLOAD_MAX;

constexpr size_t IP_HEADER_LEN = 20;
// An IP packet must fit in one Ethernet payload; the header is part of that
// budget, so the maximum payload is 1480 bytes.
constexpr size_t IP_MAX_LEN = ETH_PAYLOAD_MAX;
constexpr size_t IP_MAX_PAYLOAD = IP_MAX_LEN - IP_HEADER_LEN;

// EtherTypes used by this stack. The link-state control plane deliberately
// uses a local experimental EtherType instead of IP to avoid a circular
// dependency on the routing table it is computing.
constexpr uint16_t ETH_TYPE_IPV4 = 0x0800;
constexpr uint16_t ETH_TYPE_ARP = 0x0806;
constexpr uint16_t ETH_TYPE_LINK_STATE = 0x88b6;

typedef std::array<uint8_t, 6> macaddr_t;
typedef uint8_t eth_buf_t[ETH_BUFFER_LEN];
typedef uint8_t ip_buf_t[IP_MAX_LEN];
typedef char pcap_errbuf_t[PCAP_ERRBUF_SIZE + 1];

typedef decltype(std::chrono::steady_clock().now()) TimePoint;

// Network byte order helpers. They are inline so ARP and link-state wire
// formats can use the same primitives as IPv4.
inline uint16_t readU16(const uint8_t* data) {
    return (uint16_t)(((uint16_t)(data[0]) << 8) | data[1]);
}

inline uint32_t readU32(const uint8_t* data) {
    return (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) |
           (uint32_t(data[2]) << 8 ) |  uint32_t(data[3]);
}

inline uint64_t readU64(const uint8_t* data) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | data[i];
    }
    return value;
}

inline void writeU16(uint8_t* data, uint16_t value) {
    data[0] = uint8_t(value >> 8);
    data[1] = uint8_t(value & 0xff);
}

inline void writeU32(uint8_t* data, uint32_t value) {
    data[0] = uint8_t(value >> 24);
    data[1] = uint8_t(value >> 16);
    data[2] = uint8_t(value >> 8);
    data[3] = uint8_t(value & 0xff);
}

inline void writeU64(uint8_t* data, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        data[i] = uint8_t(value & 0xff);
        value >>= 8;
    }
}
