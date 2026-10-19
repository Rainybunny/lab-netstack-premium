#pragma once

#include "pcap/pcap.h"

#include <array>
#include <cstdlib>

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

constexpr size_t ETH_PAYLOAD_MAX = 1500;
constexpr size_t ETH_BUFFER_LEN = 14 + ETH_PAYLOAD_MAX;

typedef std::array<u_char, 6> macaddr_t;
typedef u_char eth_buf_t[ETH_BUFFER_LEN];
typedef char pcap_errbuf_t[PCAP_ERRBUF_SIZE + 1];
