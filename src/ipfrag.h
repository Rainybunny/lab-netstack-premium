/**
 * @file ipfrag.h
 * @brief IPv4 fragment reassembly.
 */

#pragma once

#include "utils.h"

#include <cstdint>
#include <map>
#include <vector>

/**
 * Reassemble IPv4 fragments addressed to a local interface.
 *
 * The reassembler keeps at most a small number of datagrams; each entry
 * reserves the maximum IPv4 payload, so the memory bound is explicit.
 */
class IpReassembler {
public:
    static constexpr size_t MAX_PAYLOAD = 65535 - IP_HEADER_LEN;
    static constexpr size_t MAX_ENTRIES = 8;

    /**
     * Add one fragment.
     *
     * @param packet Complete IPv4 fragment (header and payload).
     * @param len Fragment length from the IPv4 total-length field.
     * @param assembled Receives the complete IPv4 packet when reassembly
     * finishes.
     * @return true when @p assembled holds a complete packet.
     */
    bool add(const void* packet, int len, std::vector<uint8_t>& assembled);

    /**
     * Drop reassembly entries that have been idle for too long.
     */
    void tick(TimePoint now);

    /**
     * Drop all entries.
     */
    void clear();

private:
    struct Key {
        uint32_t source;
        uint32_t destination;
        uint16_t id;
        uint8_t protocol;
        bool operator<(const Key& other) const;
    };

    struct Entry {
        std::vector<uint8_t> data = std::vector<uint8_t>(MAX_PAYLOAD);
        std::vector<bool> present = std::vector<bool>(MAX_PAYLOAD);
        uint8_t header[IP_HEADER_LEN] = {};
        bool haveHeader = false;
        int totalLength = -1;
        TimePoint lastSeen;
    };

    std::map<Key, Entry> entries;
};
