#include "ipfrag.h"

#include <algorithm>
#include <cstring>

namespace {

constexpr uint32_t FRAGMENT_TIMEOUT_MS = 30000;

uint16_t headerChecksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t index = 0; index + 1 < len; index += 2) {
        sum += (uint16_t(data[index]) << 8) | data[index + 1];
    }
    if (len & 1) {
        sum += uint16_t(data[len - 1]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return uint16_t(~sum);
}

} // namespace

bool IpReassembler::Key::operator<(const Key& other) const {
    if (source != other.source) {
        return source < other.source;
    }
    if (destination != other.destination) {
        return destination < other.destination;
    }
    if (id != other.id) {
        return id < other.id;
    }
    return protocol < other.protocol;
}

bool IpReassembler::add(const void* packet, int len,
                        std::vector<uint8_t>& assembled) {
    if (packet == nullptr || len < int(IP_HEADER_LEN)) {
        return false;
    }
    const auto* ip = static_cast<const uint8_t*>(packet);
    const int ihl = (ip[0] & 0x0f) * 4;
    const int totalLength = readU16(ip + 2);
    if (ihl != int(IP_HEADER_LEN) || totalLength < ihl ||
        totalLength > len) {
        return false;
    }
    const uint16_t fragment = readU16(ip + 6);
    const int offset = (fragment & 0x1fff) * 8;
    const bool more = (fragment & 0x2000) != 0;
    const int payloadLength = totalLength - ihl;
    if (offset + payloadLength > int(MAX_PAYLOAD)) {
        return false;
    }

    Key key{};
    key.source = readU32(ip + 12);
    key.destination = readU32(ip + 16);
    key.id = readU16(ip + 4);
    key.protocol = ip[9];

    const TimePoint now = std::chrono::steady_clock().now();
    auto it = entries.find(key);
    if (it == entries.end()) {
        if (entries.size() >= MAX_ENTRIES) {
            auto oldest = entries.begin();
            for (auto candidate = entries.begin(); candidate != entries.end();
                 ++candidate) {
                if (candidate->second.lastSeen < oldest->second.lastSeen) {
                    oldest = candidate;
                }
            }
            entries.erase(oldest);
        }
        it = entries.emplace(key, Entry{}).first;
    }

    Entry& entry = it->second;
    entry.lastSeen = now;
    if (offset == 0) {
        std::memcpy(entry.header, ip, IP_HEADER_LEN);
        entry.haveHeader = true;
    }
    std::memcpy(entry.data.data() + offset, ip + ihl, size_t(payloadLength));
    for (int index = 0; index < payloadLength; ++index) {
        entry.present[size_t(offset + index)] = true;
    }
    if (!more) {
        entry.totalLength = offset + payloadLength;
    }
    if (!entry.haveHeader || entry.totalLength < 0) {
        return false;
    }
    for (int index = 0; index < entry.totalLength; ++index) {
        if (!entry.present[size_t(index)]) {
            return false;
        }
    }

    assembled.resize(size_t(IP_HEADER_LEN) + size_t(entry.totalLength));
    std::memcpy(assembled.data(), entry.header, IP_HEADER_LEN);
    writeU16(assembled.data() + 2,
             uint16_t(IP_HEADER_LEN + size_t(entry.totalLength)));
    writeU16(assembled.data() + 6, 0); // no more fragments
    writeU16(assembled.data() + 10, 0);
    writeU16(assembled.data() + 10,
             headerChecksum(assembled.data(), IP_HEADER_LEN));
    std::memcpy(assembled.data() + IP_HEADER_LEN, entry.data.data(),
                size_t(entry.totalLength));
    entries.erase(it);
    return true;
}

void IpReassembler::tick(TimePoint now) {
    for (auto it = entries.begin(); it != entries.end();) {
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - it->second.lastSeen)
                             .count();
        if (age >= FRAGMENT_TIMEOUT_MS) {
            it = entries.erase(it);
        } else {
            ++it;
        }
    }
}

void IpReassembler::clear() {
    entries.clear();
}
