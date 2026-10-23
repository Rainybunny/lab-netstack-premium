#include "arp.h"

#include "device.h"
#include "packetio.h"

#include <map>
#include <cstring>

namespace {

constexpr auto ARP_REQUEST_RETRY_DUR = std::chrono::milliseconds(ARP_REQUEST_RETRY_MS);
constexpr auto ARP_CACHE_TIMEOUT_DUR = std::chrono::milliseconds(ARP_CACHE_TIMEOUT_MS);

struct ArpKey {
    int deviceId;
    in_addr nextHop;
    inline bool operator < (const ArpKey& oth) const {
        if (deviceId != oth.deviceId) {
            return deviceId < oth.deviceId;
        } else {
            return nextHop.s_addr < oth.nextHop.s_addr;
        }
    }
};

struct ArpEntry {
    macaddr_t mac;
    TimePoint lastCached, lastRequest;
    int retries;
    bool resolving;
    std::vector<std::vector<uint8_t>> pending;
    ArpEntry():
        mac(),
        lastCached(std::chrono::steady_clock().now()),
        lastRequest(),
        retries(0),
        resolving(true), // to be resolved
        pending() {}
};

std::map<ArpKey, ArpEntry> cache;

int sendArpRequest(int deviceId, in_addr hop) {
    ether_arp pkt{};
    pkt.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    pkt.ea_hdr.ar_pro = htons(ARP_PROTOCOL_IPV4);
    pkt.ea_hdr.ar_hln = ARP_HARDWARE_LEN;
    pkt.ea_hdr.ar_pln = ARP_PROTOCOL_LEN;
    pkt.ea_hdr.ar_op = htons(ARPOP_REQUEST);

    auto sha = getMac(deviceId);
    if (!sha.has_value()) {
        return -1;
    }
    std::memcpy(pkt.arp_sha, sha.value().data(), ARP_HARDWARE_LEN);

    auto spa = getDeviceAddresses(deviceId);
    if (spa.empty()) {
        return -1;
    }

    // use the first IP address; in_addr_t is big-endian
    std::memcpy(pkt.arp_spa, &spa[0].address.s_addr, ARP_PROTOCOL_LEN);

    // already 0
    // pkt.arp_tha = 0;

    std::memcpy(pkt.arp_tpa, &hop.s_addr, ARP_PROTOCOL_LEN);

    macaddr_t mask{};
    mask.fill(0xff);
    return sendFrame(&pkt, ARP_PACKET_LEN, ETH_TYPE_ARP, mask.data(), deviceId);
}

int sendArpReply(int deviceId, const ether_arp &req) {
    ether_arp pkt = req;
    pkt.ea_hdr.ar_op = htons(ARPOP_REPLY); // request -> reply
    std::swap(pkt.arp_tha, pkt.arp_sha); // sender <-> target
    std::swap(pkt.arp_tpa, pkt.arp_spa);

    auto sha = getMac(deviceId);
    if (!sha.has_value()) {
        return -1;
    }
    std::memcpy(pkt.arp_sha, sha.value().data(), ARP_HARDWARE_LEN); // the answer

    return sendFrame(&pkt, ARP_PACKET_LEN, ETH_TYPE_ARP, pkt.arp_tha, deviceId);
}

void updateCache(int deviceId, const ether_arp& pkt) {
    in_addr hop;
    memcpy(&hop, pkt.arp_spa, ARP_PROTOCOL_LEN);
    if (!hop.s_addr) {
        return;
    }

    ArpKey key = { deviceId, hop };
    auto it = cache.find(key);

    if (it == cache.end()) {
        it = cache.emplace(key, ArpEntry()).first;
    } else {
        it->second.lastCached = std::chrono::steady_clock().now();
    }

    memcpy(it->second.mac.data(), pkt.arp_sha, ARP_HARDWARE_LEN);
    it->second.resolving = false;
    it->second.retries = 0;

    const auto mac = it->second.mac;
    for (auto& que = it->second.pending; que.size(); que.pop_back()) {
        auto pkt = que.back();
        if (sendFrame(pkt.data(), pkt.size(), ETH_TYPE_IPV4,
                      mac.data(), deviceId) < 0) {
            // failed... let's resolve again
            it->second.resolving = true;
            return;
        }
    }
}

} // namespace

int arpInit() {
    cache.clear();
    return 0;
}

int arpReceiveFrame(const void* frame, int len, int deviceId) {
    if (frame == nullptr || len < int(ETH_HEADER_LEN + ARP_PACKET_LEN)) {
        return 0;
    }

    ether_arp pkt{};
    memcpy(&pkt, (uint8_t*)frame + ETH_HEADER_LEN, ARP_PACKET_LEN);
    if (pkt.ea_hdr.ar_hrd != htons(ARPHRD_ETHER) ||
        pkt.ea_hdr.ar_pro != htons(ARP_PROTOCOL_IPV4) ||
        pkt.ea_hdr.ar_hln != ARP_HARDWARE_LEN ||
        pkt.ea_hdr.ar_pln != ARP_PROTOCOL_LEN) {
        return 0; // we think it's ignored instead of malformed
    }

    auto mac = getMac(deviceId);
    if (!mac.has_value()) {
        return -1; // shouldn't happen
    }

    if (pkt.ea_hdr.ar_op == htons(ARPOP_REQUEST)) {
        in_addr tpa;
        memcpy(&tpa, pkt.arp_tpa, ARP_PROTOCOL_LEN);
        if (!isLocalAddress(deviceId, tpa)) { // not for us
            return 0;
        }

        updateCache(deviceId, pkt);
        return sendArpReply(deviceId, pkt);
    }

    if (pkt.ea_hdr.ar_op == htons(ARPOP_REPLY)) {
        if (memcmp(mac.value().data(), pkt.arp_tha, ARP_HARDWARE_LEN)) {
            return 0; // not for us
        }
        updateCache(deviceId, pkt);
    } // may fall-through
    return 0;
}

ArpResult arpSendWithResolution(int deviceId, in_addr nextHopId,
                                const void* packet, int len) {
    // TODO:
    // 1. Look up (deviceId, nextHopIp) in the cache.
    // 2. If valid, send the packet with sendFrame() and return Sent.
    // 3. Otherwise send a broadcast ARP request, copy the packet into the
    //    pending queue, and return Queued.

    if (packet == nullptr || len < 0) {
        return ArpResult::Failed;
    }

    ArpKey key = { deviceId, nextHopId };
    auto it = cache.find(key);
    if (it != cache.end() && !it->second.resolving) {
        auto now = std::chrono::steady_clock().now();
        if (now - it->second.lastCached >= ARP_CACHE_TIMEOUT_DUR) {
            it->second.resolving = true;
        } else if (sendFrame(packet, len, ETH_TYPE_IPV4,
                   it->second.mac.data(), deviceId) < 0) {
            it->second.resolving = true;
        } else {
            return ArpResult::Sent;
        }
    }

    if (it == cache.end()) {
        it = cache.emplace(key, ArpEntry()).first;
        if (sendArpRequest(deviceId, nextHopId) < 0) {
            cache.erase(it);
            return ArpResult::Failed;
        }
        it->second.lastRequest = std::chrono::steady_clock().now();
    }

    if (it->second.pending.size() >= ARP_MAX_PENDING_PACKETS) {
        return ArpResult::Failed;
    }

    it->second.pending.emplace_back((uint8_t*)packet, (uint8_t*)packet + len);
    return ArpResult::Queued;
}

void arpTick(TimePoint now) {
    for (auto it = cache.begin(); it != cache.end(); ) {
        auto [deviceId, nextHop] = it->first;
        auto &entry = it->second;
        if (entry.resolving) {
            if (now - entry.lastRequest >= ARP_REQUEST_RETRY_DUR) {
                if (entry.retries >= ARP_MAX_RETRIES) {
                    it = cache.erase(it);
                } else {
                    // no need to care about the return value
                    sendArpRequest(deviceId, nextHop);
                    ++entry.retries, entry.lastRequest = now;
                    ++it;
                }
            } else {
                ++it;
            }
        } else {
            if (now - entry.lastCached >= ARP_CACHE_TIMEOUT_DUR) {
                it = cache.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void arpFlushDevice(int deviceId) {
    auto left = cache.lower_bound({ deviceId, 0 });
    auto right = cache.upper_bound({ deviceId, (in_addr_t)-1 });
    cache.erase(left, right);
}
