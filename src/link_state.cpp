#include "link_state.h"

#include "device.h"
#include "packetio.h"
#include "routing.h"

#include <arpa/inet.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <queue>
#include <string>
#include <vector>

namespace {

constexpr size_t LS_COMMON_LEN = 16;
constexpr size_t LS_HELLO_LEN = 24;
constexpr size_t LS_LSA_FIXED_LEN = 24;
constexpr size_t LS_LINK_LEN = 8;
constexpr size_t LS_PREFIX_LEN = 12;

constexpr auto HELLO_INTERVAL = std::chrono::milliseconds(HELLO_INTERVAL_MS);
constexpr auto NEIGHBOR_DEAD_INTERVAL =
    std::chrono::milliseconds(NEIGHBOR_DEAD_INTERVAL_MS);
constexpr auto LSA_REFRESH_INTERVAL =
    std::chrono::milliseconds(LSA_REFRESH_INTERVAL_MS);
constexpr auto LSA_MAX_AGE = std::chrono::milliseconds(LSA_MAX_AGE_MS);

struct Neighbor {
    uint32_t routerId;
    in_addr ip;
    TimePoint lastHello;
};

struct LsaLink {
    uint32_t neighborId;
    uint16_t cost;
};

struct LsaPrefix {
    uint32_t network;
    uint32_t mask;
    uint16_t metric;
};

struct Lsa {
    uint32_t routerId = 0;
    uint64_t sequence = 0;
    TimePoint lastSeen;
    std::vector<LsaLink> links;
    std::vector<LsaPrefix> prefixes;
};

uint32_t localRouterId = 0;
uint64_t localSequence = 0;
TimePoint lastHello;
TimePoint lastLsaRefresh;
bool localLsaDirty = true;
bool spfDirty = true;

std::map<int, int> linkCosts;
std::map<int, Neighbor> neighbors;
std::map<uint32_t, Lsa> lsdb;
std::map<uint32_t, int> lastDistances;

uint32_t ipToU32(in_addr address) {
    return ntohl(address.s_addr);
}

in_addr u32ToIp(uint32_t value) {
    in_addr address{};
    address.s_addr = htonl(value);
    return address;
}

std::string ipToString(uint32_t value) {
    char buffer[INET_ADDRSTRLEN] = {};
    const in_addr address = u32ToIp(value);
    inet_ntop(AF_INET, &address, buffer, sizeof(buffer));
    return buffer;
}

int linkCost(int deviceId) {
    const auto entry = linkCosts.find(deviceId);
    return entry == linkCosts.end() ? DEFAULT_LINK_COST : entry->second;
}

/**
 * Encode an LSA into an Ethernet payload buffer.
 *
 * @return Message length, or -1 if it does not fit.
 */
int encodeLsa(const Lsa& lsa, uint8_t* buffer) {
    const size_t length = LS_LSA_FIXED_LEN + lsa.links.size() * LS_LINK_LEN +
                          lsa.prefixes.size() * LS_PREFIX_LEN;
    if (length > ETH_PAYLOAD_MAX) {
        return -1;
    }

    std::memset(buffer, 0, length);
    buffer[0] = LINK_STATE_VERSION;
    buffer[1] = LINK_STATE_LSA;
    writeU16(buffer + 2, uint16_t(length));
    writeU32(buffer + 4, lsa.routerId);
    writeU64(buffer + 8, lsa.sequence);

    writeU16(buffer + 16, uint16_t(lsa.links.size()));
    writeU16(buffer + 18, uint16_t(lsa.prefixes.size()));
    size_t offset = LS_LSA_FIXED_LEN;
    for (const auto& link : lsa.links) {
        writeU32(buffer + offset, link.neighborId);
        writeU16(buffer + offset + 4, link.cost);
        offset += LS_LINK_LEN;
    }
    for (const auto& prefix : lsa.prefixes) {
        writeU32(buffer + offset, prefix.network);
        writeU32(buffer + offset + 4, prefix.mask);
        writeU16(buffer + offset + 8, prefix.metric);
        offset += LS_PREFIX_LEN;
    }
    return int(length);
}

void floodMessage(const uint8_t* message, int length, int excludeDevice) {
    macaddr_t broadcast{};
    broadcast.fill(0xff);
    for (int deviceId : getActiveDeviceIds()) {
        if (deviceId == excludeDevice) {
            continue;
        }
        sendFrame(message, length, ETH_TYPE_LINK_STATE, broadcast.data(),
                  deviceId);
    }
}

void sendHellos() {
    macaddr_t broadcast{};
    broadcast.fill(0xff);
    for (int deviceId : getActiveDeviceIds()) {
        const auto addresses = getDeviceAddresses(deviceId);
        if (addresses.empty()) {
            continue;
        }
        uint8_t buffer[LS_HELLO_LEN] = {};
        buffer[0] = LINK_STATE_VERSION;
        buffer[1] = LINK_STATE_HELLO;
        writeU16(buffer + 2, LS_HELLO_LEN);
        writeU32(buffer + 4, localRouterId);
        writeU32(buffer + 16, ipToU32(addresses[0].address));
        sendFrame(buffer, sizeof(buffer), ETH_TYPE_LINK_STATE,
                  broadcast.data(), deviceId);
    }
}

/**
 * Build the local LSA from live neighbor links and local interface prefixes.
 */
Lsa buildLocalLsa(TimePoint now) {
    Lsa lsa;
    lsa.routerId = localRouterId;
    lsa.sequence = ++localSequence;
    lsa.lastSeen = now;

    for (int deviceId : getActiveDeviceIds()) {
        const auto neighbor = neighbors.find(deviceId);
        if (neighbor != neighbors.end()) {
            lsa.links.push_back({neighbor->second.routerId,
                                 uint16_t(linkCost(deviceId))});
        }

        for (const auto& address : getDeviceAddresses(deviceId)) {
            const uint32_t mask = ipToU32(address.netmask);
            const uint32_t network = ipToU32(address.address) & mask;
            // Lab interfaces belong to distinct, preconfigured subnets.
            lsa.prefixes.push_back({network, mask, 0});
        }
    }
    return lsa;
}

void originateLocalLsa(TimePoint now) {
    const Lsa lsa = buildLocalLsa(now);
    lsdb[localRouterId] = lsa;

    uint8_t buffer[ETH_PAYLOAD_MAX] = {};
    const int length = encodeLsa(lsa, buffer);
    if (length < 0) {
        WARN("link-state: cannot encode local LSA\n");
        return;
    }
    floodMessage(buffer, length, -1);
    localLsaDirty = false;
}

std::map<int, Neighbor>::iterator findNeighborByRouter(uint32_t routerId) {
    for (auto entry = neighbors.begin(); entry != neighbors.end(); ++entry) {
        if (entry->second.routerId == routerId) {
            return entry;
        }
    }
    return neighbors.end();
}

/**
 * Run Dijkstra from the local router and reinstall dynamic routes.
 *
 * The graph consists of the links advertised in every stored LSA. A route's
 * metric is the path cost to the advertising router plus the prefix metric.
 * When several routers advertise the same prefix, the smallest metric wins.
 */
void recomputeRoutes() {
    std::map<uint32_t, int> distance;
    std::map<uint32_t, uint32_t> firstHop;

    using FT = std::pair<int, uint32_t>;
    std::priority_queue<FT, std::vector<FT>, std::greater<FT>> frontier;

    auto expand = [&](uint32_t id, int dist) {
        distance[id] = dist;
        frontier.emplace(dist, id);
    };

    expand(localRouterId, 0);
    while (!frontier.empty()) {
        auto [dist, cur] = frontier.top();
        frontier.pop();

        const auto lsa = lsdb.find(cur);
        if (lsa == lsdb.end()) {
            continue;
        }

        for (const auto& link : lsa->second.links) {
            const int candidate = dist + link.cost;
            const auto known = distance.find(link.neighborId);
            if (known != distance.end() && known->second <= candidate) {
                continue;
            }
            if (cur == localRouterId) {
                // The local LSA was rebuilt from the current neighbor table.
                firstHop[link.neighborId] = link.neighborId;
            } else {
                firstHop[link.neighborId] = firstHop.at(cur);
            }
            expand(link.neighborId, candidate);
        }
    }

    struct Candidate {
        int metric;
        uint32_t nextHopId;
        in_addr nextHopIp;
        int deviceId;
    };
    std::map<std::pair<uint32_t, uint32_t>, Candidate> best;
    for (const auto& [origin, lsa] : lsdb) {
        if (origin == localRouterId) {
            continue;
        }
        const auto dist = distance.find(origin);
        if (dist == distance.end()) {
            continue;
        }
        const auto neighbor = findNeighborByRouter(firstHop.at(origin));
        for (const auto& prefix : lsa.prefixes) {
            const int metric = dist->second + prefix.metric;
            const auto key = std::make_pair(prefix.network, prefix.mask);
            const auto existing = best.find(key);
            if (existing == best.end() ||
                metric < existing->second.metric ||
                (metric == existing->second.metric &&
                 neighbor->second.routerId < existing->second.nextHopId)) {
                best[key] = Candidate{metric, neighbor->second.routerId,
                                      neighbor->second.ip, neighbor->first};
            }
        }
    }

    routingClearDynamic();
    for (const auto& [key, candidate] : best) {
        routingAddDynamic(u32ToIp(key.first), u32ToIp(key.second),
                          candidate.nextHopIp, candidate.deviceId,
                          candidate.metric);
    }

    lastDistances.clear();
    for (const auto& [id, dist] : distance) {
        if (id == localRouterId || lsdb.count(id) != 0) {
            lastDistances[id] = dist;
        }
    }
    printf("LINKSTATE spf routes=%zu reachable=%zu\n", best.size(),
           lastDistances.size());
}

} // namespace

int linkStateInit() {
    neighbors.clear();
    lsdb.clear();
    lastDistances.clear();
    linkCosts.clear();
    localRouterId = 0;
    localSequence = 0;

    bool found = false;
    for (int deviceId : getActiveDeviceIds()) {
        for (const auto& address : getDeviceAddresses(deviceId)) {
            const uint32_t value = ipToU32(address.address);
            if (!found || value > localRouterId) {
                localRouterId = value;
                found = true;
            }
        }
    }
    if (!found) {
        WARN("linkStateInit: no local IPv4 address\n");
        return -1;
    }

    const TimePoint now = std::chrono::steady_clock().now();
    localSequence = uint64_t(now.time_since_epoch().count());
    lastHello = now - HELLO_INTERVAL;
    lastLsaRefresh = now - LSA_REFRESH_INTERVAL;
    localLsaDirty = true;
    spfDirty = true;
    printf("LINKSTATE init router=%s\n", ipToString(localRouterId).c_str());
    return 0;
}

int linkStateReceiveFrame(const void* frame, int len, int deviceId) {
    if (len < int(ETH_HEADER_LEN + LS_COMMON_LEN)) {
        return 0;
    }
    const auto* bytes = static_cast<const uint8_t*>(frame);
    const uint8_t* message = bytes + ETH_HEADER_LEN;
    const int available = len - int(ETH_HEADER_LEN);
    if (message[0] != LINK_STATE_VERSION) {
        return 0;
    }
    const uint8_t type = message[1];
    const uint16_t messageLength = readU16(message + 2);
    if (messageLength < LS_COMMON_LEN || messageLength > available) {
        return 0;
    }
    const uint32_t origin = readU32(message + 4);
    const uint64_t sequence = readU64(message + 8);
    const TimePoint now = std::chrono::steady_clock().now();

    if (type == LINK_STATE_HELLO) {
        if (messageLength < LS_HELLO_LEN) {
            return 0;
        }
        const uint32_t senderIp = readU32(message + 16);
        const auto [entry, inserted] = neighbors.try_emplace(
            deviceId, Neighbor{origin, u32ToIp(senderIp), now});
        entry->second.lastHello = now;
        if (inserted) {
            printf("LINKSTATE neighbor up dev=%d router=%s ip=%s\n",
                   deviceId, ipToString(origin).c_str(),
                   ipToString(senderIp).c_str());
            localLsaDirty = true;
            spfDirty = true;
        }
        return 0;
    }

    if (type != LINK_STATE_LSA || messageLength < LS_LSA_FIXED_LEN) {
        return 0;
    }
    if (origin == localRouterId) {
        return 0;
    }
    const auto stored = lsdb.find(origin);
    if (stored != lsdb.end() && sequence <= stored->second.sequence) {
        return 0;
    }

    const uint16_t linkCount = readU16(message + 16);
    const uint16_t prefixCount = readU16(message + 18);
    const size_t expected = LS_LSA_FIXED_LEN +
                            size_t(linkCount) * LS_LINK_LEN +
                            size_t(prefixCount) * LS_PREFIX_LEN;
    if (expected != messageLength) {
        return 0;
    }

    Lsa lsa;
    lsa.routerId = origin;
    lsa.sequence = sequence;
    lsa.lastSeen = now;
    size_t offset = LS_LSA_FIXED_LEN;
    for (uint16_t i = 0; i < linkCount; ++i) {
        const uint32_t neighborId = readU32(message + offset);
        const uint16_t cost = readU16(message + offset + 4);
        lsa.links.push_back({neighborId, cost});
        offset += LS_LINK_LEN;
    }
    for (uint16_t i = 0; i < prefixCount; ++i) {
        uint32_t network = readU32(message + offset);
        const uint32_t mask = readU32(message + offset + 4);
        const uint16_t metric = readU16(message + offset + 8);
        network &= mask;
        lsa.prefixes.push_back({network, mask, metric});
        offset += LS_PREFIX_LEN;
    }

    lsdb[origin] = lsa;
    printf("LINKSTATE lsa origin=%s seq=%llu links=%u prefixes=%u\n",
           ipToString(origin).c_str(), static_cast<unsigned long long>(sequence),
           linkCount, prefixCount);
    floodMessage(message, messageLength, deviceId);
    spfDirty = true;
    return 0;
}

void linkStateTick(TimePoint now) {
    if (now - lastHello >= HELLO_INTERVAL) {
        sendHellos();
        lastHello = now;
    }

    bool changed = false;
    for (auto entry = neighbors.begin(); entry != neighbors.end();) {
        if (now - entry->second.lastHello >= NEIGHBOR_DEAD_INTERVAL) {
            printf("LINKSTATE neighbor down dev=%d router=%s\n", entry->first,
                   ipToString(entry->second.routerId).c_str());
            entry = neighbors.erase(entry);
            changed = true;
        } else {
            ++entry;
        }
    }
    if (changed) {
        localLsaDirty = true;
        spfDirty = true;
    }

    for (auto entry = lsdb.begin(); entry != lsdb.end();) {
        if (entry->first == localRouterId) {
            ++entry;
            continue;
        }
        if (now - entry->second.lastSeen >= LSA_MAX_AGE) {
            printf("LINKSTATE lsa expired origin=%s\n",
                   ipToString(entry->first).c_str());
            entry = lsdb.erase(entry);
            spfDirty = true;
        } else {
            ++entry;
        }
    }

    if (localLsaDirty || now - lastLsaRefresh >= LSA_REFRESH_INTERVAL) {
        originateLocalLsa(now);
        lastLsaRefresh = now;
    }

    if (spfDirty) {
        recomputeRoutes();
        spfDirty = false;
    }
}

int linkStateSetLinkCost(const char* deviceName, int cost) {
    if (deviceName == nullptr || cost <= 0 || cost > 65535) {
        return -1;
    }
    const int deviceId = findDevice(deviceName);
    if (deviceId < 0) {
        return -1;
    }
    linkCosts[deviceId] = cost;
    localLsaDirty = true;
    spfDirty = true;
    return 0;
}

std::vector<std::pair<in_addr, int>> linkStateDistances() {
    std::vector<std::pair<in_addr, int>> result;
    result.reserve(lastDistances.size());
    for (const auto& [id, distance] : lastDistances) {
        result.push_back({u32ToIp(id), distance});
    }
    return result;
}
