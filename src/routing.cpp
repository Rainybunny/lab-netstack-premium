#include "routing.h"

#include <arpa/inet.h>

#include <algorithm>
#include <bit>

namespace {

std::vector<RouteEntry> routes;

bool maskToPrefixLength(in_addr mask, int& prefixLength) {
    const uint32_t value = ntohl(mask.s_addr);
    const uint32_t inverse = ~value;
    if ((inverse & (inverse + 1)) != 0) {
        return false;
    }
    prefixLength = std::popcount(value);
    return true;
}

in_addr applyMask(in_addr address, in_addr mask) {
    in_addr result{};
    result.s_addr = address.s_addr & mask.s_addr;
    return result;
}

bool samePrefix(const RouteEntry& entry, in_addr network, in_addr mask) {
    return entry.network.s_addr == network.s_addr &&
           entry.mask.s_addr == mask.s_addr;
}

int addRoute(in_addr dest, in_addr mask, RouteKind kind, int deviceId,
             in_addr nextHopIp, const macaddr_t& nextHopMac, int metric) {
    if (deviceId < 0) {
        return -1;
    }
    int prefixLength = 0;
    if (!maskToPrefixLength(mask, prefixLength)) {
        return -1;
    }
    const in_addr network = applyMask(dest, mask);

    for (auto& entry : routes) {
        if (entry.kind == kind && samePrefix(entry, network, mask)) {
            entry.deviceId = deviceId;
            entry.nextHopIp = nextHopIp;
            entry.nextHopMac = nextHopMac;
            entry.metric = metric;
            return 0;
        }
    }

    RouteEntry entry{};
    entry.network = network;
    entry.mask = mask;
    entry.prefixLength = prefixLength;
    entry.kind = kind;
    entry.deviceId = deviceId;
    entry.nextHopIp = nextHopIp;
    entry.nextHopMac = nextHopMac;
    entry.metric = metric;
    routes.push_back(entry);
    return 0;
}

bool isBetter(const RouteEntry& candidate, const RouteEntry& current) {
    if (candidate.prefixLength != current.prefixLength) {
        return candidate.prefixLength > current.prefixLength;
    }
    // addRoute keeps only one entry per (prefix, kind).
    return candidate.kind < current.kind;
}

} // namespace

void routingInit() {
    routes.clear();
}

int routingAddConnected(in_addr network, in_addr mask, int deviceId) {
    return addRoute(network, mask, RouteKind::Connected, deviceId,
                    in_addr{}, macaddr_t{}, 0);
}

int routingAddStatic(in_addr dest, in_addr mask,
                     const macaddr_t& nextHopMac, int deviceId) {
    return addRoute(dest, mask, RouteKind::Static, deviceId,
                    in_addr{}, nextHopMac, 0);
}

int routingAddDynamic(in_addr dest, in_addr mask, in_addr nextHopIp,
                      int deviceId, int metric) {
    return addRoute(dest, mask, RouteKind::Dynamic, deviceId,
                    nextHopIp, macaddr_t{}, metric);
}

void routingClearDynamic() {
    routes.erase(std::remove_if(routes.begin(), routes.end(),
                                [](const RouteEntry& entry) {
                                    return entry.kind == RouteKind::Dynamic;
                                }),
                 routes.end());
}

bool routingLookup(in_addr dest, RouteResult& result) {
    const RouteEntry* best = nullptr;
    for (const auto& entry : routes) {
        if ((dest.s_addr & entry.mask.s_addr) != entry.network.s_addr) {
            continue;
        }
        if (best == nullptr || isBetter(entry, *best)) {
            best = &entry;
        }
    }
    if (best == nullptr) {
        return false;
    }

    result.kind = best->kind;
    result.network = best->network;
    result.mask = best->mask;
    result.nextHopIp = best->kind == RouteKind::Connected ? dest : best->nextHopIp;
    result.nextHopMac = best->nextHopMac;
    result.deviceId = best->deviceId;
    result.prefixLength = best->prefixLength;
    result.metric = best->metric;
    return true;
}

std::vector<RouteEntry> routingEntries() {
    return routes;
}
