#include "routing.h"

#include <arpa/inet.h>

#include <algorithm>

namespace {

std::vector<RouteEntry> routes;

bool maskToPrefixLength(in_addr mask, int& prefixLength) {
    const uint32_t value = ntohl(mask.s_addr);
    bool seenZero = false;
    int length = 0;
    for (int bit = 31; bit >= 0; --bit) {
        const bool isSet = ((value >> bit) & 1u) != 0;
        if (isSet) {
            if (seenZero) {
                return false; // Non-contiguous mask.
            }
            ++length;
        } else {
            seenZero = true;
        }
    }
    prefixLength = length;
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

int routePriority(RouteKind kind) {
    switch (kind) {
    case RouteKind::Connected:
        return 0;
    case RouteKind::Static:
        return 1;
    case RouteKind::Dynamic:
        return 2;
    }
    return 3;
}

bool isBetter(const RouteEntry& candidate, const RouteEntry& current) {
    if (candidate.prefixLength != current.prefixLength) {
        return candidate.prefixLength > current.prefixLength;
    }
    if (candidate.kind != current.kind) {
        return routePriority(candidate.kind) < routePriority(current.kind);
    }
    if (candidate.metric != current.metric) {
        return candidate.metric < current.metric;
    }
    return candidate.deviceId < current.deviceId;
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
    if (metric < 0) {
        return -1;
    }
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
    result.nextHopIp = best->kind == RouteKind::Connected ? dest : best->nextHopIp;
    result.nextHopMac = best->nextHopMac;
    result.deviceId = best->deviceId;
    result.prefixLength = best->prefixLength;
    result.metric = best->metric;
    return true;
}

void routingTick(TimePoint) {
    // Dynamic routes are refreshed by the link-state module, so there is no
    // timer-driven work here yet.
}

std::vector<RouteEntry> routingEntries() {
    return routes;
}
