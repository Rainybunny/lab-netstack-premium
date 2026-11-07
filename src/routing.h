/**
 * @file routing.h
 * @brief Routing table and longest-prefix matching.
 *
 * The table holds three kinds of routes:
 * - Connected: a local interface subnet. The next hop is the destination
 *   itself, so the IP layer resolves it with ARP.
 * - Static: installed by setRoutingTable(). The next-hop MAC is supplied by
 *   the caller, so no ARP is needed.
 * - Dynamic: installed by the link-state module. The next hop is a neighbor's
 *   IPv4 address and is resolved with ARP.
 *
 * Lookup order is longest prefix first. On equal prefix length, connected
 * routes win over static routes and static routes win over dynamic routes.
 * Each (prefix, kind) has one entry; link-state selects the dynamic next hop.
 */

#pragma once

#include "utils.h"

#include <netinet/in.h>

#include <vector>

enum class RouteKind {
    Connected,
    Static,
    Dynamic,
};

/**
 * One routing-table entry.
 *
 * For Connected routes, nextHopIp is unused and the lookup result uses the
 * destination address itself. For Static routes, nextHopMac is used. For
 * Dynamic routes, nextHopIp is used.
 */
struct RouteEntry {
    in_addr network;
    in_addr mask;
    int prefixLength;
    RouteKind kind;
    int deviceId;
    in_addr nextHopIp;
    macaddr_t nextHopMac;
    int metric;
};

/**
 * Result of a successful routing-table lookup.
 */
struct RouteResult {
    RouteKind kind;
    in_addr network;
    in_addr mask;
    in_addr nextHopIp;
    macaddr_t nextHopMac;
    int deviceId;
    int prefixLength;
    int metric;
};

/**
 * Clear the routing table. Called once during stack initialization.
 */
void routingInit();

/**
 * Install a connected route for a local interface subnet.
 *
 * @param network An address on the subnet; it is masked before storage.
 * @param mask Subnet mask. It must be contiguous.
 * @param deviceId Device owning the subnet.
 * @return 0 on success, -1 on invalid input.
 */
int routingAddConnected(in_addr network, in_addr mask, int deviceId);

/**
 * Install or replace a static route.
 *
 * @param dest Destination prefix.
 * @param mask Prefix mask. It must be contiguous.
 * @param nextHopMac MAC address used directly when sending.
 * @param deviceId Device to send on.
 * @return 0 on success, -1 on invalid input.
 */
int routingAddStatic(in_addr dest, in_addr mask,
                     const macaddr_t& nextHopMac, int deviceId);

/**
 * Install or replace a dynamic route.
 *
 * @param dest Destination prefix.
 * @param mask Prefix mask. It must be contiguous.
 * @param nextHopIp Neighbor address resolved with ARP.
 * @param deviceId Device to send on.
 * @param metric Path cost from the link-state computation.
 * @return 0 on success, -1 on invalid input.
 */
int routingAddDynamic(in_addr dest, in_addr mask, in_addr nextHopIp,
                      int deviceId, int metric);

/**
 * Remove all dynamic routes. The link-state module calls this before
 * installing a newly computed route set; static and connected routes survive.
 */
void routingClearDynamic();

/**
 * Find the best route for a destination.
 *
 * @param dest Destination address.
 * @param result Receives the selected route on success.
 * @return true if a route was found, false otherwise.
 */
bool routingLookup(in_addr dest, RouteResult& result);

/**
 * Return a copy of all routing-table entries, primarily for diagnostics.
 */
std::vector<RouteEntry> routingEntries();
