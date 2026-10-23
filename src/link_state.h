/**
 * @file link_state.h
 * @brief Link-state routing: HELLO neighbor discovery, LSA flooding, Dijkstra.
 *
 * Design notes:
 * - Control frames use EtherType ETH_TYPE_LINK_STATE on the local link; they
 *   do not depend on the IP routing table or ARP, avoiding a circular
 *   dependency while routes are being computed.
 * - The router ID is the highest IPv4 address assigned to a local interface.
 * - HELLO frames are broadcast periodically. A neighbor is declared dead after
 *   NEIGHBOR_DEAD_INTERVAL_MS without a HELLO.
 * - Each router originates an LSA containing its live links (neighbor router
 *   ID and cost) and its local prefixes. LSAs carry a 64-bit sequence number,
 *   are flooded to all other interfaces, refreshed periodically, and aged out.
 * - The SPF result is installed into the routing table as dynamic routes.
 *   Each route's next hop is the first-hop neighbor's IPv4 address on the
 *   outgoing interface, so the IP layer resolves it with ARP.
 */

#pragma once

#include "utils.h"

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>

constexpr uint8_t LINK_STATE_VERSION = 1;

constexpr int HELLO_INTERVAL_MS = 1000;
constexpr int NEIGHBOR_DEAD_INTERVAL_MS = 3000;
constexpr int LSA_REFRESH_INTERVAL_MS = 5000;
constexpr int LSA_MAX_AGE_MS = 15000;

constexpr int DEFAULT_LINK_COST = 1;
constexpr size_t LSA_MAX_LINKS = 32;
constexpr size_t LSA_MAX_PREFIXES = 32;

/**
 * Initialize the neighbor table, LSDB and router ID.
 *
 * Must run after the Ethernet devices have been added so local addresses are
 * available.
 */
int linkStateInit();

/**
 * Process an Ethernet frame carrying a HELLO or LSA message.
 *
 * Newer LSAs are stored and flooded to the other interfaces; neighbor
 * liveness is refreshed by HELLO. A route recomputation is scheduled when the
 * topology changes.
 *
 * @return 0 on success or when the frame is ignored, -1 on malformed input.
 */
int linkStateReceiveFrame(const void* frame, int len, int deviceId);

/**
 * Drive HELLO, LSA refresh/aging and route recomputation timers.
 * Called from the single-threaded receive-loop tick.
 */
void linkStateTick(TimePoint now);

/**
 * Configure the cost advertised for a local interface.
 *
 * Costs are positive and are used as the weight of the link in the SPF graph.
 * The function must be called after addDevice() so the name can be resolved.
 *
 * @param deviceName Interface name.
 * @param cost Positive link cost.
 * @return 0 on success, -1 on invalid input or unknown device.
 */
int linkStateSetLinkCost(const char* deviceName, int cost);
