/**
 * @file link_state.h
 * @brief Link-state routing: HELLO neighbor discovery, LSA flooding, Dijkstra.
 */

#pragma once

#include "utils.h"

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

constexpr uint8_t LINK_STATE_VERSION = 1;
constexpr uint8_t LINK_STATE_HELLO = 1;
constexpr uint8_t LINK_STATE_LSA = 2;

constexpr int HELLO_INTERVAL_MS = 1000;
constexpr int NEIGHBOR_DEAD_INTERVAL_MS = 3000;
constexpr int LSA_REFRESH_INTERVAL_MS = 5000;
constexpr int LSA_MAX_AGE_MS = 15000;

constexpr int DEFAULT_LINK_COST = 1;

/**
 * Initialize the neighbor table, LSDB and router ID.
 *
 * Must run after the Ethernet devices have been added so local addresses are
 * available.
 *
 * @return 0 on success, -1 if no local IPv4 address exists.
 */
int linkStateInit();

/**
 * Process a link-state frame from the Ethernet dispatcher after initialization.
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
 * Call after netstackInit(), which initializes the device and link-state tables.
 *
 * @param deviceName Interface name.
 * @param cost Positive link cost.
 * @return 0 on success, -1 on invalid input or unknown device.
 */
int linkStateSetLinkCost(const char* deviceName, int cost);

/**
 * Return the router distances from the most recent SPF computation.
 *
 * The local router is included with distance 0. Unreachable routers are
 * omitted. Distances are the sum of link costs along the shortest path.
 */
std::vector<std::pair<in_addr, int>> linkStateDistances();
