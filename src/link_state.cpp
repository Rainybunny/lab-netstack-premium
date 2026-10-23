#include "link_state.h"

#include "device.h"
#include "routing.h"

#include <map>

namespace {

// deviceId -> advertised link cost.
std::map<int, int> linkCosts;

} // namespace

int linkStateInit(TimePoint now) {
    // TODO:
    // 1. Choose the router ID (highest local IPv4 address).
    // 2. Clear the neighbor table and LSDB.
    // 3. Build the initial LSA from local prefixes and configured costs.
    return 0;
}

int linkStateReceiveFrame(const void*, int, int) {
    // TODO:
    // 1. Decode the HELLO/LSA message and validate version/length.
    // 2. HELLO: update neighbor liveness, interface IP and device.
    // 3. LSA: accept only newer sequence numbers, store, flood to other
    //    interfaces, and recompute SPF.
    // 4. Install the result with routingClearDynamic() and
    //    routingAddDynamic().
    return 0;
}

void linkStateTick() {
    // TODO:
    // 1. Send HELLOs every HELLO_INTERVAL_MS.
    // 2. Declare neighbors dead after NEIGHBOR_DEAD_INTERVAL_MS.
    // 3. Refresh the local LSA every LSA_REFRESH_INTERVAL_MS and age out
    //    other routers' LSAs after LSA_MAX_AGE_MS.
    // 4. Recompute SPF when the topology changes.
}

int linkStateSetLinkCost(const char* deviceName, int cost) {
    if (deviceName == nullptr || cost <= 0) {
        return -1;
    }
    const int deviceId = findDevice(deviceName);
    if (deviceId < 0) {
        return -1;
    }
    linkCosts[deviceId] = cost;
    return 0;
}
