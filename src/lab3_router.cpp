/**
 * @file lab3_router.cpp
 * @brief A stack instance that only forwards IPv4 packets and pumps timers.
 *
 * Used as an interior router in the Lab 3 topologies. Routing is learned by
 * the link-state module; no socket callback is installed.
 */

#include "netstack.h"

int main() {
    if (netstackInit() < 0) {
        return 1;
    }
    return netstackRun() == 0 ? 0 : 1;
}
