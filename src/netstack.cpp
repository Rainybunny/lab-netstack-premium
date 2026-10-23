#include "netstack.h"

#include "ip.h"
#include "arp.h"
#include "device.h"
#include "link_state.h"
#include "packetio.h"
#include "routing.h"
#include "utils.h"

#include <cstdint>
#include <string>

namespace {

int ethDispatch(const void* frame, int len, int deviceId) {
    if (frame == nullptr || len < int(ETH_HEADER_LEN)) {
        return 0;
    }
    const auto* bytes = (const uint8_t*)(frame);
    const uint16_t etherType = readU16(bytes + 12);
    switch (etherType) {
    case ETH_TYPE_IPV4:
        return ipReceiveFrame(frame, len, deviceId);
    case ETH_TYPE_ARP:
        return arpReceiveFrame(frame, len, deviceId);
    case ETH_TYPE_LINK_STATE:
        return linkStateReceiveFrame(frame, len, deviceId);
    default:
        return 0;
    }
}

void netstackTick() {
    auto now = std::chrono::steady_clock().now();
    arpTick(now);
    linkStateTick(now);
    routingTick(now);
}

} // namespace

int netstackInit() {
    initAllDevices();
    routingInit();
    if (arpInit() < 0) {
        return -1;
    }

    int added = 0;
    for (const auto& name : getDeviceNames()) {
        // Loopback and the Linux "any" pseudo-device are not Ethernet ports.
        if (name == "lo" || name == "any") {
            continue;
        }
        const int id = addDevice(name.c_str());
        if (id < 0) {
            continue;
        }
        ++added;
        for (const auto& address : getDeviceAddresses(id)) {
            if (address.netmask.s_addr == 0) {
                continue;
            }
            routingAddConnected(address.address, address.netmask, id);
        }
    }
    if (added == 0) {
        WARN("netstackInit: no usable Ethernet device\n");
        return -1;
    }

    // Link-state initialization needs the device and address snapshot.
    if (linkStateInit() < 0) {
        return -1;
    }
    setFrameReceiveCallback(ethDispatch);
    setDeviceTickCallback(netstackTick);
    return 0;
}

int netstackRun() {
    return runReceiveLoop();
}
