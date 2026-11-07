#include "netstack.h"

#include "ip.h"
#include "arp.h"
#include "device.h"
#include "egress.h"
#include "link_state.h"
#include "packetio.h"
#include "routing.h"
#include "tcp.h"
#include "utils.h"

#include <cstdint>
#include <string>

namespace {

void (*appTick)() = nullptr;

int ethDispatch(const void* frame, int len, int deviceId) {
    const auto* bytes = (const uint8_t*)(frame);
    const uint16_t etherType = readU16(bytes + 12);
    switch (etherType) {
    case ETH_TYPE_IPV4:
        return ipReceiveFrame(frame, len);
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
    egressTick(now);
    tcpTick(now);
    ipTick();
    if (appTick != nullptr) {
        appTick();
    }
}

} // namespace

int netstackInit() {
    initAllDevices();
    routingInit();
    arpInit();
    ipInit();

    int added = 0;
    for (const auto& name : getDeviceNames()) {
        // Loopback and libpcap pseudo-devices are not Ethernet ports.
        if (name == "lo" || name == "any" || name == "nflog" || name == "nfqueue") {
            continue;
        }
        const int id = addDevice(name.c_str());
        if (id < 0) {
            continue;
        }
        ++added;
        for (const auto& address : getDeviceAddresses(id)) {
            routingAddConnected(address.address, address.netmask, id);
        }
    }
    if (added == 0) {
        WARN("netstackInit: no usable Ethernet device\n");
        return -1;
    }

    // The optional egress shaper is configured by device name, so it must
    // run after the interfaces have been added.
    egressInit();

    // Link-state initialization needs the device and address snapshot.
    if (linkStateInit() < 0) {
        return -1;
    }
    setFrameReceiveCallback(ethDispatch);
    setDeviceTickCallback(netstackTick);
    return 0;
}

void netstackSetAppTick(void (*callback)()) {
    appTick = callback;
}

int netstackRun() {
    return runReceiveLoop();
}

int netstackPump(int timeoutMs) {
    return pollReceive(timeoutMs);
}
