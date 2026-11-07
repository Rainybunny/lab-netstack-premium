#include "ip.h"

#include "arp.h"
#include "device.h"
#include "egress.h"
#include "ipfrag.h"
#include "packetio.h"
#include "routing.h"
#include "utils.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace {

constexpr uint8_t DEFAULT_TTL = 64;
constexpr int IP_FRAGMENT_PAYLOAD = 1480; // multiple of eight
uint16_t nextIpId = 0;
IPPacketReceiveCallback ipReceiveCallback = nullptr;
IpReassembler reassembler;

/**
 * Compute the Internet checksum over an IPv4 header (a multiple of 4 bytes).
 *
 * Returns the checksum in host byte order. When the checksum field is already
 * present in the buffer, a valid header yields zero.
 */
uint16_t ipChecksum(const void* data, size_t len) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    for (size_t index = 0; index < len; index += 2) {
        sum += (uint16_t(bytes[index]) << 8) | bytes[index + 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return uint16_t(~sum);
}

bool ipIsLocalAddress(in_addr address) {
    for (int id : getActiveDeviceIds()) {
        for (const auto& entry : getDeviceAddresses(id)) {
            if (entry.address.s_addr == address.s_addr) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Forward a transit packet. TTL is decremented and the header checksum is
 * recomputed before the route lookup. The original packet buffer is modified.
 */
int ipForwardPacket(uint8_t* packet, int len) {
    // ipReceiveFrame has already validated the complete header.
    const int ihl = (packet[0] & 0x0f) * 4;
    if (packet[8] <= 1) {
        return -1; // TTL expired; ICMP Time Exceeded is not implemented.
    }
    --packet[8];
    writeU16(packet + 10, 0);
    writeU16(packet + 10, ipChecksum(packet, size_t(ihl)));

    in_addr dest{};
    in_addr src{};
    std::memcpy(&dest, packet + 16, sizeof(dest));
    std::memcpy(&src, packet + 12, sizeof(src));
    RouteResult route{};
    if (!routingLookup(dest, route)) {
        return -1;
    }

    macaddr_t cached{};
    const macaddr_t* nextHopMac = nullptr;
    if (route.kind == RouteKind::Static) {
        nextHopMac = &route.nextHopMac;
    } else if (arpLookup(route.deviceId, route.nextHopIp, cached)) {
        nextHopMac = &cached;
    }

    if (nextHopMac == nullptr) {
        auto result = arpSendWithResolution(route.deviceId,
                                            route.nextHopIp, packet, len);
        return result == ArpResult::Failed ? -1 : 0;
    }
    if (egressEnabled(route.deviceId)) {
        return egressEnqueue(route.deviceId, *nextHopMac, packet, len, src);
    }
    return sendFrame(packet, len, ETH_TYPE_IPV4, nextHopMac->data(),
                     route.deviceId);
}

int sendIpPacketViaRoute(const uint8_t* packet, int len) {
    in_addr dest{};
    std::memcpy(&dest, packet + 16, sizeof(dest));
    RouteResult route{};
    if (!routingLookup(dest, route)) {
        return -1;
    }
    if (route.kind == RouteKind::Static) {
        return sendFrame(packet, len, ETH_TYPE_IPV4, route.nextHopMac.data(),
                         route.deviceId);
    }
    const auto result = arpSendWithResolution(route.deviceId, route.nextHopIp,
                                              packet, len);
    return result == ArpResult::Failed ? -1 : 0;
}

} // namespace

int sendIPPacket(const struct in_addr src, const struct in_addr dest,
                 int proto, const void* buf, int len) {
    if (len < 0 || len > int(IpReassembler::MAX_PAYLOAD)) {
        return -1;
    }
    if (len > 0 && buf == nullptr) {
        return -1;
    }
    if (proto < 0 || proto > 255) {
        return -1;
    }

    const uint16_t id = nextIpId++;
    const auto* payload = static_cast<const uint8_t*>(buf);
    int offset = 0;
    while (offset < len || (len == 0 && offset == 0)) {
        const int chunk = std::min(IP_FRAGMENT_PAYLOAD, len - offset);
        const bool more = offset + chunk < len;
        uint8_t packet[IP_MAX_LEN] = {};
        const int totalLen = int(IP_HEADER_LEN) + chunk;
        packet[0] = 0x45; // Version 4, IHL 5 (no options).
        packet[1] = 0;    // TOS.
        writeU16(packet + 2, uint16_t(totalLen));
        writeU16(packet + 4, id);
        writeU16(packet + 6,
                 uint16_t((more ? 0x2000 : 0) | (offset / 8)));
        packet[8] = DEFAULT_TTL;
        packet[9] = uint8_t(proto);
        writeU16(packet + 10, 0);
        std::memcpy(packet + 12, &src, sizeof(src));
        std::memcpy(packet + 16, &dest, sizeof(dest));
        if (chunk > 0) {
            std::memcpy(packet + IP_HEADER_LEN, payload + offset,
                        size_t(chunk));
        }
        writeU16(packet + 10, ipChecksum(packet, IP_HEADER_LEN));
        if (sendIpPacketViaRoute(packet, totalLen) < 0) {
            WARN("sendIPPacket: no route or send failure\n");
            return -1;
        }
        offset += chunk;
        if (len == 0) {
            break;
        }
    }
    return 0;
}

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback) {
    ipReceiveCallback = callback;
    return 0;
}

int setRoutingTable(const struct in_addr dest,
                    const struct in_addr mask,
                    const void* nextHopMac,
                    const char* device) {
    if (nextHopMac == nullptr || device == nullptr) {
        return -1;
    }
    const int deviceId = findDevice(device);
    if (deviceId < 0) {
        return -1;
    }
    macaddr_t mac{};
    std::memcpy(mac.data(), nextHopMac, mac.size());
    return routingAddStatic(dest, mask, mac, deviceId);
}

int ipReceiveFrame(const void* frame, int len) {
    if (len < int(ETH_HEADER_LEN + IP_HEADER_LEN)) {
        return 0;
    }
    const auto* bytes = (const uint8_t*)(frame);

    const uint8_t* packet = bytes + ETH_HEADER_LEN;
    const int available = len - int(ETH_HEADER_LEN);
    if ((packet[0] >> 4) != 4) {
        return 0;
    }
    const int ihl = (packet[0] & 0x0f) * 4;
    if (ihl < int(IP_HEADER_LEN) || available < ihl) {
        return 0;
    }
    const int totalLen = readU16(packet + 2);
    if (totalLen < ihl || totalLen > available ||
        totalLen > int(IP_MAX_LEN)) {
        return 0;
    }
    if (ipChecksum(packet, size_t(ihl)) != 0) {
        return 0; // Invalid header checksum.
    }

    const uint16_t fragmentField = readU16(packet + 6);
    const bool moreFragments = (fragmentField & 0x2000u) != 0;
    const int fragmentOffset = (fragmentField & 0x1fffu) * 8;

    in_addr dest{};
    std::memcpy(&dest, packet + 16, sizeof(dest));
    if (moreFragments || fragmentOffset != 0) {
        if (!ipIsLocalAddress(dest)) {
            std::array<uint8_t, IP_MAX_LEN> forwarded{}; // will be modified
            std::memcpy(forwarded.data(), packet, size_t(totalLen));
            return ipForwardPacket(forwarded.data(), totalLen);
        }
        std::vector<uint8_t> assembled;
        if (!reassembler.add(packet, totalLen, assembled) ||
            ipReceiveCallback == nullptr) {
            return 0;
        }
        return ipReceiveCallback(assembled.data(), int(assembled.size()));
    }

    if (ipIsLocalAddress(dest)) { // it's mine
        if (ipReceiveCallback == nullptr) {
            return 0;
        }
        return ipReceiveCallback(packet, totalLen);
    } else { // not mine
        std::array<uint8_t, IP_MAX_LEN> forwarded{}; // will be modified
        std::memcpy(forwarded.data(), packet, size_t(totalLen));
        return ipForwardPacket(forwarded.data(), totalLen);
    }
}

void ipInit() {
    reassembler.clear();
}

void ipTick() {
    reassembler.tick(std::chrono::steady_clock().now());
}
