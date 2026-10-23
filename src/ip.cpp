#include "ip.h"

#include "arp.h"
#include "device.h"
#include "packetio.h"
#include "routing.h"
#include "utils.h"

#include <array>
#include <cstring>

namespace {

constexpr uint8_t DEFAULT_TTL = 64;
uint16_t nextIpId = 0;
IPPacketReceiveCallback ipReceiveCallback = nullptr;

/**
 * Compute the Internet checksum over a byte buffer.
 *
 * Returns the checksum in host byte order. When the checksum field is already
 * present in the buffer, a valid header yields zero.
 */
uint16_t ipChecksum(const void* data, size_t len) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    size_t index = 0;
    for (; index + 1 < len; index += 2) {
        sum += (uint16_t(bytes[index]) << 8) | bytes[index + 1];
    }
    if (index < len) {
        sum += uint16_t(bytes[index]) << 8;
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
int ipForwardPacket(uint8_t* packet, int len, int inDeviceId) {
    (void)inDeviceId; // Reserved for split-horizon checks.
    if (packet == nullptr || len < int(IP_HEADER_LEN)) {
        return -1;
    }
    const int ihl = (packet[0] & 0x0f) * 4;
    if ((packet[0] >> 4) != 4 || ihl < int(IP_HEADER_LEN) || ihl > len) {
        return -1;
    }
    if (packet[8] <= 1) {
        return -1; // TTL expired; ICMP Time Exceeded is not implemented.
    }
    --packet[8];
    writeU16(packet + 10, 0);
    writeU16(packet + 10, ipChecksum(packet, size_t(ihl)));

    in_addr dest{};
    std::memcpy(&dest, packet + 16, sizeof(dest));
    RouteResult route{};
    if (!routingLookup(dest, route)) {
        return -1;
    }

    if (route.kind == RouteKind::Static) {
        return sendFrame(packet, len, ETH_TYPE_IPV4,
                         route.nextHopMac.data(), route.deviceId);
    } else {
        auto result = arpSendWithResolution(route.deviceId,
                                            route.nextHopIp, packet, len);
        return result == ArpResult::Failed ? -1 : 0;
    }
}

} // namespace

int sendIPPacket(const struct in_addr src, const struct in_addr dest,
                 int proto, const void* buf, int len) {
    if (len < 0 || len > int(IP_MAX_PAYLOAD)) {
        return -1;
    }
    if (len > 0 && buf == nullptr) {
        return -1;
    }
    if (proto < 0 || proto > 255) {
        return -1;
    }

    std::array<uint8_t, IP_MAX_LEN> packet{};
    const int totalLen = int(IP_HEADER_LEN) + len;
    packet[0] = 0x45; // Version 4, IHL 5 (no options).
    packet[1] = 0;    // TOS.
    writeU16(packet.data() + 2, uint16_t(totalLen));
    writeU16(packet.data() + 4, nextIpId++);
    writeU16(packet.data() + 6, 0); // DF = 0, fragment offset = 0.
    packet[8] = DEFAULT_TTL;
    packet[9] = uint8_t(proto);
    writeU16(packet.data() + 10, 0);
    std::memcpy(packet.data() + 12, &src, sizeof(src));
    std::memcpy(packet.data() + 16, &dest, sizeof(dest));
    writeU16(packet.data() + 10, ipChecksum(packet.data(), IP_HEADER_LEN));
    if (len > 0) {
        std::memcpy(packet.data() + IP_HEADER_LEN, buf, size_t(len));
    }

    RouteResult route{};
    if (!routingLookup(dest, route)) {
        WARN("sendIPPacket: no route to destination\n");
        return -1;
    }

    if (route.kind == RouteKind::Static) {
        return sendFrame(packet.data(), totalLen, ETH_TYPE_IPV4,
                         route.nextHopMac.data(), route.deviceId);
    } else {
        auto result = arpSendWithResolution(route.deviceId, route.nextHopIp,
                                            packet.data(), totalLen);
        return result == ArpResult::Failed ? -1 : 0;
    }
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

int ipReceiveFrame(const void* frame, int len, int deviceId) {
    if (frame == nullptr || len < int(ETH_HEADER_LEN + IP_HEADER_LEN)) {
        return 0;
    }
    const auto* bytes = (const uint8_t*)(frame);
    if (readU16(bytes + 12) != ETH_TYPE_IPV4) {
        return 0;
    }

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

    const uint16_t off = readU16(packet + 6);
    if ((off & 0x2000u) != 0 || (off & 0x1fffu) != 0) {
        return 0; // Fragmentation is not supported.
    }

    in_addr dest{};
    std::memcpy(&dest, packet + 16, sizeof(dest));
    if (ipIsLocalAddress(dest)) { // it's mine
        if (ipReceiveCallback == nullptr) {
            return 0;
        }
        return ipReceiveCallback(packet, totalLen);
    } else { // not mine
        std::array<uint8_t, IP_MAX_LEN> forwarded{}; // will be modified
        std::memcpy(forwarded.data(), packet, size_t(totalLen));
        return ipForwardPacket(forwarded.data(), totalLen, deviceId);
    }
}
