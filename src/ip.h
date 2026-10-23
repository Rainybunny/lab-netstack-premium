/**
 * @file ip.h
 * @brief Library supporting sending / receiving IPv4 packets encapsulated
 * in Ethernet II frames.
 *
 * The public interface follows the names in the lab manual so a C or C++
 * test program can link against it directly.
 */

#pragma once

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send an IPv4 packet to the specified host.
 *
 * @param src Source IP address. It is used verbatim in the IPv4 header.
 * @param dest Destination IP address.
 * @param proto Value of the IPv4 protocol field (0..255).
 * @param buf Pointer to the IP payload.
 * @param len Length of the IP payload, 0..1480 bytes.
 * @return 0 on success, -1 on error. A packet queued for ARP resolution is
 * considered accepted and returns 0.
 */
int sendIPPacket(const struct in_addr src, const struct in_addr dest,
                 int proto, const void* buf, int len);

/**
 * @brief Process an IP packet upon receiving it.
 *
 * @param buf Pointer to the complete IPv4 packet, starting at the IPv4
 * header. The buffer is valid only during the callback; copy it if it must
 * be retained.
 * @param len Length reported by the IPv4 total-length field.
 * @return 0 on success, -1 on error.
 */
typedef int (*IPPacketReceiveCallback)(const void* buf, int len);

/**
 * @brief Register a callback invoked for IPv4 packets addressed to a local
 * interface.
 *
 * @param callback The callback function, or nullptr to clear it.
 * @return 0 on success, -1 on error.
 */
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

/**
 * @brief Manually add an entry to the routing table. Useful when talking
 * with real Linux machines.
 *
 * @param dest The destination IP prefix.
 * @param mask The subnet mask of the destination IP prefix. Masks must be
 * contiguous.
 * @param nextHopMac MAC address of the next hop.
 * @param device Name of a device that has already been added.
 * @return 0 on success, -1 on error.
 */
int setRoutingTable(const struct in_addr dest,
                    const struct in_addr mask,
                    const void* nextHopMac,
                    const char* device);

/**
 * Process an Ethernet frame that carries an IPv4 packet.
 *
 * The function validates the Ethernet/IP headers, delivers local packets to
 * the callback registered with setIPPacketReceiveCallback(), and forwards
 * transit packets according to the routing table.
 *
 * @param frame Complete Ethernet frame.
 * @param len Captured frame length, including the Ethernet header and any
 * padding.
 * @param deviceId ID of the receiving device.
 * @return 0 on success or when the frame is ignored, -1 on error.
 */
int ipReceiveFrame(const void* frame, int len, int deviceId);

#ifdef __cplusplus
}
#endif
