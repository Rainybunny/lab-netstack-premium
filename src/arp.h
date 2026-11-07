/**
 * @file arp.h
 * @brief ARP request/reply handling and next-hop MAC resolution.
 */

#pragma once

#include "utils.h"

#include <netinet/in.h>

#include <chrono>
#include <cstddef>

constexpr size_t ARP_PACKET_LEN = 28;
constexpr uint16_t ARP_HARDWARE_ETHERNET = 1;
constexpr uint16_t ARP_PROTOCOL_IPV4 = ETH_TYPE_IPV4;
constexpr uint8_t ARP_HARDWARE_LEN = 6;
constexpr uint8_t ARP_PROTOCOL_LEN = 4;

constexpr int ARP_CACHE_TIMEOUT_MS = 60000;
constexpr int ARP_REQUEST_RETRY_MS = 1000;
constexpr int ARP_MAX_RETRIES = 3;
constexpr size_t ARP_MAX_PENDING_PACKETS = 4;

enum class ArpResult {
    Sent,   ///< A cached mapping existed and the packet was sent.
    Queued, ///< The packet was queued and an ARP request was sent.
    Failed, ///< Frame injection failed or the pending queue is full.
};

/**
 * Clear the ARP cache and all pending queues.
 */
void arpInit();

/**
 * Process an Ethernet frame carrying an ARP packet.
 *
 * Called by the Ethernet dispatcher for ARP frames on an active device.
 * The function learns the sender mapping, answers requests for addresses on
 * the receiving interface, and flushes queued packets when a reply arrives.
 *
 * @return 0 on success or when the frame is ignored, -1 on malformed input.
 */
int arpReceiveFrame(const void* frame, int len, int deviceId);

/**
 * Send an IP packet after resolving its next hop.
 *
 * If a valid cache entry exists, the packet is sent immediately and Sent is
 * returned. Otherwise a copy is queued, an ARP request is sent, and Queued is
 * returned. The caller treats both as success and Failed as an error.
 *
 * @param deviceId Device used for the next hop.
 * @param nextHopIp IPv4 address whose MAC is needed.
 * @param packet Complete IP packet to send.
 * @param len Length of the IP packet.
 * @note Called by the IP layer with a validated packet and route-owned device.
 */
ArpResult arpSendWithResolution(int deviceId, in_addr nextHopIp,
                                const void* packet, int len);

/**
 * Look up a valid cached MAC address for a next hop.
 *
 * @return true and fills @p mac when a fresh mapping exists.
 */
bool arpLookup(int deviceId, in_addr nextHopIp, macaddr_t& mac);

/**
 * Drive ARP timers: retry unresolved requests and expire stale cache entries.
 * Called from the single-threaded receive-loop tick.
 */
void arpTick(TimePoint now);
