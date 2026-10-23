/**
 * @file arp.h
 * @brief ARP request/reply handling and next-hop MAC resolution.
 *
 * Design notes:
 * - Cache entries are keyed by (device ID, next-hop IPv4 address).
 * - A packet whose next hop is unresolved is copied into a bounded pending
 *   queue and an ARP request is broadcast on that device.
 * - Requests are retried a small number of times; exhausted entries are
 *   dropped and their queued packets are discarded.
 * - The implementation answers requests only for addresses assigned to the
 *   receiving interface.
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
    Failed, ///< Invalid input, no route-owned device, or a full queue.
};

/**
 * Clear the ARP cache and all pending queues.
 */
int arpInit();

/**
 * Process an Ethernet frame carrying an ARP packet.
 *
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
 */
ArpResult arpSendWithResolution(int deviceId, in_addr nextHopIp,
                                const void* packet, int len);

/**
 * Drive ARP timers: retry unresolved requests and expire stale cache entries.
 * Called from the single-threaded receive-loop tick.
 */
void arpTick(TimePoint now);

/**
 * Drop all cache entries and pending packets associated with a device.
 * Used when an interface goes down.
 */
void arpFlushDevice(int deviceId);
