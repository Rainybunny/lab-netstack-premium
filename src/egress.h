/**
 * @file egress.h
 * @brief Rate-limited FIFO and weighted fair queueing for forwarded packets.
 *
 * The module is configured from the environment so an interior router can be
 * turned into a bottleneck without changing the topology scripts:
 *   NETSTACK_EGRESS_DEV       egress interface name
 *   NETSTACK_EGRESS_RATE      token-bucket rate in bytes per second
 *   NETSTACK_EGRESS_QUEUE     queue capacity in bytes (default 32768)
 *   NETSTACK_EGRESS_MODE      fifo (default) or wfq
 *   NETSTACK_EGRESS_WEIGHTS   wfq weights as ip=weight,ip=weight
 *
 * WFQ classifies packets by source IPv4 address and schedules by virtual
 * finish time, so the long-term share of each flow is proportional to its
 * weight.
 */

#pragma once

#include "utils.h"

#include <netinet/in.h>

/**
 * Parse the configuration and resolve the egress device. Called after the
 * devices have been added.
 */
void egressInit();

/**
 * True when @p deviceId is the configured bottleneck device.
 */
bool egressEnabled(int deviceId);

/**
 * Queue an IPv4 packet for transmission.
 *
 * @param deviceId Egress device.
 * @param mac Next-hop MAC address.
 * @param packet Complete IPv4 packet.
 * @param len Packet length.
 * @param source Source address of the packet, used for WFQ classification.
 * @return 0 when queued or dropped by tail drop, -1 on invalid input.
 */
int egressEnqueue(int deviceId, const macaddr_t& mac, const void* packet,
                  int len, in_addr source);

/**
 * Send queued packets while the token bucket has credit. Called from the
 * single-threaded receive-loop tick.
 */
void egressTick(TimePoint now);
