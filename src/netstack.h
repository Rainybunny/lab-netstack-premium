/**
 * @file netstack.h
 * @brief Initialization and run loop for the user-space protocol stack.
 */

#pragma once

/**
 * Initialize the stack:
 * - discover and add all non-loopback Ethernet devices;
 * - install connected routes for their IPv4 subnets;
 * - initialize ARP and link-state state;
 * - install the single Ethernet EtherType dispatcher and the timer tick.
 *
 * The stack owns the frame callback; upper layers use
 * setIPPacketReceiveCallback() instead of setFrameReceiveCallback().
 * Call this before setRoutingTable() or sendIPPacket().
 *
 * @warning The current implementation adds every non-loopback Ethernet
 * interface it finds. Run it inside a dedicated network namespace, not in the
 * host namespace, so unrelated interfaces are never used for injection.
 *
 * @return 0 on success, -1 if no usable device was found or init failed.
 */
int netstackInit();

/**
 * Run the single-threaded receive loop until stopped or an error occurs.
 *
 * The receive loop wakes at least every 100 ms so ARP, HELLO and LSA timers
 * can run on the same thread. Interactive stdin commands will be integrated
 * into this loop later by adding a control fd to its poll set.
 *
 * @return 0 when stopped, -1 on error.
 */
int netstackRun();
