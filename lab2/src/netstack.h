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
 * @return 0 on success, -1 if no usable device was found or init failed.
 */
int netstackInit();

/**
 * Register an application tick called after the stack's own timers.
 *
 * The receive loop wakes at least every 100 ms. The demo uses this hook to
 * process stdin commands and drive ping timers on the same thread as packet
 * reception, so no protocol state is shared between threads.
 *
 * @param callback Tick handler, or nullptr to clear it. It must not block.
 */
void netstackSetAppTick(void (*callback)());

/**
 * Run the single-threaded receive loop until stopped or an error occurs.
 *
 * The receive loop wakes at least every 100 ms so ARP, HELLO and LSA timers
 * can run on the same thread.
 *
 * @return 0 when stopped, -1 on error.
 */
int netstackRun();
