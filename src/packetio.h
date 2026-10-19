/**
 * @file packetio.h
 * @brief Library supporting sending / receiving Ethernet II frames.
 */

#pragma once

#include "device.h"

#include <cstring>
#include <netinet/ether.h>

/**
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 *
 * @param buf Pointer to the payload.
 * @param len Payload length, 0..1500 bytes (padded to 46 if shorter).
 * @param ethtype EtherType in host byte order, 0x0600..0xffff.
 * @param destmac MAC address of the destination.
 * @param id ID of the device (returned by `addDevice') to send on.
 * @return 0 on success, -1 on error.
 */
int send_frame(const void* buf, int len,
               int ethtype, const void* destmac, int id);
/**
 * @brief Process a frame upon receiving it.
 *
 * @param buf Pointer to the frame.
 * @param len Length of the frame.
 * @param id ID of the device (returned by ‘addDevice ‘) receiving
 * current frame.
 * @return 0 on success, -1 on error.
 */
typedef int (*recv_callback_t)(const void*, int, int);

/**
 * @brief Register a callback function to be called each time an
 * Ethernet II frame was received.
 *
 * @param callback the callback function.
 * @note nullptr clears the callback. A nonzero callback result is logged;
 * reception continues. The frame buffer is valid only during the callback.
 * @return 0 on success, -1 on error.
 */
int set_frame_receive_callback(recv_callback_t callback);

/**
 * Receive frames from all added devices until stopped or an error occurs.
 * @note Runs callbacks serially on the calling thread. Register a callback
 * and add devices before calling. This API is not thread-safe.
 * @return 0 when stopped, -1 if no callback is set or reception fails.
 */
int run_receive_loop();

/**
 * Stop reception after the current callback returns.
 * @note Call from the receive callback only; not signal-safe or thread-safe.
 */
void stop_receive_loop();
