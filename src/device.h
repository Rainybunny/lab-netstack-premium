/**
 * @file device.h
 * @brief Library supporting network device management.
 */

#pragma once

#include "utils.h"
#include "pcap/pcap.h"

#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <optional>
#include <net/if_arp.h>
#include <netpacket/packet.h>

/**
 * Scan all devices and initialize their metadata.
 * 
 * @note Call before any other device operation. Repeated calls are harmless;
 * the initial interface snapshot is retained.
 */
void init_all_devices();

/**
 * Return copies of the interface names discovered by init_all_devices().
 */
std::vector<std::string> get_device_names();

/**
 * Add a device to the library for sending / receiving packets.
 *
 * @param device Name of network device to send / receive packet on.
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
int add_device(const char* device);

/**
 * Find a device added by `addDevice'.
 *
 * @param device Name of the network device.
 * @return A non-negative _device-ID_ on success, -1 if no such device.
 * was found .
 */
int find_device(const char* device);

/**
 * Get the mac address of the device with id @p id
 * 
 * @param id device-ID
 * @return mac address if one available, nullopt otherwise.
 */
std::optional<macaddr_t> get_mac(int id);

/**
 * Inject @p len bytes starting from @p bytes to device of ID @p id
 * 
 * @param id device-ID
 * @param bytes pointer to frame. This function involves no any wrapper
 * @param len length of frame.
 * @return 0 on success, -1 on failure.
 */
int inject_frame(int id, const u_char* bytes, int len);

/**
 * Run a single-threaded receive loop on all added devices.
 *
 * @param callback Handler for captured bytes, captured length and device-ID.
 * @note Devices must be added before entering the loop. The handler must not
 * throw or retain the buffer after returning. Nested loops are not supported.
 * @return 0 when stopped, -1 on setup or capture error.
 */
int run_device_receive_loop(void (*callback)(const void*, int, int));

/**
 * Request that the current receive loop stop after the current callback.
 * @note Call from the receive callback, not another thread or a signal handler.
 */
void stop_device_receive_loop();
