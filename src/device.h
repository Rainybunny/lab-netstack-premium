/**
 * @file device.h
 * @brief Library supporting network device management.
 */

#pragma once

#include "utils.h"
#include "pcap/pcap.h"

#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include <optional>
#include <string>
#include <vector>

/**
 * @brief An IPv4 address and its subnet mask on one interface.
 */
struct DeviceAddress {
    in_addr address;
    in_addr netmask;
};

/**
 * Scan all devices and initialize their metadata.
 *
 * @note Call before any other device operation. Repeated calls are harmless;
 * the initial interface snapshot is retained.
 */
void initAllDevices();

/**
 * Return copies of the interface names discovered by initAllDevices().
 */
std::vector<std::string> getDeviceNames();

/**
 * Add a device to the library for sending / receiving packets.
 *
 * @param device Name of network device to send / receive packet on.
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
int addDevice(const char* device);

/**
 * Find a device added by `addDevice'.
 *
 * @param device Name of the network device.
 * @return A non-negative _device-ID_ on success, -1 if no such device
 * was found.
 */
int findDevice(const char* device);

/**
 * Get the MAC address of the device with id @p id.
 *
 * @param id device-ID.
 * @return MAC address if one is available, nullopt otherwise.
 */
std::optional<macaddr_t> getMac(int id);

/**
 * Return the IDs of all devices that have been added successfully.
 */
std::vector<int> getActiveDeviceIds();

/**
 * Return the IPv4 addresses and netmasks of an active device.
 *
 * @param id device-ID.
 * @return A copy of the address list, or an empty vector for an invalid ID.
 */
std::vector<DeviceAddress> getDeviceAddresses(int id);

bool isLocalAddress(int deviceId, in_addr addr);

/**
 * Inject @p len bytes starting from @p bytes to device of ID @p id.
 *
 * @param id device-ID.
 * @param bytes pointer to frame. This function involves no wrapper.
 * @param len length of frame.
 * @return 0 on success, -1 on failure.
 */
int injectFrame(int id, const uint8_t* bytes, int len);

/**
 * Run a single-threaded receive loop on all added devices.
 *
 * @param callback Handler for captured bytes, captured length and device-ID.
 * @note Devices must be added before entering the loop. The handler must not
 * throw or retain the buffer after returning. Nested loops are not supported.
 * @return 0 when stopped, -1 on setup or capture error.
 */
int runDeviceReceiveLoop(void (*callback)(const void*, int, int));

/**
 * Process one batch of pending frames, run the protocol tick, then wait up to
 * @p timeoutMs for more frames.
 *
 * This is the body of runDeviceReceiveLoop(), exposed so a blocking socket
 * call can drive the stack while it waits. The first call prepares the poll
 * descriptors; subsequent calls reuse them.
 *
 * @param callback Handler for captured bytes, captured length and device-ID.
 * @param timeoutMs Poll timeout in milliseconds, or 0 to return immediately
 * after draining pending frames.
 * @return 0 on success, -1 on setup or capture error.
 */
int pollDevicesOnce(void (*callback)(const void*, int, int), int timeoutMs);

/**
 * Request that the current receive loop stop after the current callback.
 * @note Call from the receive callback, not another thread or a signal handler.
 */
void stopDeviceReceiveLoop();

/**
 * Register a function called once per receive-loop iteration.
 *
 * The loop wakes at least every 100 ms, so the tick can drive HELLO, LSA,
 * ARP and other timers without a second thread. The callback must not throw,
 * block, or start another receive loop.
 *
 * @param callback Tick handler, or nullptr to clear it.
 */
void setDeviceTickCallback(void (*callback)());
