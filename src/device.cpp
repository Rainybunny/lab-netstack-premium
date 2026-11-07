#include "device.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <map>
#include <poll.h>
#include <set>
#include <thread>

namespace {

int devIdCount = 0;
std::map<std::string, int> nameToDev;
std::map<std::string, int> nameToId;

struct DeviceInfo {
    std::string name;
    std::optional<macaddr_t> mac;
    std::vector<DeviceAddress> addresses;

    explicit DeviceInfo(const pcap_if_t* dev) : name(dev->name), mac(std::nullopt) {
        for (auto* address = dev->addresses; address != nullptr; address = address->next) {
            if (address->addr == nullptr) {
                continue;
            }
            if (address->addr->sa_family == AF_PACKET) {
                const auto* link = reinterpret_cast<const sockaddr_ll*>(address->addr);
                if (link->sll_hatype != ARPHRD_ETHER || link->sll_halen != 6) {
                    continue;
                }
                macaddr_t value{};
                std::memcpy(value.data(), link->sll_addr, value.size());
                mac = value;
            } else if (address->addr->sa_family == AF_INET) {
                const auto* inet = reinterpret_cast<const sockaddr_in*>(address->addr);
                DeviceAddress value{};
                value.address = inet->sin_addr;
                if (address->netmask == nullptr) {
                    continue;
                }
                value.netmask =
                    reinterpret_cast<const sockaddr_in*>(address->netmask)->sin_addr;
                addresses.push_back(value);
            }
        }
    }
};

std::vector<DeviceInfo> allDevs;
std::map<int, std::pair<pcap_t*, int>> activeHandles;
bool receiveRunning = false;
bool receiveStop = false;
void (*tickCallback)() = nullptr;

struct HandlesDestroyer {
    ~HandlesDestroyer() {
        for (auto [_, handle] : activeHandles) {
            pcap_close(handle.first);
        }
    }
} destroyer;

} // namespace

void initAllDevices() {
    static bool initialized = false;
    if (initialized) {
        return;
    }
    pcap_if_t* devices = nullptr;
    pcap_errbuf_t errbuf{};
    int result = pcap_findalldevs(&devices, errbuf);
    if (result < 0) {
        PANIC("initAllDevices: %s\n", errbuf);
    }
    for (auto* device = devices; device != nullptr; device = device->next) {
        nameToDev[device->name] = static_cast<int>(allDevs.size());
        allDevs.emplace_back(device);
    }
    pcap_freealldevs(devices);
    initialized = true;
}

std::vector<std::string> getDeviceNames() {
    std::vector<std::string> names;
    for (const auto& device : allDevs) {
        names.push_back(device.name);
    }
    return names;
}

namespace {

pcap_t* getHandle(int id) {
    auto it = activeHandles.find(id);
    return it == activeHandles.end() ? nullptr : it->second.first;
}

const DeviceInfo* getDeviceInfo(int id) {
    auto it = activeHandles.find(id);
    if (it == activeHandles.end()) {
        return nullptr;
    }
    return &allDevs[it->second.second];
}

} // namespace

std::optional<macaddr_t> getMac(int id) {
    const DeviceInfo* device = getDeviceInfo(id);
    return device == nullptr ? std::nullopt : device->mac;
}

std::vector<int> getActiveDeviceIds() {
    std::vector<int> ids;
    for (const auto& entry : activeHandles) {
        ids.push_back(entry.first);
    }
    return ids;
}

std::vector<DeviceAddress> getDeviceAddresses(int id) {
    const DeviceInfo* device = getDeviceInfo(id);
    return device == nullptr ? std::vector<DeviceAddress>{} : device->addresses;
}

bool isLocalAddress(int deviceId, in_addr addr) {
    for (const auto &entry : getDeviceAddresses(deviceId)) {
        if (entry.address.s_addr == addr.s_addr) {
            return true;
        }
    }
    return false;
}

int addDevice(const char* device) {
    pcap_errbuf_t errbuf{};

    if (device == nullptr) {
        return -1;
    }
    if (receiveRunning) {
        WARN("addDevice: receive loop is running\n");
        return -1;
    }

    auto idIt = nameToId.find(device);
    if (idIt != nameToId.end()) {
        return idIt->second;
    }

    auto devIt = nameToDev.find(device);
    if (devIt == nameToDev.end() || !allDevs[devIt->second].mac) {
        WARN("addDevice: unknown or non-Ethernet interface %s\n", device);
        return -1;
    }

    pcap_t* handle = pcap_create(device, errbuf);
    if (handle == nullptr) {
        WARN("addDevice: %s: %s\n", device, errbuf);
        return -1;
    }
    if (pcap_set_snaplen(handle, 65535) < 0 ||
        pcap_set_promisc(handle, 1) < 0 ||
        pcap_set_timeout(handle, 100) < 0 ||
        pcap_set_buffer_size(handle, 16 * 1024 * 1024) < 0 ||
        pcap_set_immediate_mode(handle, 1) < 0) {
        WARN("addDevice: %s: %s\n", device, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    const int activate = pcap_activate(handle);
    if (activate < 0) {
        WARN("addDevice: %s: %s\n", device, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    if (activate > 0) {
        WARN("addDevice: %s: %s\n", device, pcap_statustostr(activate));
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        WARN("addDevice: unsupported link type\n");
        pcap_close(handle);
        return -1;
    }

    // Linux Ethernet/veth supports incoming-only capture.
    if (pcap_setdirection(handle, PCAP_D_IN) < 0) {
        WARN("addDevice: cannot restrict capture direction: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    int id = devIdCount++;
    activeHandles[id] = {handle, devIt->second};
    nameToId[device] = id;
    return id;
}

int findDevice(const char* device) {
    if (device == nullptr) {
        return -1;
    }
    auto it = nameToId.find(device);
    return it == nameToId.end() ? -1 : it->second;
}

int injectFrame(int id, const uint8_t* bytes, int len) {
    pcap_t* handle = getHandle(id);
    if (handle == nullptr || bytes == nullptr || len < static_cast<int>(ETH_HEADER_LEN)) {
        return -1;
    }
    int result = pcap_sendpacket(handle, bytes, len);
    if (result != 0) {
        // A link can be administratively down during a topology test. Report
        // the first failure per device without flooding the log every second.
        static std::set<int> warnedDevices;
        if (warnedDevices.insert(id).second) {
            WARN("injectFrame: device %d: %s\n", id, pcap_geterr(handle));
        }
        return -1;
    }
    return 0;
}

void setDeviceTickCallback(void (*callback)()) {
    tickCallback = callback;
}

namespace {

bool pollPrepared = false;
std::vector<pollfd> pollDescriptors;
// A veth that is administratively down makes its capture descriptor report
// an error. Keep the other devices running; the handle is polled again in
// case the link comes back.
std::set<int> warnedDevices;
std::set<int> warnedDescriptors;

int preparePollDescriptors() {
    if (pollPrepared) {
        return 0;
    }
    pcap_errbuf_t errbuf{};
    for (const auto& [id, entry] : activeHandles) {
        pcap_t* handle = entry.first;
        int fd = pcap_get_selectable_fd(handle);
        // This loop targets Linux Ethernet/veth capture with poll support.
        if (fd < 0) {
            WARN("preparePollDescriptors: device %d cannot use this poll loop\n", id);
            return -1;
        }
        if (pcap_setnonblock(handle, 1, errbuf) < 0) {
            WARN("preparePollDescriptors: device %d: %s\n", id, errbuf);
            return -1;
        }
        pollDescriptors.push_back({fd, POLLIN, 0});
    }
    pollPrepared = true;
    return 0;
}

bool stopping() {
    return receiveRunning && receiveStop;
}

} // namespace

int pollDevicesOnce(void (*callback)(const void*, int, int), int timeoutMs) {
    if (callback == nullptr || activeHandles.empty()) {
        WARN("pollDevicesOnce: invalid state or callback\n");
        return -1;
    }
    if (preparePollDescriptors() < 0) {
        return -1;
    }

    // Bound each device's turn so a busy interface cannot starve the others.
    constexpr int batchSize = 64;
    bool pending = false;
    for (const auto& [id, entry] : activeHandles) {
        for (int count = 0; count < batchSize && !stopping(); ++count) {
            pcap_pkthdr* header = nullptr;
            const u_char* bytes = nullptr;
            int result = pcap_next_ex(entry.first, &header, &bytes);
            if (result == 0) {
                break;
            }
            if (result < 0) {
                if (warnedDevices.insert(id).second) {
                    WARN("pollDevicesOnce: device %d: %s\n",
                         id, pcap_geterr(entry.first));
                }
                break;
            }
            // snaplen is 65535; only complete captures are dispatched.
            if (header->caplen == header->len) {
                callback(bytes, static_cast<int>(header->caplen), id);
            }
            if (count == batchSize - 1) {
                pending = true;
            }
        }
        if (stopping()) {
            return 0;
        }
    }

    // Timers run on the same thread as packet processing. Keeping the
    // poll timeout finite is what lets HELLO, LSA, ARP and TCP time out.
    if (tickCallback != nullptr) {
        tickCallback();
    }
    if (stopping()) {
        return 0;
    }

    if (std::getenv("NETSTACK_PCAP_STATS") != nullptr) {
        static TimePoint lastStats;
        const TimePoint now = std::chrono::steady_clock().now();
        if (lastStats.time_since_epoch().count() == 0 ||
            now - lastStats >= std::chrono::seconds(1)) {
            lastStats = now;
            for (const auto& [id, entry] : activeHandles) {
                pcap_stat stats{};
                if (pcap_stats(entry.first, &stats) == 0) {
                    WARN("pcap device %d recv=%u drop=%u\n", id, stats.ps_recv,
                         stats.ps_drop);
                }
            }
        }
    }

    // libpcap may still hold packets even when its fd is not readable.
    // Only sleep after every handle has reported an empty capture buffer.
    int result = poll(pollDescriptors.data(), pollDescriptors.size(),
                      pending ? 0 : timeoutMs);
    if (result < 0) {
        if (errno == EINTR) {
            return 0;
        }
        WARN("pollDevicesOnce: poll: %s\n", strerror(errno));
        return -1;
    }
    bool descriptorError = false;
    for (const auto& descriptor : pollDescriptors) {
        if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            descriptorError = true;
            if (warnedDescriptors.insert(descriptor.fd).second) {
                WARN("pollDevicesOnce: capture descriptor %d failed\n",
                     descriptor.fd);
            }
        }
    }
    // poll() returns immediately while a descriptor is in an error state.
    // A short sleep keeps a down link from spinning the receive loop.
    if (descriptorError) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}

int runDeviceReceiveLoop(void (*callback)(const void*, int, int)) {
    if (receiveRunning || callback == nullptr || activeHandles.empty()) {
        WARN("runDeviceReceiveLoop: invalid state or callback\n");
        return -1;
    }

    receiveRunning = true;
    receiveStop = false;
    struct RunningReset {
        ~RunningReset() { receiveRunning = false; }
    } reset;

    while (!receiveStop) {
        if (pollDevicesOnce(callback, 100) < 0) {
            return -1;
        }
    }
    return 0;
}

void stopDeviceReceiveLoop() {
    if (receiveRunning) {
        receiveStop = true;
    }
}
