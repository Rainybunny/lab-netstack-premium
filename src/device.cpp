#include "device.h"

#include <cerrno>
#include <climits>
#include <cstring>
#include <map>
#include <poll.h>

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
                // A missing netmask is treated as a host route rather than
                // accidentally installing a default connected route.
                value.netmask.s_addr = INADDR_BROADCAST;
                if (address->netmask != nullptr &&
                    address->netmask->sa_family == AF_INET) {
                    value.netmask =
                        reinterpret_cast<const sockaddr_in*>(address->netmask)->sin_addr;
                }
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
    static pcap_errbuf_t errbuf;

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
    pcap_t* handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        WARN("addDevice: %s: %s\n", device, errbuf);
        return -1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        WARN("addDevice: unsupported link type\n");
        pcap_close(handle);
        return -1;
    }

    // Do not feed locally injected frames back into the stack. If the
    // platform rejects this request, packetio drops frames whose source MAC
    // is the receiving device's MAC instead.
    if (pcap_setdirection(handle, PCAP_D_IN) < 0) {
        WARN("addDevice: cannot restrict capture direction: %s\n", pcap_geterr(handle));
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
        WARN("injectFrame: device %d: %s\n", id, pcap_geterr(handle));
        return -1;
    }
    return 0;
}

void setDeviceTickCallback(void (*callback)()) {
    tickCallback = callback;
}

int runDeviceReceiveLoop(void (*callback)(const void*, int, int)) {
    if (receiveRunning || callback == nullptr || activeHandles.empty()) {
        WARN("runDeviceReceiveLoop: invalid state or callback\n");
        return -1;
    }

    std::vector<pollfd> descriptors;
    pcap_errbuf_t errbuf{};
    for (const auto& [id, entry] : activeHandles) {
        pcap_t* handle = entry.first;
        int fd = pcap_get_selectable_fd(handle);
        // This loop targets Linux Ethernet/veth capture with poll support.
        if (fd < 0 || pcap_get_required_select_timeout(handle) != nullptr) {
            WARN("runDeviceReceiveLoop: device %d cannot use this poll loop\n", id);
            return -1;
        }
        if (pcap_setnonblock(handle, 1, errbuf) < 0) {
            WARN("runDeviceReceiveLoop: device %d: %s\n", id, errbuf);
            return -1;
        }
        descriptors.push_back({fd, POLLIN, 0});
    }

    receiveRunning = true;
    receiveStop = false;
    struct RunningReset {
        ~RunningReset() { receiveRunning = false; }
    } reset;

    // Bound each device's turn so a busy interface cannot starve the others.
    constexpr int batchSize = 64;
    constexpr int pollTimeoutMs = 100;
    while (!receiveStop) {
        bool pending = false;
        for (const auto& [id, entry] : activeHandles) {
            for (int count = 0; count < batchSize && !receiveStop; ++count) {
                pcap_pkthdr* header = nullptr;
                const u_char* bytes = nullptr;
                int result = pcap_next_ex(entry.first, &header, &bytes);
                if (result == 0) {
                    break;
                }
                if (result < 0) {
                    WARN("runDeviceReceiveLoop: device %d: %s\n",
                         id, pcap_geterr(entry.first));
                    return -1;
                }
                // Do not pass truncated captures or an unrepresentable length.
                if (header->caplen == header->len && header->caplen <= INT_MAX) {
                    callback(bytes, static_cast<int>(header->caplen), id);
                }
                if (count == batchSize - 1) {
                    pending = true;
                }
            }
            if (receiveStop) {
                break;
            }
        }
        if (receiveStop) {
            break;
        }

        // Timers run on the same thread as packet processing. Keeping the
        // poll timeout finite is what lets HELLO, LSA and ARP time out.
        if (tickCallback != nullptr) {
            tickCallback();
        }
        if (receiveStop) {
            break;
        }

        // libpcap may still hold packets even when its fd is not readable.
        // Only sleep after every handle has reported an empty capture buffer.
        int result = poll(descriptors.data(), descriptors.size(),
                          pending ? 0 : pollTimeoutMs);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            WARN("runDeviceReceiveLoop: poll: %s\n", strerror(errno));
            return -1;
        }
        for (const auto& descriptor : descriptors) {
            if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                WARN("runDeviceReceiveLoop: capture descriptor failed\n");
                return -1;
            }
        }
    }
    return 0;
}

void stopDeviceReceiveLoop() {
    if (receiveRunning) {
        receiveStop = true;
    }
}
