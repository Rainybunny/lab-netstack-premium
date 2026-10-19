#include "device.h"

#include <cerrno>
#include <climits>
#include <poll.h>

static int dev_id_count = 0;
static std::map<std::string, int> name_to_dev, name_to_id;

struct DeviceInfo {
    std::string name;
    std::optional<macaddr_t> mac;

    DeviceInfo(const pcap_if_t* dev): name(dev->name), mac(std::nullopt) {
        for (auto* a = dev->addresses; a != nullptr; a = a->next) {
            if (!a->addr || a->addr->sa_family != AF_PACKET) {
                continue;
            }
            const auto* link = (const sockaddr_ll*)(a->addr);
            if (link->sll_hatype != ARPHRD_ETHER || link->sll_halen != 6) {
                continue;
            }

            mac.emplace(macaddr_t());
            memcpy(mac.value().data(), link->sll_addr, mac.value().size());
        }
    }
};

static std::vector<DeviceInfo> all_devs;
static std::map<int, std::pair<pcap_t*, int>> active_handles;
static bool receive_running = false;
static bool receive_stop = false;

static struct handles_destroyer {
    ~handles_destroyer() {
        for (auto [_, handle] : active_handles) {
            pcap_close(handle.first);
        }
    }
} destroyer;

void init_all_devices() {
    static bool initialized = false;
    if (initialized) {
        return;
    }
    pcap_if_t* devices = nullptr;
    pcap_errbuf_t errbuf{};
    int r = pcap_findalldevs(&devices, errbuf);
    if (r < 0) {
        PANIC("init_all_devices: %s\n", errbuf);
    }
    for (auto dev = devices; dev != nullptr; dev = dev->next) {
        name_to_dev[dev->name] = (int)all_devs.size();
        all_devs.emplace_back(dev);
    }
    pcap_freealldevs(devices);
    initialized = true;
}

std::vector<std::string> get_device_names() {
    std::vector<std::string> names;
    for (const auto& device : all_devs) {
        names.push_back(device.name);
    }
    return names;
}

static pcap_t* get_handle(int id) {
    auto it = active_handles.find(id);
    return it == active_handles.end() ? nullptr : it->second.first;
}

std::optional<macaddr_t> get_mac(int id) {
    auto it = active_handles.find(id);
    return it == active_handles.end() ? std::nullopt : all_devs[it->second.second].mac;
}

int add_device(const char* device) {
    static pcap_errbuf_t errbuf;

    if (device == nullptr) {
        return -1;
    }
    if (receive_running) {
        WARN("add_device: receive loop is running\n");
        return -1;
    }

    if (name_to_id.contains(device)) {
        return name_to_id[device];
    }

    auto it = name_to_dev.find(device);
    if (it == name_to_dev.end() || !all_devs[it->second].mac) {
        WARN("add_device: unknown or non-Ethernet interface %s\n", device);
        return -1;
    }
    auto handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        WARN("add_device: %s: %s\n", device, errbuf);
        return -1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        WARN("add_device: unsupported link type\n");
        pcap_close(handle);
        return -1;
    }

    int id = dev_id_count++;
    active_handles[id] = { handle, it->second };
    return name_to_id[device] = id;
}

int find_device(const char* device) {
    if (device == nullptr) {
        return -1;
    }
    auto it = name_to_id.find(device);
    return it == name_to_id.end() ? -1 : it->second;
}

int inject_frame(int id, const u_char* bytes, int len) {
    auto handle = get_handle(id);
    if (handle == nullptr || bytes == nullptr || len < 14) {
        return -1;
    }
    int result = pcap_sendpacket(handle, bytes, len);
    if (result != 0) {
        WARN("inject_frame: device %d: %s\n", id, pcap_geterr(handle));
        return -1;
    }
    return 0;
}

int run_device_receive_loop(void (*callback)(const void*, int, int)) {
    if (receive_running || callback == nullptr || active_handles.empty()) {
        WARN("run_device_receive_loop: invalid state or callback\n");
        return -1;
    }

    std::vector<pollfd> descriptors;
    pcap_errbuf_t errbuf{};
    for (const auto& [id, entry] : active_handles) {
        auto* handle = entry.first;
        int fd = pcap_get_selectable_fd(handle);
        // This loop targets Linux Ethernet/veth capture with poll support.
        if (fd < 0 || pcap_get_required_select_timeout(handle) != nullptr) {
            WARN("run_device_receive_loop: device %d cannot use this poll loop\n", id);
            return -1;
        }
        if (pcap_setnonblock(handle, 1, errbuf) < 0) {
            WARN("run_device_receive_loop: device %d: %s\n", id, errbuf);
            return -1;
        }
        descriptors.push_back({fd, POLLIN, 0});
    }

    receive_running = true;
    receive_stop = false;
    struct running_reset {
        ~running_reset() { receive_running = false; }
    } reset;

    // Bound each device's turn so a busy interface cannot starve the others.
    constexpr int batch_size = 64;
    while (!receive_stop) {
        bool pending = false;
        for (const auto& [id, entry] : active_handles) {
            for (int count = 0; count < batch_size && !receive_stop; ++count) {
                pcap_pkthdr* header = nullptr;
                const u_char* bytes = nullptr;
                int result = pcap_next_ex(entry.first, &header, &bytes);
                if (result == 0) {
                    break;
                }
                if (result < 0) {
                    WARN("run_device_receive_loop: device %d: %s\n",
                         id, pcap_geterr(entry.first));
                    return -1;
                }
                // Do not pass truncated captures or an unrepresentable length.
                if (header->caplen == header->len && header->caplen <= INT_MAX) {
                    callback(bytes, static_cast<int>(header->caplen), id);
                }
                if (count == batch_size - 1) {
                    pending = true;
                }
            }
            if (receive_stop) {
                break;
            }
        }
        if (receive_stop) {
            break;
        }

        // libpcap may still hold packets even when its fd is not readable.
        // Only sleep after every handle has reported an empty capture buffer.
        int result = poll(descriptors.data(), descriptors.size(), pending ? 0 : -1);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            WARN("run_device_receive_loop: poll: %s\n", strerror(errno));
            return -1;
        }
        for (const auto& descriptor : descriptors) {
            if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                WARN("run_device_receive_loop: capture descriptor failed\n");
                return -1;
            }
        }
    }
    return 0;
}

void stop_device_receive_loop() {
    if (receive_running) {
        receive_stop = true;
    }
}
