#include "egress.h"

#include "device.h"
#include "packetio.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <vector>

namespace {

struct QueueEntry {
    std::vector<uint8_t> packet;
    macaddr_t mac;
    double finish = 0;
};

struct FlowQueue {
    std::deque<QueueEntry> queue;
    double lastFinish = 0;
};

struct EgressState {
    int deviceId = -1;
    double rate = 0;
    size_t capacity = 32768;
    bool wfq = false;
    std::deque<QueueEntry> fifo;
    std::map<uint32_t, FlowQueue> flows;
    std::map<uint32_t, int> weights;
    size_t queuedBytes = 0;
    double tokens = 0;
    double virtualTime = 0;
    TimePoint last;
};

EgressState egress;

int parseWeight(const char* text, uint32_t& address, int& weight) {
    const char* equals = std::strchr(text, '=');
    if (equals == nullptr) {
        return -1;
    }
    char addressText[INET_ADDRSTRLEN] = {};
    const size_t length = size_t(equals - text);
    if (length == 0 || length >= sizeof(addressText)) {
        return -1;
    }
    std::memcpy(addressText, text, length);
    in_addr parsed{};
    if (inet_pton(AF_INET, addressText, &parsed) != 1) {
        return -1;
    }
    const int value = std::atoi(equals + 1);
    if (value <= 0) {
        return -1;
    }
    address = parsed.s_addr;
    weight = value;
    return 0;
}

} // namespace

void egressInit() {
    egress = EgressState{};

    const char* device = std::getenv("NETSTACK_EGRESS_DEV");
    const char* rate = std::getenv("NETSTACK_EGRESS_RATE");
    if (device == nullptr || rate == nullptr) {
        return;
    }
    egress.deviceId = findDevice(device);
    egress.rate = std::atof(rate);
    if (egress.deviceId < 0 || egress.rate <= 0) {
        WARN("egress: invalid device or rate\n");
        egress.deviceId = -1;
        return;
    }

    const char* capacity = std::getenv("NETSTACK_EGRESS_QUEUE");
    if (capacity != nullptr) {
        egress.capacity = size_t(std::strtoul(capacity, nullptr, 10));
    }
    const char* mode = std::getenv("NETSTACK_EGRESS_MODE");
    egress.wfq = mode != nullptr && std::strcmp(mode, "wfq") == 0;

    const char* weights = std::getenv("NETSTACK_EGRESS_WEIGHTS");
    if (weights != nullptr) {
        const char* cursor = weights;
        while (*cursor != '\0') {
            const char* comma = std::strchr(cursor, ',');
            const size_t length =
                comma == nullptr ? std::strlen(cursor) : size_t(comma - cursor);
            char item[128] = {};
            if (length < sizeof(item)) {
                std::memcpy(item, cursor, length);
                uint32_t address = 0;
                int weight = 0;
                if (parseWeight(item, address, weight) == 0) {
                    egress.weights[address] = weight;
                }
            }
            if (comma == nullptr) {
                break;
            }
            cursor = comma + 1;
        }
    }

    egress.last = std::chrono::steady_clock().now();
}

bool egressEnabled(int deviceId) {
    return egress.deviceId >= 0 && egress.deviceId == deviceId;
}

int egressEnqueue(int deviceId, const macaddr_t& mac, const void* packet,
                  int len, in_addr source) {
    if (!egressEnabled(deviceId) || packet == nullptr || len <= 0) {
        return -1;
    }
    if (egress.queuedBytes + size_t(len) > egress.capacity) {
        return 0; // tail drop
    }

    QueueEntry entry;
    const auto* bytes = static_cast<const uint8_t*>(packet);
    entry.packet.assign(bytes, bytes + len);
    entry.mac = mac;

    if (egress.wfq) {
        const uint32_t key = source.s_addr;
        const auto weightIt = egress.weights.find(key);
        const int weight = weightIt == egress.weights.end() ? 1 : weightIt->second;
        FlowQueue& flow = egress.flows[key];
        entry.finish = std::max(egress.virtualTime, flow.lastFinish) +
                       double(len) / double(weight);
        flow.lastFinish = entry.finish;
        flow.queue.push_back(std::move(entry));
    } else {
        egress.fifo.push_back(std::move(entry));
    }
    egress.queuedBytes += size_t(len);
    return 0;
}

void egressTick(TimePoint now) {
    if (egress.deviceId < 0) {
        return;
    }
    const double elapsed =
        std::chrono::duration<double>(now - egress.last).count();
    egress.last = now;
    egress.tokens = std::min(egress.tokens + egress.rate * elapsed,
                             egress.rate * 0.02 + 1500.0);

    while (egress.queuedBytes > 0) {
        QueueEntry* selected = nullptr;
        uint32_t selectedFlow = 0;

        if (egress.wfq) {
            for (auto& [key, flow] : egress.flows) {
                if (flow.queue.empty()) {
                    continue;
                }
                if (selected == nullptr ||
                    flow.queue.front().finish < selected->finish) {
                    selected = &flow.queue.front();
                    selectedFlow = key;
                }
            }
        } else if (!egress.fifo.empty()) {
            selected = &egress.fifo.front();
        }

        if (selected == nullptr) {
            break;
        }
        const size_t length = selected->packet.size();
        if (double(length) > egress.tokens) {
            break;
        }

        sendFrame(selected->packet.data(), int(length), ETH_TYPE_IPV4,
                  selected->mac.data(), egress.deviceId);
        egress.tokens -= double(length);
        egress.queuedBytes -= std::min(egress.queuedBytes, length);
        if (egress.wfq) {
            egress.virtualTime = std::max(egress.virtualTime, selected->finish);
            FlowQueue& flow = egress.flows[selectedFlow];
            flow.queue.pop_front();
            if (flow.queue.empty()) {
                egress.flows.erase(selectedFlow);
            }
        } else {
            egress.fifo.pop_front();
        }
    }
}
