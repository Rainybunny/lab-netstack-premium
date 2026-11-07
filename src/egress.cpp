#include "egress.h"

#include "device.h"
#include "packetio.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <vector>

namespace {

constexpr int64_t DRR_QUANTUM = 1500; // bytes per weight unit

struct QueueEntry {
    std::vector<uint8_t> packet;
    macaddr_t mac;
};

struct FlowQueue {
    std::deque<QueueEntry> queue;
    size_t queuedBytes = 0;
    int64_t deficit = 0;
    int weight = 1;
};

struct EgressState {
    int deviceId = -1;
    double rate = 0;
    size_t capacity = 32768;
    bool wfq = false;
    std::deque<QueueEntry> fifo;
    std::map<uint32_t, FlowQueue> flows;
    std::map<uint32_t, int> weights;
    std::map<uint32_t, FlowQueue>::iterator current;
    size_t queuedBytes = 0;
    double tokens = 0;
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

void logEnqueued(uint32_t flow, size_t length, TimePoint now) {
    static std::map<uint32_t, uint64_t> counts;
    static TimePoint last;
    counts[flow] += length;
    if (last.time_since_epoch().count() == 0) {
        last = now;
        return;
    }
    if (now - last < std::chrono::seconds(1)) {
        return;
    }
    last = now;
    for (const auto& [key, bytes] : counts) {
        WARN("egress enq flow=%u bytes=%llu\n", key,
             static_cast<unsigned long long>(bytes));
    }
}

void logSent(uint32_t flow, size_t length, TimePoint now) {
    static std::map<uint32_t, uint64_t> counts;
    static TimePoint last;
    counts[flow] += length;
    if (last.time_since_epoch().count() == 0) {
        last = now;
        return;
    }
    if (now - last < std::chrono::seconds(1)) {
        return;
    }
    last = now;
    for (const auto& [key, bytes] : counts) {
        WARN("egress flow=%u bytes=%llu\n", key,
             static_cast<unsigned long long>(bytes));
    }
}

} // namespace

void egressInit() {
    egress = EgressState{};
    egress.current = egress.flows.end();

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
    QueueEntry entry;
    const auto* bytes = static_cast<const uint8_t*>(packet);
    entry.packet.assign(bytes, bytes + len);
    entry.mac = mac;

    if (egress.wfq) {
        const uint32_t key = source.s_addr;
        FlowQueue& flow = egress.flows[key];
        if (flow.queuedBytes + size_t(len) > egress.capacity) {
            if (std::getenv("NETSTACK_EGRESS_LOG") != nullptr) {
                static std::map<uint32_t, uint64_t> drops;
                drops[key] += uint64_t(len);
                WARN("egress drop flow=%u bytes=%llu\n", key,
                     static_cast<unsigned long long>(drops[key]));
            }
            return 0; // per-flow tail drop
        }
        if (std::getenv("NETSTACK_EGRESS_LOG") != nullptr) {
            logEnqueued(key, size_t(len), std::chrono::steady_clock().now());
        }
        const auto weightIt = egress.weights.find(key);
        flow.weight = weightIt == egress.weights.end() ? 1 : weightIt->second;
        flow.queuedBytes += size_t(len);
        flow.queue.push_back(std::move(entry));
        if (egress.current == egress.flows.end()) {
            egress.current = egress.flows.begin();
        }
    } else {
        if (egress.queuedBytes + size_t(len) > egress.capacity) {
            return 0; // shared tail drop
        }
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

    if (!egress.wfq) {
        while (!egress.fifo.empty()) {
            QueueEntry& entry = egress.fifo.front();
            const size_t length = entry.packet.size();
            if (double(length) > egress.tokens) {
                break;
            }
            sendFrame(entry.packet.data(), int(length), ETH_TYPE_IPV4,
                      entry.mac.data(), egress.deviceId);
            egress.tokens -= double(length);
            egress.queuedBytes -= std::min(egress.queuedBytes, length);
            egress.fifo.pop_front();
        }
        return;
    }

    // Deficit round robin with a persistent round-robin position, so a
    // flow that cannot send for lack of tokens does not block the others.
    bool progress = true;
    while (progress && egress.queuedBytes > 0) {
        progress = false;
        size_t attempts = 0;
        while (attempts < egress.flows.size()) {
            if (egress.flows.empty()) {
                break;
            }
            if (egress.current == egress.flows.end()) {
                egress.current = egress.flows.begin();
            }
            FlowQueue& flow = egress.current->second;
            ++attempts;
            if (flow.queue.empty()) {
                flow.deficit = 0;
                flow.queuedBytes = 0;
                ++egress.current;
                continue;
            }
            const size_t length = flow.queue.front().packet.size();
            if (double(length) > egress.tokens) {
                // Resume this flow after the bucket refills; advancing now
                // would let the next flow take its quantum's tokens.
                break;
            }
            if (flow.deficit < int64_t(length)) {
                flow.deficit += DRR_QUANTUM * flow.weight;
            }
            while (!flow.queue.empty()) {
                QueueEntry& entry = flow.queue.front();
                const size_t packetLength = entry.packet.size();
                if (flow.deficit < int64_t(packetLength) ||
                    double(packetLength) > egress.tokens) {
                    break;
                }
                const uint32_t key = egress.current->first;
                sendFrame(entry.packet.data(), int(packetLength),
                          ETH_TYPE_IPV4, entry.mac.data(), egress.deviceId);
                egress.tokens -= double(packetLength);
                egress.queuedBytes -= std::min(egress.queuedBytes, packetLength);
                flow.deficit -= int64_t(packetLength);
                flow.queuedBytes -= std::min(flow.queuedBytes, packetLength);
                flow.queue.pop_front();
                if (std::getenv("NETSTACK_EGRESS_LOG") != nullptr) {
                    logSent(key, packetLength, now);
                }
                progress = true;
            }
            if (flow.queue.empty()) {
                flow.deficit = 0;
                flow.queuedBytes = 0;
                ++egress.current;
            } else if (flow.deficit <
                       int64_t(flow.queue.front().packet.size())) {
                ++egress.current;
            } else {
                // The flow still has quantum but the bucket is empty.
                break;
            }
            if (egress.tokens < 1.0) {
                break;
            }
        }
    }
}
