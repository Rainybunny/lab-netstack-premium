/**
 * @file lab2_demo.cpp
 * @brief CP3-CP6 demo: IP forwarding, link-state routes, longest prefix match.
 *
 * The process runs one stack instance and reads commands from stdin:
 *   ping IP [COUNT]              send ICMP echo requests
 *   distances                    print SPF router distances
 *   lookup IP                    print matching routes and the selected one
 *   setroute DEST MASK MAC DEV   install a static route
 *   quit                         stop the receive loop
 *
 * ICMP echo lives here, not in the IP library: PT3 only requires IP send and
 * receive, while CP4 needs an application-level reachability test.
 */

#include "device.h"
#include "ip.h"
#include "link_state.h"
#include "netstack.h"
#include "packetio.h"
#include "routing.h"
#include "utils.h"

#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint8_t ICMP_ECHO_REPLY = 0;
constexpr uint8_t ICMP_ECHO_REQUEST = 8;
constexpr int PING_DEFAULT_COUNT = 4;
constexpr int PING_MAX_COUNT = 100;
constexpr int PING_TIMEOUT_MS = 1000;

struct PingState {
    bool active = false;
    in_addr destination{};
    int count = 0;
    int sent = 0;
    int received = 0;
    uint16_t identifier = 0;
    uint16_t sequence = 0;
    bool waiting = false;
    TimePoint sentAt;
    TimePoint deadline;
};

PingState ping;
std::string inputBuffer;
bool stdinOpen = true;

std::string ipToString(in_addr address) {
    char buffer[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &address, buffer, sizeof(buffer));
    return buffer;
}

std::string macToString(const macaddr_t& mac) {
    char buffer[18] = {};
    std::snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buffer;
}

std::string deviceName(int deviceId) {
    for (const auto& name : getDeviceNames()) {
        if (findDevice(name.c_str()) == deviceId) {
            return name;
        }
    }
    return "?";
}

const char* kindName(RouteKind kind) {
    switch (kind) {
    case RouteKind::Connected:
        return "connected";
    case RouteKind::Static:
        return "static";
    case RouteKind::Dynamic:
        return "dynamic";
    }
    return "?";
}

uint16_t checksum16(const void* data, size_t len) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    size_t index = 0;
    for (; index + 1 < len; index += 2) {
        sum += (uint16_t(bytes[index]) << 8) | bytes[index + 1];
    }
    if (index < len) {
        sum += uint16_t(bytes[index]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return uint16_t(~sum);
}

bool parseIp(const char* text, in_addr& address) {
    return inet_pton(AF_INET, text, &address) == 1;
}

bool parseMac(const char* text, macaddr_t& mac) {
    if (std::strlen(text) != 17) {
        return false;
    }
    for (size_t i = 0; i < mac.size(); ++i) {
        unsigned value = 0;
        const char* begin = text + i * 3;
        const auto result = std::from_chars(begin, begin + 2, value, 16);
        if (result.ec != std::errc() || result.ptr != begin + 2 ||
            (i != 5 && text[i * 3 + 2] != ':')) {
            return false;
        }
        mac[i] = static_cast<uint8_t>(value);
    }
    return true;
}

bool parseCount(const char* text, int& count) {
    char* end = nullptr;
    errno = 0;
    const long value = std::strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 1 ||
        value > PING_MAX_COUNT) {
        return false;
    }
    count = static_cast<int>(value);
    return true;
}

/**
 * Pick the source address of the interface selected by the routing table.
 */
bool sourceFor(in_addr destination, in_addr& source) {
    RouteResult route{};
    if (!routingLookup(destination, route)) {
        return false;
    }
    const auto addresses = getDeviceAddresses(route.deviceId);
    if (addresses.empty()) {
        return false;
    }
    source = addresses[0].address;
    return true;
}

int sendEchoRequest(in_addr destination, uint16_t sequence) {
    in_addr source{};
    if (!sourceFor(destination, source)) {
        printf("PING no route to %s\n", ipToString(destination).c_str());
        return -1;
    }

    uint8_t message[16] = {};
    message[0] = ICMP_ECHO_REQUEST;
    writeU16(message + 4, ping.identifier);
    writeU16(message + 6, sequence);
    const char payload[] = "lab2ping";
    std::memcpy(message + 8, payload, sizeof(payload) - 1);
    const int length = 8 + int(sizeof(payload) - 1);
    writeU16(message + 2, checksum16(message, size_t(length)));

    if (sendIPPacket(source, destination, 1, message, length) < 0) {
        printf("PING send failed seq=%u\n", sequence);
        return -1;
    }
    printf("PING request seq=%u dst=%s src=%s\n", sequence,
           ipToString(destination).c_str(), ipToString(source).c_str());
    return 0;
}

int onIpPacket(const void* buffer, int len) {
    // The IP layer has validated the header and trimmed Ethernet padding.
    const auto* packet = static_cast<const uint8_t*>(buffer);
    const int ihl = (packet[0] & 0x0f) * 4;
    if (packet[9] != 1) {
        return 0; // Not ICMP.
    }
    const int icmpLen = len - ihl;
    if (icmpLen < 8) {
        return 0;
    }
    const uint8_t* icmp = packet + ihl;
    if (checksum16(icmp, size_t(icmpLen)) != 0) {
        return 0;
    }

    in_addr source{};
    in_addr destination{};
    std::memcpy(&source, packet + 12, sizeof(source));
    std::memcpy(&destination, packet + 16, sizeof(destination));

    if (icmp[0] == ICMP_ECHO_REQUEST) {
        std::vector<uint8_t> reply(icmp, icmp + icmpLen);
        reply[0] = ICMP_ECHO_REPLY;
        reply[1] = 0;
        writeU16(reply.data() + 2, 0);
        writeU16(reply.data() + 2, checksum16(reply.data(), reply.size()));
        const int result = sendIPPacket(destination, source, 1, reply.data(),
                                        int(reply.size()));
        printf("ICMP request from %s id=%u seq=%u reply=%s\n",
               ipToString(source).c_str(), readU16(icmp + 4),
               readU16(icmp + 6), result == 0 ? "sent" : "failed");
        return 0;
    }

    if (icmp[0] != ICMP_ECHO_REPLY) {
        return 0;
    }
    const uint16_t identifier = readU16(icmp + 4);
    const uint16_t sequence = readU16(icmp + 6);
    if (!ping.active || !ping.waiting || identifier != ping.identifier ||
        sequence != ping.sequence) {
        return 0;
    }

    const auto now = std::chrono::steady_clock().now();
    const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - ping.sentAt)
                         .count();
    ++ping.received;
    ping.waiting = false;
    ping.deadline = now;
    printf("PING reply from %s seq=%u time=%lld ms\n",
           ipToString(source).c_str(), sequence, static_cast<long long>(rtt));
    return 0;
}

void startPing(in_addr destination, int count) {
    if (ping.active) {
        printf("PING already running\n");
        return;
    }
    in_addr source{};
    if (!sourceFor(destination, source)) {
        printf("PING no route to %s\n", ipToString(destination).c_str());
        return;
    }

    ping.active = true;
    ping.destination = destination;
    ping.count = count;
    ping.sent = 0;
    ping.received = 0;
    ping.identifier = uint16_t(getpid() & 0xffff);
    ping.sequence = 0;
    ping.waiting = false;
    ping.deadline = std::chrono::steady_clock().now();
    printf("PING start dst=%s count=%d\n", ipToString(destination).c_str(),
           count);
}

void drivePing(TimePoint now) {
    if (!ping.active) {
        return;
    }
    if (ping.waiting && now >= ping.deadline) {
        printf("PING timeout seq=%u\n", ping.sequence);
        ping.waiting = false;
    }
    if (ping.waiting) {
        return;
    }
    if (ping.sent >= ping.count) {
        const int lost = ping.sent - ping.received;
        const int loss = lost * 100 / ping.sent;
        printf("PING summary transmitted=%d received=%d loss=%d%%\n",
               ping.sent, ping.received, loss);
        ping.active = false;
        return;
    }

    ping.sequence = uint16_t(ping.sent);
    if (sendEchoRequest(ping.destination, ping.sequence) < 0) {
        printf("PING aborted\n");
        ping.active = false;
        return;
    }
    ++ping.sent;
    ping.waiting = true;
    ping.sentAt = now;
    ping.deadline = now + std::chrono::milliseconds(PING_TIMEOUT_MS);
}

void printDistances() {
    const auto distances = linkStateDistances();
    if (distances.empty()) {
        printf("DISTANCES none\n");
        return;
    }
    for (const auto& [address, distance] : distances) {
        printf("DISTANCES router=%s distance=%d\n",
               ipToString(address).c_str(), distance);
    }
}

void printLookup(in_addr address) {
    printf("LOOKUP %s\n", ipToString(address).c_str());
    for (const auto& entry : routingEntries()) {
        if ((address.s_addr & entry.mask.s_addr) != entry.network.s_addr) {
            continue;
        }
        printf("LOOKUP candidate prefix=%s/%d kind=%s metric=%d dev=%s\n",
               ipToString(entry.network).c_str(), entry.prefixLength,
               kindName(entry.kind), entry.metric,
               deviceName(entry.deviceId).c_str());
    }

    RouteResult result{};
    if (!routingLookup(address, result)) {
        printf("LOOKUP selected none\n");
        return;
    }
    if (result.kind == RouteKind::Static) {
        printf("LOOKUP selected prefix=%s/%d kind=%s metric=%d dev=%s "
               "nextMac=%s\n",
               ipToString(result.network).c_str(), result.prefixLength,
               kindName(result.kind), result.metric,
               deviceName(result.deviceId).c_str(),
               macToString(result.nextHopMac).c_str());
    } else {
        printf("LOOKUP selected prefix=%s/%d kind=%s metric=%d dev=%s "
               "nextIp=%s\n",
               ipToString(result.network).c_str(), result.prefixLength,
               kindName(result.kind), result.metric,
               deviceName(result.deviceId).c_str(),
               ipToString(result.nextHopIp).c_str());
    }
}

void printCommandHelp() {
    printf("commands: ping IP [COUNT] | distances | lookup IP | "
           "setroute DEST MASK MAC DEV | quit\n");
}

void handleCommand(const std::string& line) {
    std::vector<std::string> words;
    size_t index = 0;
    while (index < line.size()) {
        while (index < line.size() &&
               std::isspace(static_cast<unsigned char>(line[index])) != 0) {
            ++index;
        }
        const size_t begin = index;
        while (index < line.size() &&
               std::isspace(static_cast<unsigned char>(line[index])) == 0) {
            ++index;
        }
        if (index > begin) {
            words.push_back(line.substr(begin, index - begin));
        }
    }
    if (words.empty()) {
        return;
    }
    printf("CMD %s\n", line.c_str());

    const std::string& command = words[0];
    if (command == "quit" && words.size() == 1) {
        printf("BYE\n");
        stopReceiveLoop();
        return;
    }
    if (command == "distances" && words.size() == 1) {
        printDistances();
        return;
    }
    if (command == "lookup" && words.size() == 2) {
        in_addr address{};
        if (!parseIp(words[1].c_str(), address)) {
            printf("lookup: invalid address\n");
            return;
        }
        printLookup(address);
        return;
    }
    if (command == "ping" && words.size() >= 2 && words.size() <= 3) {
        in_addr destination{};
        if (!parseIp(words[1].c_str(), destination)) {
            printf("ping: invalid address\n");
            return;
        }
        int count = PING_DEFAULT_COUNT;
        if (words.size() == 3 && !parseCount(words[2].c_str(), count)) {
            printf("ping: invalid count\n");
            return;
        }
        startPing(destination, count);
        return;
    }
    if (command == "setroute" && words.size() == 5) {
        in_addr destination{};
        in_addr mask{};
        macaddr_t mac{};
        if (!parseIp(words[1].c_str(), destination) ||
            !parseIp(words[2].c_str(), mask) ||
            !parseMac(words[3].c_str(), mac)) {
            printf("setroute: invalid arguments\n");
            return;
        }
        if (setRoutingTable(destination, mask, mac.data(),
                            words[4].c_str()) < 0) {
            printf("setroute: failed\n");
            return;
        }
        printf("STATIC dest=%s mask=%s mac=%s dev=%s\n",
               ipToString(destination).c_str(), ipToString(mask).c_str(),
               macToString(mac).c_str(), words[4].c_str());
        return;
    }

    printf("unknown command: %s\n", line.c_str());
    printCommandHelp();
}

void readCommands() {
    if (!stdinOpen) {
        return;
    }
    pollfd descriptor{STDIN_FILENO, POLLIN, 0};
    const int result = poll(&descriptor, 1, 0);
    if (result < 0) {
        if (errno != EINTR) {
            stdinOpen = false;
        }
        return;
    }
    if (result == 0) {
        return;
    }
    if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
        stdinOpen = false;
        return;
    }

    char buffer[256];
    const ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (count <= 0) {
        if (count == 0 || (errno != EINTR && errno != EAGAIN)) {
            stdinOpen = false;
        }
        return;
    }
    inputBuffer.append(buffer, size_t(count));
    size_t position = 0;
    while ((position = inputBuffer.find('\n')) != std::string::npos) {
        const std::string line = inputBuffer.substr(0, position);
        inputBuffer.erase(0, position + 1);
        handleCommand(line);
    }
}

void demoTick() {
    readCommands();
    drivePing(std::chrono::steady_clock().now());
}

void printDevices() {
    for (int deviceId : getActiveDeviceIds()) {
        const auto mac = getMac(deviceId);
        printf("DEVICE id=%d name=%s mac=%s", deviceId,
               deviceName(deviceId).c_str(),
               mac.has_value() ? macToString(*mac).c_str() : "?");
        for (const auto& address : getDeviceAddresses(deviceId)) {
            printf(" addr=%s/%s", ipToString(address.address).c_str(),
                   ipToString(address.netmask).c_str());
        }
        printf("\n");
    }
}

} // namespace

int main() {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (netstackInit() < 0) {
        fprintf(stderr, "netstack initialization failed\n");
        return 1;
    }
    setIPPacketReceiveCallback(onIpPacket);
    netstackSetAppTick(demoTick);
    printDevices();
    printf("READY ");
    printCommandHelp();
    return netstackRun() == 0 ? 0 : 1;
}
