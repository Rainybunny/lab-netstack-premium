/**
 * @file lab1_demo.cpp
 * @brief CP1/CP2 interface discovery, Ethernet capture and injection demo.
 */

#include "packetio.h"

#include <charconv>
#include <climits>
#include <cstdio>
#include <cstring>
#include <map>
#include <string_view>

static constexpr int demoType = 0x88b5;
static std::map<int, std::string> receiveDevices;
static std::map<int, int> receiveCounts;
static int targetCount = 0;
static int receivedCount = 0;
static bool receiveFailed = false;

static void printMac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool parseNumber(const char* text, int& value, int min, int max) {
    const char* end = text + strlen(text);
    auto result = std::from_chars(text, end, value);
    return result.ec == std::errc() && result.ptr == end && value >= min && value <= max;
}

static bool parseMac(std::string_view text, macaddr_t& mac) {
    if (text.size() != 17) {
        return false;
    }
    for (size_t i = 0; i < mac.size(); ++i) {
        unsigned value = 0;
        const char* begin = text.data() + i * 3;
        auto result = std::from_chars(begin, begin + 2, value, 16);
        if (result.ec != std::errc() || result.ptr != begin + 2 ||
            (i != 5 && text[i * 3 + 2] != ':')) {
            return false;
        }
        mac[i] = static_cast<uint8_t>(value);
    }
    return true;
}

static int openDevice(const char* name) {
    int id = addDevice(name);
    if (id < 0) {
        return -1;
    }
    auto mac = getMac(id);
    if (!mac) {
        fprintf(stderr, "No Ethernet MAC for %s\n", name);
        return -1;
    }
    printf("DEVICE name=%s id=%d mac=", name, id);
    printMac(mac->data());
    printf("\n");
    return id;
}

/**
 * Decode and validate demo frames. Other traffic does not count toward CP2.
 * The payload contains LAB1, sequence (32-bit), length (16-bit), and a pattern.
 */
static int receiveFrame(const void* buffer, int len, int id) {
    const auto* frame = static_cast<const uint8_t*>(buffer);
    if (len < 18 || frame[12] != (demoType >> 8) ||
        frame[13] != (demoType & 0xff) || memcmp(frame + 14, "LAB1", 4) != 0) {
        return 0;
    }
    bool valid = len >= 24;
    uint32_t sequence = 0;
    uint16_t payloadLen = 0;
    if (valid) {
        memcpy(&sequence, frame + 18, sizeof(sequence));
        memcpy(&payloadLen, frame + 22, sizeof(payloadLen));
        sequence = ntohl(sequence);
        payloadLen = ntohs(payloadLen);
        valid = payloadLen >= 10 && payloadLen <= 1500 &&
                len == (payloadLen < 46 ? 60 : payloadLen + 14);
        for (int i = 10; valid && i < payloadLen; ++i) {
            valid = frame[14 + i] == static_cast<uint8_t>(i + sequence);
        }
        for (int i = 14 + payloadLen; valid && i < len; ++i) {
            valid = frame[i] == 0;
        }
    }
    auto localMac = getMac(id);
    valid = valid && localMac && memcmp(frame, localMac->data(), localMac->size()) == 0;
    printf("RX device=%s id=%d bytes=%d dst=", receiveDevices.at(id).c_str(), id, len);
    printMac(frame);
    printf(" src=");
    printMac(frame + 6);
    printf(" type=0x%04x sequence=%u payload=%u check=%s\n",
           demoType, sequence, payloadLen, valid ? "PASS" : "FAIL");
    printf("HEX");
    for (int i = 0; i < len && i < 64; ++i) {
        printf(" %02x", frame[i]);
    }
    printf("%s\n", len > 64 ? " ..." : "");
    ++receivedCount;
    ++receiveCounts[id];
    if (!valid) {
        receiveFailed = true;
    }
    if (!valid || receivedCount >= targetCount) {
        stopReceiveLoop();
    }
    return valid ? 0 : -1;
}

static int sendDemo(int id, const macaddr_t& destination, int count, int length) {
    std::vector<uint8_t> payload(length);
    for (int sequence = 1; sequence <= count; ++sequence) {
        memcpy(payload.data(), "LAB1", 4);
        uint32_t networkSequence = htonl(sequence);
        uint16_t networkLength = htons(length);
        memcpy(payload.data() + 4, &networkSequence, 4);
        memcpy(payload.data() + 8, &networkLength, 2);
        for (int i = 10; i < length; ++i) {
            payload[i] = static_cast<uint8_t>(i + sequence);
        }
        if (sendFrame(payload.data(), length, demoType, destination.data(), id) != 0) {
            fprintf(stderr, "Injection failed at sequence %d\n", sequence);
            return 1;
        }
        printf("TX id=%d dst=", id);
        printMac(destination.data());
        printf(" type=0x%04x sequence=%d payload=%d bytes=%d injected\n",
               demoType, sequence, length, length < 46 ? 60 : length + 14);
    }
    return 0;
}

/**
 * Exercise rejected inputs without transmitting frames onto the interface.
 */
static int checkBoundaries(const char* name) {
    int failures = 0;
    auto check = [&](const char* label, bool passed) {
        printf("%s %s\n", passed ? "PASS" : "FAIL", label);
        failures += !passed;
    };
    check("missing callback", runReceiveLoop() == -1);
    setFrameReceiveCallback(receiveFrame);
    check("no devices", runReceiveLoop() == -1);
    setFrameReceiveCallback(nullptr);
    check("unknown device lookup", findDevice("lab1-not-present") == -1);
    check("null device name", addDevice(nullptr) == -1);
    int id = openDevice(name);
    if (id < 0) {
        return 1;
    }
    check("duplicate add keeps ID", addDevice(name) == id);
    check("find added device", findDevice(name) == id);
    auto names = getDeviceNames();
    initAllDevices();
    check("repeated initialization", getDeviceNames() == names && findDevice(name) == id);
    check("unknown device add", addDevice("lab1-not-present") == -1);
    check("non-Ethernet device", addDevice("lo") == -1);
    macaddr_t destination{};
    uint8_t byte = 0;
    check("negative length", sendFrame(&byte, -1, demoType, destination.data(), id) == -1);
    check("1501-byte payload", sendFrame(&byte, 1501, demoType, destination.data(), id) == -1);
    check("oversize length", sendFrame(&byte, ETH_BUFFER_LEN, demoType, destination.data(), id) == -1);
    check("INT_MAX length", sendFrame(&byte, INT_MAX, demoType, destination.data(), id) == -1);
    check("null payload", sendFrame(nullptr, 1, demoType, destination.data(), id) == -1);
    check("null destination", sendFrame(&byte, 1, demoType, nullptr, id) == -1);
    check("invalid ID", sendFrame(&byte, 1, demoType, destination.data(), -1) == -1);
    check("802.3 length rejected", sendFrame(&byte, 1, 1500, destination.data(), id) == -1);
    check("invalid EtherType", sendFrame(&byte, 1, 0x10000, destination.data(), id) == -1);
    return failures == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        printf("Usage:\n  %s list\n  %s send INTERFACE DEST_MAC COUNT PAYLOAD_BYTES\n"
               "  %s recv COUNT INTERFACE [INTERFACE ...]\n  %s check INTERFACE\n"
               "COUNT: 1..100000; PAYLOAD_BYTES: 10..1500.\n"
               "recv stops after COUNT demo frames; use an external timeout if needed.\n",
               argv[0], argv[0], argv[0], argv[0]);
        return argc < 2 ? 2 : 0;
    }
    const std::string_view command = argv[1];
    int count = 0, length = 0;
    macaddr_t destination{};
    if (!((command == "list" && argc == 2) || (command == "check" && argc == 3) ||
          (command == "recv" && argc >= 4 && parseNumber(argv[2], count, 1, 100000)) ||
          (command == "send" && argc == 6 && parseMac(argv[3], destination) &&
           parseNumber(argv[4], count, 1, 100000) && parseNumber(argv[5], length, 10, 1500)))) {
        fprintf(stderr, "Invalid arguments; use --help.\n");
        return 2;
    }
    initAllDevices();
    if (command == "list") {
        auto names = getDeviceNames();
        printf("CP1 discovered %zu capture interfaces (not all support Ethernet injection):\n", names.size());
        for (const auto& name : names) {
            printf("INTERFACE %s\n", name.c_str());
        }
        return names.empty() ? 1 : 0;
    }
    if (command == "check") {
        return checkBoundaries(argv[2]);
    }
    if (command == "send") {
        int id = openDevice(argv[2]);
        return id < 0 ? 1 : sendDemo(id, destination, count, length);
    }
    targetCount = count;
    for (int i = 3; i < argc; ++i) {
        int id = openDevice(argv[i]);
        if (id < 0) {
            return 1;
        }
        receiveDevices[id] = argv[i];
    }
    setFrameReceiveCallback(receiveFrame);
    printf("READY interfaces=%zu target=%d\n", receiveDevices.size(), targetCount);
    int result = runReceiveLoop();
    for (const auto& [id, name] : receiveDevices) {
        printf("SUMMARY device=%s id=%d frames=%d\n", name.c_str(), id, receiveCounts[id]);
    }
    return result == 0 && !receiveFailed && receivedCount == targetCount ? 0 : 1;
}
