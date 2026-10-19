/**
 * @file lab1_demo.cpp
 * @brief CP1/CP2 interface discovery, Ethernet capture and injection demo.
 */

#include "packetio.h"

#include <charconv>
#include <climits>
#include <cstdio>
#include <string_view>

static constexpr int demo_type = 0x88b5;
static std::map<int, std::string> receive_devices;
static std::map<int, int> receive_counts;
static int target_count = 0;
static int received_count = 0;
static bool receive_failed = false;

static void print_mac(const u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool parse_number(const char* text, int& value, int min, int max) {
    const char* end = text + strlen(text);
    auto result = std::from_chars(text, end, value);
    return result.ec == std::errc() && result.ptr == end && value >= min && value <= max;
}

static bool parse_mac(std::string_view text, macaddr_t& mac) {
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
        mac[i] = static_cast<u_char>(value);
    }
    return true;
}

static int open_device(const char* name) {
    int id = add_device(name);
    if (id < 0) {
        return -1;
    }
    auto mac = get_mac(id);
    if (!mac) {
        fprintf(stderr, "No Ethernet MAC for %s\n", name);
        return -1;
    }
    printf("DEVICE name=%s id=%d mac=", name, id);
    print_mac(mac->data());
    printf("\n");
    return id;
}

/**
 * Decode and validate demo frames. Other traffic does not count toward CP2.
 * The payload contains LAB1, sequence (32-bit), length (16-bit), and a pattern.
 */
static int receive_frame(const void* buffer, int len, int id) {
    const auto* frame = static_cast<const u_char*>(buffer);
    if (len < 18 || frame[12] != (demo_type >> 8) ||
        frame[13] != (demo_type & 0xff) || memcmp(frame + 14, "LAB1", 4) != 0) {
        return 0;
    }
    bool valid = len >= 24;
    uint32_t sequence = 0;
    uint16_t payload_len = 0;
    if (valid) {
        memcpy(&sequence, frame + 18, sizeof(sequence));
        memcpy(&payload_len, frame + 22, sizeof(payload_len));
        sequence = ntohl(sequence);
        payload_len = ntohs(payload_len);
        valid = payload_len >= 10 && payload_len <= 1500 &&
                len == (payload_len < 46 ? 60 : payload_len + 14);
        for (int i = 10; valid && i < payload_len; ++i) {
            valid = frame[14 + i] == static_cast<u_char>(i + sequence);
        }
        for (int i = 14 + payload_len; valid && i < len; ++i) {
            valid = frame[i] == 0;
        }
    }
    auto local_mac = get_mac(id);
    valid = valid && local_mac && memcmp(frame, local_mac->data(), 6) == 0;
    printf("RX device=%s id=%d bytes=%d dst=", receive_devices.at(id).c_str(), id, len);
    print_mac(frame);
    printf(" src=");
    print_mac(frame + 6);
    printf(" type=0x%04x sequence=%u payload=%u check=%s\n",
           demo_type, sequence, payload_len, valid ? "PASS" : "FAIL");
    printf("HEX");
    for (int i = 0; i < len && i < 64; ++i) {
        printf(" %02x", frame[i]);
    }
    printf("%s\n", len > 64 ? " ..." : "");
    ++received_count;
    ++receive_counts[id];
    if (!valid) {
        receive_failed = true;
    }
    if (!valid || received_count >= target_count) {
        stop_receive_loop();
    }
    return valid ? 0 : -1;
}

static int send_demo(int id, const macaddr_t& destination, int count, int length) {
    std::vector<u_char> payload(length);
    for (int sequence = 1; sequence <= count; ++sequence) {
        memcpy(payload.data(), "LAB1", 4);
        uint32_t network_sequence = htonl(sequence);
        uint16_t network_length = htons(length);
        memcpy(payload.data() + 4, &network_sequence, 4);
        memcpy(payload.data() + 8, &network_length, 2);
        for (int i = 10; i < length; ++i) {
            payload[i] = static_cast<u_char>(i + sequence);
        }
        if (send_frame(payload.data(), length, demo_type, destination.data(), id) != 0) {
            fprintf(stderr, "Injection failed at sequence %d\n", sequence);
            return 1;
        }
        printf("TX id=%d dst=", id);
        print_mac(destination.data());
        printf(" type=0x%04x sequence=%d payload=%d bytes=%d injected\n",
               demo_type, sequence, length, length < 46 ? 60 : length + 14);
    }
    return 0;
}

/**
 * Exercise rejected inputs without transmitting frames onto the interface.
 */
static int check_boundaries(const char* name) {
    int failures = 0;
    auto check = [&](const char* label, bool passed) {
        printf("%s %s\n", passed ? "PASS" : "FAIL", label);
        failures += !passed;
    };
    check("missing callback", run_receive_loop() == -1);
    set_frame_receive_callback(receive_frame);
    check("no devices", run_receive_loop() == -1);
    set_frame_receive_callback(nullptr);
    check("unknown device lookup", find_device("lab1-not-present") == -1);
    check("null device name", add_device(nullptr) == -1);
    int id = open_device(name);
    if (id < 0) {
        return 1;
    }
    check("duplicate add keeps ID", add_device(name) == id);
    check("find added device", find_device(name) == id);
    auto names = get_device_names();
    init_all_devices();
    check("repeated initialization", get_device_names() == names && find_device(name) == id);
    check("unknown device add", add_device("lab1-not-present") == -1);
    check("non-Ethernet device", add_device("lo") == -1);
    macaddr_t destination{};
    u_char byte = 0;
    check("negative length", send_frame(&byte, -1, demo_type, destination.data(), id) == -1);
    check("1501-byte payload", send_frame(&byte, 1501, demo_type, destination.data(), id) == -1);
    check("oversize length", send_frame(&byte, ETH_BUFFER_LEN, demo_type, destination.data(), id) == -1);
    check("INT_MAX length", send_frame(&byte, INT_MAX, demo_type, destination.data(), id) == -1);
    check("null payload", send_frame(nullptr, 1, demo_type, destination.data(), id) == -1);
    check("null destination", send_frame(&byte, 1, demo_type, nullptr, id) == -1);
    check("invalid ID", send_frame(&byte, 1, demo_type, destination.data(), -1) == -1);
    check("802.3 length rejected", send_frame(&byte, 1, 1500, destination.data(), id) == -1);
    check("invalid EtherType", send_frame(&byte, 1, 0x10000, destination.data(), id) == -1);
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
          (command == "recv" && argc >= 4 && parse_number(argv[2], count, 1, 100000)) ||
          (command == "send" && argc == 6 && parse_mac(argv[3], destination) &&
           parse_number(argv[4], count, 1, 100000) && parse_number(argv[5], length, 10, 1500)))) {
        fprintf(stderr, "Invalid arguments; use --help.\n");
        return 2;
    }
    init_all_devices();
    if (command == "list") {
        auto names = get_device_names();
        printf("CP1 discovered %zu capture interfaces (not all support Ethernet injection):\n", names.size());
        for (const auto& name : names) {
            printf("INTERFACE %s\n", name.c_str());
        }
        return names.empty() ? 1 : 0;
    }
    if (command == "check") {
        return check_boundaries(argv[2]);
    }
    if (command == "send") {
        int id = open_device(argv[2]);
        return id < 0 ? 1 : send_demo(id, destination, count, length);
    }
    target_count = count;
    for (int i = 3; i < argc; ++i) {
        int id = open_device(argv[i]);
        if (id < 0) {
            return 1;
        }
        receive_devices[id] = argv[i];
    }
    set_frame_receive_callback(receive_frame);
    printf("READY interfaces=%zu target=%d\n", receive_devices.size(), target_count);
    int result = run_receive_loop();
    for (const auto& [id, name] : receive_devices) {
        printf("SUMMARY device=%s id=%d frames=%d\n", name.c_str(), id, receive_counts[id]);
    }
    return result == 0 && !receive_failed && received_count == target_count ? 0 : 1;
}
