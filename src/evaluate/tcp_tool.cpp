/**
 * @file tcp_tool.cpp
 * @brief Evaluation application using only the POSIX socket interface.
 *
 * Modes:
 *   sink PORT COUNT SECONDS [slow]
 *       Accept COUNT connections, count received bytes per peer, and print a
 *       sample every second. "slow" reads 1024 bytes, then pumps the stack
 *       for 20 ms without reading, so the receive window closes.
 *   source IP PORT BYTES
 *       Connect, send BYTES of a deterministic pattern, then wait until the
 *       send buffer is empty and close.
 *   echoserver PORT
 *       Accept one connection, read a 4-byte length and that many bytes, and
 *       echo the payload.
 *   echoclient IP PORT BYTES
 *       Send a length-prefixed pattern, read the echo, and verify it.
 *   simopen LOCAL_IP LOCAL_PORT PEER_IP PEER_PORT OPEN_MS CLOSE_MS
 *       Bind a fixed port, connect at OPEN_MS, exchange a byte, close at
 *       CLOSE_MS, then keep pumping so both close state machines run.
 */

#include "netstack.h"
#include "socket.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr int BUFFER_SIZE = 65536;

std::string ipText(in_addr address) {
    char buffer[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &address, buffer, sizeof(buffer));
    return buffer;
}

bool makeAddress(const char* ip, const char* port, sockaddr_in& address) {
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        return false;
    }
    const int value = std::atoi(port);
    if (value <= 0 || value > 65535) {
        return false;
    }
    address.sin_port = htons(uint16_t(value));
    return true;
}

ssize_t readExact(int fd, void* buffer, size_t length) {
    size_t done = 0;
    auto* bytes = static_cast<uint8_t*>(buffer);
    while (done < length) {
        const ssize_t count = read(fd, bytes + done, length - done);
        if (count <= 0) {
            return done == 0 ? count : ssize_t(done);
        }
        done += size_t(count);
    }
    return ssize_t(done);
}

ssize_t writeAll(int fd, const void* buffer, size_t length) {
    size_t done = 0;
    const auto* bytes = static_cast<const uint8_t*>(buffer);
    while (done < length) {
        const ssize_t count = write(fd, bytes + done, length - done);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return done == 0 ? -1 : ssize_t(done);
        }
        if (count == 0) {
            return done == 0 ? -1 : ssize_t(done);
        }
        done += size_t(count);
    }
    return ssize_t(done);
}

void fillPattern(std::vector<uint8_t>& buffer) {
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = uint8_t('a' + i % 26);
    }
}

int runSink(int port, int count, int seconds, bool slow) {
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(uint16_t(port));
    if (bind(listener, reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) < 0 ||
        listen(listener, count) < 0) {
        perror("bind/listen");
        return 1;
    }

    struct Flow {
        int fd;
        std::string peer;
        uint64_t bytes;
        bool closed;
    };
    std::vector<Flow> flows;
    for (int i = 0; i < count; ++i) {
        sockaddr_in peer{};
        socklen_t peerLength = sizeof(peer);
        const int fd = accept(listener, reinterpret_cast<sockaddr*>(&peer),
                              &peerLength);
        if (fd < 0) {
            perror("accept");
            return 1;
        }
        flows.push_back({fd, ipText(peer.sin_addr) + ":" +
                                std::to_string(ntohs(peer.sin_port)),
                         0, false});
        printf("ACCEPT %s\n", flows.back().peer.c_str());
        fflush(stdout);
    }

    std::vector<uint8_t> buffer(BUFFER_SIZE);
    const auto start = std::chrono::steady_clock().now();
    auto lastPrint = start;
    while (true) {
        const auto now = std::chrono::steady_clock().now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - start)
                .count() >= seconds) {
            break;
        }
        netstackPump(1);

        for (auto& flow : flows) {
            if (flow.closed) {
                continue;
            }
            const size_t request = slow ? 1024 : BUFFER_SIZE;
            const ssize_t countRead =
                recv(flow.fd, buffer.data(), request, MSG_DONTWAIT);
            if (countRead > 0) {
                flow.bytes += uint64_t(countRead);
                if (slow) {
                    const auto until = std::chrono::steady_clock().now() +
                                       std::chrono::milliseconds(20);
                    while (std::chrono::steady_clock().now() < until) {
                        netstackPump(5);
                    }
                }
            } else if (countRead == 0) {
                flow.closed = true;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                flow.closed = true;
            }
        }

        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastPrint)
                .count() >= 1000) {
            lastPrint = now;
            for (const auto& flow : flows) {
                printf("FLOW %s %llu\n", flow.peer.c_str(),
                       static_cast<unsigned long long>(flow.bytes));
            }
            fflush(stdout);
        }
    }

    for (auto& flow : flows) {
        printf("TOTAL %s %llu\n", flow.peer.c_str(),
               static_cast<unsigned long long>(flow.bytes));
        close(flow.fd);
    }
    close(listener);
    return 0;
}

int runSource(const char* ip, int port, uint64_t total) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in address{};
    if (!makeAddress(ip, std::to_string(port).c_str(), address)) {
        fprintf(stderr, "invalid address\n");
        return 1;
    }
    if (connect(fd, reinterpret_cast<sockaddr*>(&address),
                sizeof(address)) < 0) {
        perror("connect");
        return 1;
    }

    std::vector<uint8_t> buffer(BUFFER_SIZE);
    fillPattern(buffer);
    uint64_t sent = 0;
    auto lastPrint = std::chrono::steady_clock().now();
    while (sent < total) {
        const size_t chunk =
            size_t(std::min<uint64_t>(buffer.size(), total - sent));
        const ssize_t count = write(fd, buffer.data(), chunk);
        if (count <= 0) {
            perror("write");
            return 1;
        }
        sent += uint64_t(count);
        const auto now = std::chrono::steady_clock().now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastPrint)
                .count() >= 1000) {
            lastPrint = now;
            TcpCongestionInfo info{};
            tcpGetSocketCongestionInfo(fd, info);
            printf("PROGRESS sent=%llu queued=%llu inflight=%llu\n",
                   static_cast<unsigned long long>(sent),
                   static_cast<unsigned long long>(info.bytesQueued),
                   static_cast<unsigned long long>(info.bytesInFlight));
            fflush(stdout);
        }
    }

    // Let the tail reach the wire before close() sends the FIN.
    for (int attempt = 0; attempt < 3000; ++attempt) {
        TcpCongestionInfo info{};
        if (!tcpGetSocketCongestionInfo(fd, info)) {
            break;
        }
        if (info.bytesQueued == 0 && info.bytesInFlight == 0) {
            break;
        }
        netstackPump(10);
    }
    TcpCongestionInfo info{};
    tcpGetSocketCongestionInfo(fd, info);
    printf("SENT %llu queued=%llu inflight=%llu\n",
           static_cast<unsigned long long>(sent),
           static_cast<unsigned long long>(info.bytesQueued),
           static_cast<unsigned long long>(info.bytesInFlight));
    close(fd);
    return 0;
}

int runEchoServer(int port) {
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(uint16_t(port));
    if (bind(listener, reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) < 0 ||
        listen(listener, 1) < 0) {
        perror("bind/listen");
        return 1;
    }
    const int fd = accept(listener, nullptr, nullptr);
    if (fd < 0) {
        perror("accept");
        return 1;
    }

    uint32_t length = 0;
    if (readExact(fd, &length, sizeof(length)) != ssize_t(sizeof(length))) {
        fprintf(stderr, "short length\n");
        return 1;
    }
    length = ntohl(length);
    std::vector<uint8_t> buffer(length);
    if (readExact(fd, buffer.data(), buffer.size()) != ssize_t(buffer.size())) {
        fprintf(stderr, "short payload\n");
        return 1;
    }
    if (writeAll(fd, buffer.data(), buffer.size()) != ssize_t(buffer.size())) {
        fprintf(stderr, "short echo\n");
        return 1;
    }
    printf("ECHO %u\n", length);
    close(fd);
    close(listener);
    return 0;
}

int64_t epochMilliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void waitUntil(int64_t epochMs) {
    while (epochMilliseconds() < epochMs) {
        netstackPump(10);
    }
}

int runSimultaneous(const char* localIp, int localPort, const char* peerIp,
                    int peerPort, int64_t openMs, int64_t closeMs) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in local{};
    if (!makeAddress(localIp, std::to_string(localPort).c_str(), local)) {
        fprintf(stderr, "invalid local address\n");
        return 1;
    }
    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        perror("bind");
        return 1;
    }
    sockaddr_in peer{};
    if (!makeAddress(peerIp, std::to_string(peerPort).c_str(), peer)) {
        fprintf(stderr, "invalid peer address\n");
        return 1;
    }

    waitUntil(openMs);
    printf("CONNECTING at %lld\n",
           static_cast<long long>(epochMilliseconds()));
    if (connect(fd, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) < 0) {
        perror("connect");
        return 1;
    }
    printf("OPENED at %lld\n", static_cast<long long>(epochMilliseconds()));

    const char message[] = "hello";
    if (writeAll(fd, message, sizeof(message) - 1) != ssize_t(sizeof(message) - 1)) {
        fprintf(stderr, "write failed\n");
        return 1;
    }
    char received[sizeof(message) - 1] = {};
    if (readExact(fd, received, sizeof(received)) != ssize_t(sizeof(received)) ||
        std::memcmp(received, message, sizeof(received)) != 0) {
        fprintf(stderr, "exchange failed\n");
        return 1;
    }
    printf("EXCHANGED at %lld\n", static_cast<long long>(epochMilliseconds()));

    waitUntil(closeMs);
    printf("CLOSING at %lld\n", static_cast<long long>(epochMilliseconds()));
    close(fd);
    // The socket descriptor is gone, but the TCB keeps running in the timer
    // tick. Pump long enough for the FIN handshake to reach TIME_WAIT.
    const int64_t until = epochMilliseconds() + 5000;
    while (epochMilliseconds() < until) {
        netstackPump(10);
    }
    printf("CLOSED at %lld\n", static_cast<long long>(epochMilliseconds()));
    return 0;
}

int runEchoClient(const char* ip, int port, uint32_t length) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in address{};
    if (!makeAddress(ip, std::to_string(port).c_str(), address)) {
        fprintf(stderr, "invalid address\n");
        return 1;
    }
    if (connect(fd, reinterpret_cast<sockaddr*>(&address),
                sizeof(address)) < 0) {
        perror("connect");
        return 1;
    }

    std::vector<uint8_t> sent(length);
    fillPattern(sent);
    const uint32_t networkLength = htonl(length);
    const auto start = std::chrono::steady_clock().now();
    if (writeAll(fd, &networkLength, sizeof(networkLength)) !=
            ssize_t(sizeof(networkLength)) ||
        writeAll(fd, sent.data(), sent.size()) != ssize_t(sent.size())) {
        perror("write");
        return 1;
    }

    std::vector<uint8_t> received(length);
    if (readExact(fd, received.data(), received.size()) !=
        ssize_t(received.size())) {
        fprintf(stderr, "short echo\n");
        return 1;
    }
    if (std::memcmp(sent.data(), received.data(), sent.size()) != 0) {
        for (size_t i = 0; i < sent.size(); ++i) {
            if (sent[i] != received[i]) {
                printf("MISMATCH at %zu: %u != %u\n", i, sent[i], received[i]);
                break;
            }
        }
        return 1;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock().now() - start)
                             .count();
    printf("VERIFIED %u bytes in %lld ms\n", length,
           static_cast<long long>(elapsed));
    close(fd);
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s sink|source|echoserver|echoclient ...\n",
                argv[0]);
        return 1;
    }
    const std::string mode = argv[1];
    if (mode == "sink" && (argc == 5 || argc == 6)) {
        const bool slow = argc == 6 && std::strcmp(argv[5], "slow") == 0;
        return runSink(std::atoi(argv[2]), std::atoi(argv[3]),
                       std::atoi(argv[4]), slow);
    }
    if (mode == "source" && argc == 5) {
        return runSource(argv[2], std::atoi(argv[3]),
                         std::strtoull(argv[4], nullptr, 10));
    }
    if (mode == "echoserver" && argc == 3) {
        return runEchoServer(std::atoi(argv[2]));
    }
    if (mode == "echoclient" && argc == 5) {
        return runEchoClient(argv[2], std::atoi(argv[3]),
                             uint32_t(std::strtoul(argv[4], nullptr, 10)));
    }
    if (mode == "simopen" && argc == 8) {
        return runSimultaneous(
            argv[2], std::atoi(argv[3]), argv[4], std::atoi(argv[5]),
            std::strtoll(argv[6], nullptr, 10),
            std::strtoll(argv[7], nullptr, 10));
    }
    fprintf(stderr, "invalid arguments\n");
    return 1;
}
