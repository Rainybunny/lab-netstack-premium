/**
 * @file http_proxy.cpp
 * @brief CL8 HTTP proxy: real socket toward the browser, user-space stack
 * toward the origin server.
 *
 * Usage: http_proxy LISTEN_PORT ORIGIN_IP ORIGIN_PORT
 *
 * The browser-facing listener uses the kernel loopback interface so an
 * unmodified browser can reach the proxy. Origin requests go through the
 * user-space TCP stack.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
int __real_socket(int domain, int type, int protocol);
int __real_bind(int socket, const struct sockaddr* address,
                socklen_t address_len);
int __real_listen(int socket, int backlog);
int __real_accept(int socket, struct sockaddr* address,
                  socklen_t* address_len);
ssize_t __real_read(int fildes, void* buf, size_t nbyte);
ssize_t __real_write(int fildes, const void* buf, size_t nbyte);
int __real_close(int fildes);
}

namespace {

const char BAD_GATEWAY[] =
    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
    "Connection: close\r\n\r\n";

bool writeAll(int fd, const void* buffer, size_t length, bool real) {
    size_t done = 0;
    const auto* bytes = static_cast<const uint8_t*>(buffer);
    while (done < length) {
        const ssize_t count =
            real ? __real_write(fd, bytes + done, length - done)
                 : write(fd, bytes + done, length - done);
        if (count <= 0) {
            return false;
        }
        done += size_t(count);
    }
    return true;
}

bool readRequest(int fd, std::string& request) {
    request.clear();
    char buffer[1024];
    while (request.size() < 16384) {
        const ssize_t count = __real_read(fd, buffer, sizeof(buffer));
        if (count <= 0) {
            return false;
        }
        request.append(buffer, size_t(count));
        if (request.find("\r\n\r\n") != std::string::npos) {
            return true;
        }
    }
    return true;
}

bool parseUrl(const std::string& url, std::string& host, uint16_t& port,
              std::string& path, uint16_t defaultPort) {
    const std::string prefix = "http://";
    if (url.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const std::string rest = url.substr(prefix.size());
    const size_t slash = rest.find('/');
    const std::string authority = rest.substr(0, slash);
    path = slash == std::string::npos ? "/" : rest.substr(slash);
    const size_t colon = authority.find(':');
    host = authority.substr(0, colon);
    port = defaultPort;
    if (colon != std::string::npos) {
        port = uint16_t(std::atoi(authority.substr(colon + 1).c_str()));
    }
    return !host.empty() && port != 0;
}

} // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc != 4) {
        fprintf(stderr, "usage: %s LISTEN_PORT ORIGIN_IP ORIGIN_PORT\n",
                argv[0]);
        return 1;
    }
    const int listenPort = std::atoi(argv[1]);
    const int originPort = std::atoi(argv[3]);

    const int listener = __real_socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("real socket");
        return 1;
    }
    sockaddr_in listenAddress{};
    listenAddress.sin_family = AF_INET;
    listenAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddress.sin_port = htons(uint16_t(listenPort));
    if (__real_bind(listener, reinterpret_cast<sockaddr*>(&listenAddress),
                    sizeof(listenAddress)) < 0 ||
        __real_listen(listener, 4) < 0) {
        perror("real bind/listen");
        return 1;
    }
    printf("PROXY listening on 127.0.0.1:%d\n", listenPort);

    for (int connection = 0; connection < 4; ++connection) {
        const int client = __real_accept(listener, nullptr, nullptr);
        if (client < 0) {
            perror("real accept");
            return 1;
        }
        std::string request;
        if (!readRequest(client, request)) {
            __real_close(client);
            continue;
        }

        const size_t lineEnd = request.find("\r\n");
        const std::string line = request.substr(0, lineEnd);
        const size_t firstSpace = line.find(' ');
        const size_t secondSpace =
            firstSpace == std::string::npos
                ? std::string::npos
                : line.find(' ', firstSpace + 1);
        if (firstSpace == std::string::npos ||
            secondSpace == std::string::npos) {
            writeAll(client, BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1, true);
            __real_close(client);
            continue;
        }
        const std::string method = line.substr(0, firstSpace);
        const std::string url =
            line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        std::string host;
        std::string path;
        uint16_t port = 0;
        in_addr originAddress{};
        if (!parseUrl(url, host, port, path, uint16_t(originPort)) ||
            inet_pton(AF_INET, host.c_str(), &originAddress) != 1) {
            writeAll(client, BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1, true);
            __real_close(client);
            continue;
        }

        const int origin = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in originName{};
        originName.sin_family = AF_INET;
        originName.sin_addr = originAddress;
        originName.sin_port = htons(port);
        if (origin < 0 ||
            connect(origin, reinterpret_cast<sockaddr*>(&originName),
                    sizeof(originName)) < 0) {
            perror("origin connect");
            writeAll(client, BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1, true);
            if (origin >= 0) {
                close(origin);
            }
            __real_close(client);
            continue;
        }

        const std::string outgoing = method + " " + path + " HTTP/1.1\r\n" +
                                     "Host: " + host + "\r\n" +
                                     "Connection: close\r\n\r\n";
        if (!writeAll(origin, outgoing.data(), outgoing.size(), false)) {
            writeAll(client, BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1, true);
            close(origin);
            __real_close(client);
            continue;
        }

        uint64_t forwarded = 0;
        char buffer[4096];
        while (true) {
            const ssize_t count = read(origin, buffer, sizeof(buffer));
            if (count <= 0) {
                break;
            }
            if (!writeAll(client, buffer, size_t(count), true)) {
                break;
            }
            forwarded += uint64_t(count);
        }
        printf("PROXY %s %s forwarded=%llu\n", method.c_str(), url.c_str(),
               static_cast<unsigned long long>(forwarded));
        close(origin);
        __real_close(client);
    }
    __real_close(listener);
    return 0;
}
