#include "socket.h"

#include "device.h"
#include "ip.h"
#include "netstack.h"

#include <arpa/inet.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>

extern "C" {
ssize_t __real_read(int fildes, void* buf, size_t nbyte);
ssize_t __real_write(int fildes, const void* buf, size_t nbyte);
int __real_close(int fildes);
ssize_t __real_send(int socket, const void* buf, size_t len, int flags);
ssize_t __real_recv(int socket, void* buf, size_t len, int flags);
ssize_t __real_sendto(int socket, const void* buf, size_t len, int flags,
                      const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t __real_recvfrom(int socket, void* buf, size_t len, int flags,
                        struct sockaddr* src_addr, socklen_t* addrlen);
}

namespace {

constexpr int FIRST_STACK_FD = 10000;
constexpr int CONNECT_TIMEOUT_MS = 15000;
constexpr int ROUTE_WAIT_MS = 5000;

std::map<int, int> fdToConnection;
int nextFd = FIRST_STACK_FD;
bool stackReady = false;

bool isStackFd(int fd) {
    return fdToConnection.find(fd) != fdToConnection.end();
}

int connectionFor(int fd) {
    auto it = fdToConnection.find(fd);
    return it == fdToConnection.end() ? -1 : it->second;
}

int allocFd(int conn) {
    const int fd = nextFd++;
    fdToConnection[fd] = conn;
    return fd;
}

bool ensureStack() {
    if (stackReady) {
        return true;
    }
    if (netstackInit() < 0) {
        errno = ENETDOWN;
        return false;
    }
    tcpInit();
    setIPPacketReceiveCallback(tcpReceivePacket);
    stackReady = true;
    return true;
}

bool isLocalAddressValue(in_addr address) {
    if (address.s_addr == htonl(INADDR_ANY)) {
        return true;
    }
    for (int deviceId : getActiveDeviceIds()) {
        for (const auto& entry : getDeviceAddresses(deviceId)) {
            if (entry.address.s_addr == address.s_addr) {
                return true;
            }
        }
    }
    return false;
}

} // namespace

int __wrap_socket(int domain, int type, int protocol) {
    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    int baseType = type;
#ifdef SOCK_NONBLOCK
    baseType &= ~SOCK_NONBLOCK;
#endif
#ifdef SOCK_CLOEXEC
    baseType &= ~SOCK_CLOEXEC;
#endif
    if (baseType != SOCK_STREAM) {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    if (!ensureStack()) {
        return -1;
    }
    const int conn = tcpOpen();
    if (conn < 0) {
        errno = ENOMEM;
        return -1;
    }
    return allocFd(conn);
}

int __wrap_bind(int socket, const struct sockaddr* address,
                socklen_t address_len) {
    const int conn = connectionFor(socket);
    if (conn < 0) {
        errno = EBADF;
        return -1;
    }
    if (address == nullptr || address_len < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }
    const auto* name = reinterpret_cast<const struct sockaddr_in*>(address);
    if (name->sin_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    if (!isLocalAddressValue(name->sin_addr)) {
        errno = EADDRNOTAVAIL;
        return -1;
    }
    return tcpBind(conn, name->sin_addr, ntohs(name->sin_port));
}

int __wrap_listen(int socket, int backlog) {
    const int conn = connectionFor(socket);
    if (conn < 0) {
        errno = EBADF;
        return -1;
    }
    return tcpListen(conn, backlog);
}

int __wrap_connect(int socket, const struct sockaddr* address,
                   socklen_t address_len) {
    const int conn = connectionFor(socket);
    if (conn < 0) {
        errno = EBADF;
        return -1;
    }
    if (address == nullptr || address_len < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }
    const auto* name = reinterpret_cast<const struct sockaddr_in*>(address);
    if (name->sin_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    // Link-state routes appear a few ticks after the stack starts. A client
    // process may call connect() before its own topology has converged.
    const auto routeDeadline = std::chrono::steady_clock().now() +
                               std::chrono::milliseconds(ROUTE_WAIT_MS);
    while (tcpConnect(conn, name->sin_addr, ntohs(name->sin_port)) < 0) {
        if (errno != ENETUNREACH ||
            std::chrono::steady_clock().now() >= routeDeadline) {
            return -1;
        }
        netstackPump(10);
    }

    const auto deadline = std::chrono::steady_clock().now() +
                          std::chrono::milliseconds(CONNECT_TIMEOUT_MS);
    while (tcpState(conn) == TcpState::SynSent ||
           tcpState(conn) == TcpState::SynReceived) {
        if (tcpError(conn) != 0 ||
            std::chrono::steady_clock().now() >= deadline) {
            break;
        }
        netstackPump(10);
    }
    if (tcpState(conn) == TcpState::Established) {
        return 0;
    }
    if (tcpError(conn) != 0) {
        errno = tcpError(conn);
    } else {
        errno = ETIMEDOUT;
    }
    return -1;
}

int __wrap_accept(int socket, struct sockaddr* address,
                  socklen_t* address_len) {
    const int listener = connectionFor(socket);
    if (listener < 0) {
        errno = EBADF;
        return -1;
    }
    if (address != nullptr && address_len == nullptr) {
        errno = EINVAL;
        return -1;
    }

    int child = -1;
    while (true) {
        child = tcpAccept(listener);
        if (child >= 0) {
            break;
        }
        if (errno != EAGAIN) {
            return -1;
        }
        netstackPump(10);
    }

    if (address != nullptr) {
        auto* name = reinterpret_cast<struct sockaddr_in*>(address);
        std::memset(name, 0, sizeof(*name));
        name->sin_family = AF_INET;
        name->sin_port = htons(tcpPeerPort(child));
        name->sin_addr = tcpPeerAddress(child);
        *address_len = sizeof(struct sockaddr_in);
    }
    return allocFd(child);
}

ssize_t __wrap_read(int fildes, void* buf, size_t nbyte) {
    const int conn = connectionFor(fildes);
    if (conn < 0) {
        return __real_read(fildes, buf, nbyte);
    }
    while (true) {
        const ssize_t count = tcpRead(conn, buf, nbyte);
        if (count >= 0) {
            return count;
        }
        if (errno != EAGAIN) {
            return -1;
        }
        netstackPump(10);
    }
}

ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte) {
    const int conn = connectionFor(fildes);
    if (conn < 0) {
        return __real_write(fildes, buf, nbyte);
    }
    size_t done = 0;
    const auto* bytes = static_cast<const uint8_t*>(buf);
    while (done < nbyte) {
        const ssize_t count = tcpWrite(conn, bytes + done, nbyte - done);
        if (count < 0) {
            return done > 0 ? ssize_t(done) : -1;
        }
        if (count == 0) {
            netstackPump(10);
            continue;
        }
        done += size_t(count);
    }
    return ssize_t(done);
}

int __wrap_close(int fildes) {
    const int conn = connectionFor(fildes);
    if (conn < 0) {
        return __real_close(fildes);
    }
    if (tcpState(conn) == TcpState::Closed) {
        tcpRelease(conn);
    } else {
        tcpClose(conn);
    }
    fdToConnection.erase(fildes);
    return 0;
}

int __wrap_getaddrinfo(const char* node, const char* service,
                       const struct addrinfo* hints, struct addrinfo** res) {
    if (res == nullptr) {
        return EAI_FAIL;
    }
    *res = nullptr;
    if (hints != nullptr) {
        if (hints->ai_family != AF_INET && hints->ai_family != AF_UNSPEC) {
            return EAI_FAMILY;
        }
        if (hints->ai_socktype != 0 && hints->ai_socktype != SOCK_STREAM) {
            return EAI_SOCKTYPE;
        }
        if (hints->ai_protocol != 0 && hints->ai_protocol != IPPROTO_TCP) {
            return EAI_SOCKTYPE;
        }
        if (hints->ai_flags != 0) {
            return EAI_BADFLAGS;
        }
    }

    in_addr address{};
    address.s_addr = htonl(INADDR_ANY);
    if (node != nullptr && *node != '\0' &&
        inet_pton(AF_INET, node, &address) != 1) {
        return EAI_NONAME;
    }

    uint16_t port = 0;
    if (service != nullptr && *service != '\0') {
        char* end = nullptr;
        errno = 0;
        const long value = std::strtol(service, &end, 10);
        if (errno != 0 || end == service || *end != '\0' || value < 0 ||
            value > 65535) {
            return EAI_SERVICE;
        }
        port = htons(uint16_t(value));
    }

    auto* result = static_cast<struct addrinfo*>(
        std::calloc(1, sizeof(struct addrinfo)));
    auto* name = static_cast<struct sockaddr_in*>(
        std::calloc(1, sizeof(struct sockaddr_in)));
    if (result == nullptr || name == nullptr) {
        std::free(result);
        std::free(name);
        return EAI_MEMORY;
    }
    name->sin_family = AF_INET;
    name->sin_port = port;
    name->sin_addr = address;

    result->ai_family = AF_INET;
    result->ai_socktype = SOCK_STREAM;
    result->ai_protocol = IPPROTO_TCP;
    result->ai_addrlen = sizeof(struct sockaddr_in);
    result->ai_addr = reinterpret_cast<struct sockaddr*>(name);
    *res = result;
    return 0;
}

ssize_t __wrap_send(int socket, const void* buf, size_t len, int flags) {
    if (!isStackFd(socket)) {
        return __real_send(socket, buf, len, flags);
    }
    if ((flags & ~MSG_NOSIGNAL) != 0) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return __wrap_write(socket, buf, len);
}

ssize_t __wrap_recv(int socket, void* buf, size_t len, int flags) {
    if (!isStackFd(socket)) {
        return __real_recv(socket, buf, len, flags);
    }
    if ((flags & ~MSG_NOSIGNAL) != 0) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return __wrap_read(socket, buf, len);
}

ssize_t __wrap_sendto(int socket, const void* buf, size_t len, int flags,
                      const struct sockaddr* dest_addr, socklen_t addrlen) {
    if (!isStackFd(socket)) {
        return __real_sendto(socket, buf, len, flags, dest_addr, addrlen);
    }
    (void)dest_addr;
    (void)addrlen;
    return __wrap_send(socket, buf, len, flags);
}

ssize_t __wrap_recvfrom(int socket, void* buf, size_t len, int flags,
                        struct sockaddr* src_addr, socklen_t* addrlen) {
    if (!isStackFd(socket)) {
        return __real_recvfrom(socket, buf, len, flags, src_addr, addrlen);
    }
    if (src_addr != nullptr) {
        if (addrlen == nullptr) {
            errno = EINVAL;
            return -1;
        }
        const int conn = connectionFor(socket);
        auto* name = reinterpret_cast<struct sockaddr_in*>(src_addr);
        std::memset(name, 0, sizeof(*name));
        name->sin_family = AF_INET;
        name->sin_port = htons(tcpPeerPort(conn));
        name->sin_addr = tcpPeerAddress(conn);
        *addrlen = sizeof(struct sockaddr_in);
    }
    return __wrap_recv(socket, buf, len, flags);
}

bool tcpGetSocketCongestionInfo(int fd, TcpCongestionInfo& info) {
    const int conn = connectionFor(fd);
    return conn >= 0 && tcpGetCongestionInfo(conn, info);
}
