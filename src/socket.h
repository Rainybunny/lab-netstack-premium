/**
 * @file socket.h
 * @brief POSIX-compatible socket library supporting TCP on IPv4.
 *
 * The functions are linked into applications with the GNU ld --wrap option.
 * File descriptors owned by this library start at a high value and are
 * disjoint from the descriptors allocated by the C library.
 */

#pragma once

#include "tcp.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int __wrap_socket(int domain, int type, int protocol);

int __wrap_bind(int socket, const struct sockaddr* address,
                socklen_t address_len);

int __wrap_listen(int socket, int backlog);

int __wrap_connect(int socket, const struct sockaddr* address,
                   socklen_t address_len);

int __wrap_accept(int socket, struct sockaddr* address,
                  socklen_t* address_len);

ssize_t __wrap_read(int fildes, void* buf, size_t nbyte);

ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte);

int __wrap_close(int fildes);

int __wrap_getaddrinfo(const char* node, const char* service,
                       const struct addrinfo* hints, struct addrinfo** res);

ssize_t __wrap_send(int socket, const void* buf, size_t len, int flags);

ssize_t __wrap_recv(int socket, void* buf, size_t len, int flags);

ssize_t __wrap_sendto(int socket, const void* buf, size_t len, int flags,
                      const struct sockaddr* dest_addr, socklen_t addrlen);

ssize_t __wrap_recvfrom(int socket, void* buf, size_t len, int flags,
                        struct sockaddr* src_addr, socklen_t* addrlen);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/**
 * Fill @p info with congestion-control state of the stack socket @p fd.
 *
 * This is an evaluation helper, not part of POSIX.
 *
 * @return true on success, false if @p fd is not a stack socket.
 */
bool tcpGetSocketCongestionInfo(int fd, TcpCongestionInfo& info);
#endif
