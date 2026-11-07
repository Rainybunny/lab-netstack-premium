/**
 * @file tcp.h
 * @brief TCP transport (RFC 793) used by the POSIX socket layer.
 *
 * A connection is identified by an integer handle. The socket layer maps
 * fake file descriptors to these handles and drives the blocking calls by
 * pumping the stack with netstackPump(). All state is owned by the single
 * receive-loop thread.
 */

#pragma once

#include "utils.h"

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

constexpr size_t TCP_SEND_CAPACITY = 256 * 1024;
constexpr size_t TCP_RECV_CAPACITY = 65535;
constexpr uint16_t TCP_LOCAL_MSS = 1460;
constexpr uint16_t TCP_DEFAULT_MSS = 536;
constexpr int TCP_TIME_WAIT_MS = 8000;

enum class TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
};

enum class TcpCongestionControl {
    Reno,
    Bbr,
};

/**
 * Snapshot of congestion-control state, used by the evaluation programs.
 */
struct TcpCongestionInfo {
    TcpCongestionControl algorithm;
    uint64_t cwnd;
    uint64_t ssthresh;
    uint64_t bytesInFlight;
    uint32_t srttMs;
    uint32_t rtoMs;
    uint32_t minRttMs;
    uint32_t pacingRate;
    int mode;
};

/**
 * Compute the TCP checksum over a segment using the IPv4 pseudo-header.
 *
 * @param src Source IPv4 address, as stored in the IPv4 header.
 * @param dst Destination IPv4 address.
 * @param segment Complete TCP segment (header and payload).
 * @param len Segment length.
 * @return Checksum in host byte order. A valid received segment yields zero.
 */
uint16_t tcpChecksum(in_addr src, in_addr dst, const void* segment, size_t len);

/**
 * Signed sequence-number comparison: true when @p a precedes @p b modulo
 * 2^32.
 */
inline bool tcpSeqLess(uint32_t a, uint32_t b) {
    return int32_t(a - b) < 0;
}

/**
 * Clear all transport state.
 */
void tcpInit();

/**
 * Read the congestion-control algorithm from NETSTACK_CC (reno or bbr).
 */
void tcpInitCongestionControl();

/**
 * Process an IPv4 packet delivered by the IP layer.
 *
 * @return 0 on success or when the packet is ignored, -1 on error.
 */
int tcpReceivePacket(const void* packet, int len);

/**
 * Drive SYN, retransmission, TIME-WAIT and congestion-control timers.
 */
void tcpTick(TimePoint now);

/**
 * Allocate an unbound connection handle.
 * @return A non-negative handle, or -1 on error.
 */
int tcpOpen();

/**
 * Bind a connection handle to a local address and port.
 *
 * @param port Local port in host byte order, or 0 to allocate an ephemeral
 * port.
 * @return 0 on success, -1 with errno set on error.
 */
int tcpBind(int conn, in_addr address, uint16_t port);

/**
 * Turn a bound connection into a listener.
 *
 * @param backlog Maximum number of completed connections waiting for
 * accept().
 * @return 0 on success, -1 with errno set on error.
 */
int tcpListen(int conn, int backlog);

/**
 * Start an active open. The caller pumps until the state changes.
 *
 * @return 0 if the SYN was sent, -1 with errno set on error.
 */
int tcpConnect(int conn, in_addr remoteAddress, uint16_t remotePort);

/**
 * Return a completed connection from a listener's accept queue.
 *
 * @return A non-negative connection handle, or -1 with errno set (EAGAIN
 * when the queue is empty).
 */
int tcpAccept(int listener);

/**
 * Copy received bytes.
 *
 * @return Number of bytes copied (0 at end of stream), -1 with errno set
 * (EAGAIN when no data is available now).
 */
ssize_t tcpRead(int conn, void* buffer, size_t length);

/**
 * Copy bytes into the send buffer.
 *
 * @return Number of bytes accepted, 0 when the send buffer is full, or -1
 * with errno set.
 */
ssize_t tcpWrite(int conn, const void* buffer, size_t length);

/**
 * Close a connection, sending a FIN after queued data.
 */
void tcpClose(int conn);

/**
 * Release a closed connection handle. Used when the socket layer gives up
 * on a handle that never reached the wire (for example, a failed connect).
 */
void tcpRelease(int conn);

/**
 * Pending socket error (an errno value), or 0.
 */
int tcpError(int conn);

TcpState tcpState(int conn);
in_addr tcpLocalAddress(int conn);
uint16_t tcpLocalPort(int conn);
in_addr tcpPeerAddress(int conn);
uint16_t tcpPeerPort(int conn);

/**
 * Fill @p info with congestion-control state for @p conn.
 * @return true on success, false for an unknown handle.
 */
bool tcpGetCongestionInfo(int conn, TcpCongestionInfo& info);
