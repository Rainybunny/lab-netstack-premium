#include "tcp.h"

#include "device.h"
#include "ip.h"
#include "routing.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <strings.h>
#include <vector>
#include <unistd.h>

namespace {

constexpr uint8_t TH_FIN = 0x01;
constexpr uint8_t TH_SYN = 0x02;
constexpr uint8_t TH_RST = 0x04;
constexpr uint8_t TH_ACK = 0x10;
constexpr size_t TCP_HEADER_LEN = 20;
constexpr size_t TCP_MAX_SEGMENT = TCP_HEADER_LEN + 4 + TCP_LOCAL_MSS;

constexpr uint32_t TCP_INITIAL_CWND = 10 * TCP_LOCAL_MSS;
constexpr uint32_t TCP_MAX_CWND = 1 << 20;
constexpr int TCP_INITIAL_RTO_MS = 1000;
constexpr int TCP_MIN_RTO_MS = 200;
constexpr int TCP_MAX_RTO_MS = 6000;
constexpr int TCP_MAX_RETRIES = 8;
constexpr int TCP_SYN_RETRIES = 3;
constexpr int TCP_CC_LOG_INTERVAL_MS = 100;
constexpr int TCP_BBR_BW_SAMPLE_MS = 100;
constexpr int TCP_BBR_MIN_RTT_WINDOW_MS = 10000;
constexpr int TCP_BBR_PROBE_RTT_MS = 200;

constexpr int CC_SLOW_START = 0;
constexpr int CC_CONGESTION_AVOIDANCE = 1;
constexpr int CC_FAST_RECOVERY = 2;

constexpr int BBR_STARTUP = 0;
constexpr int BBR_DRAIN = 1;
constexpr int BBR_PROBE_BW = 2;
constexpr int BBR_PROBE_RTT = 3;

struct BbrState {
    uint64_t delivered = 0;
    uint64_t deliveredAtSample = 0;
    TimePoint sampleTime;
    double btlbw = 0; ///< bytes per second
    uint32_t minRttMs = UINT32_MAX;
    TimePoint minRttTime;
    int mode = BBR_STARTUP;
    TimePoint modeStart;
    double lastBtlBw = 0;
    int steadyRounds = 0;
    int cycleIndex = 0;
    TimePoint probeRttTime;
    TimePoint probeRttStart;
    uint32_t priorCwnd = 0;
    double pacingGain = 2.885;
    double cwndGain = 2.885;
    double pacingTokens = 0;
    TimePoint pacingTime;
};

struct TcpConn {
    int id = 0;
    int parent = -1;
    bool isChild = false;
    TcpState state = TcpState::Closed;

    in_addr localAddress{};
    in_addr remoteAddress{};
    uint16_t localPort = 0;
    uint16_t remotePort = 0;

    uint32_t iss = 0;
    uint32_t sndUna = 0;
    uint32_t sndNxt = 0;
    uint32_t sndWnd = 0;
    uint16_t peerMss = TCP_DEFAULT_MSS;
    bool synSent = false;
    bool synAcked = false;
    int synRetries = 0;
    TimePoint synSentAt;

    std::vector<uint8_t> sendBuf;
    bool finQueued = false;
    bool finSent = false;
    bool finAcked = false;
    uint32_t finSeq = 0;

    uint32_t rcvNxt = 0;
    std::vector<uint8_t> recvBuf;
    std::map<uint32_t, std::vector<uint8_t>> outOfOrder;
    size_t outOfOrderBytes = 0;
    bool peerFinQueued = false;
    uint32_t peerFinSeq = 0;
    bool finReceived = false;

    uint32_t srttMs = 0;
    uint32_t rttvarMs = 0;
    uint32_t rtoMs = TCP_INITIAL_RTO_MS;
    bool rttPending = false;
    TimePoint rttStart;
    bool retransmitted = false;
    bool timerRunning = false;
    TimePoint timerStart;
    int retries = 0;
    uint8_t dupAcks = 0;

    bool probePending = false;
    TimePoint probeStart;

    TcpCongestionControl cc = TcpCongestionControl::Reno;
    uint32_t cwnd = TCP_INITIAL_CWND;
    uint32_t ssthresh = 65535;
    int ccState = CC_SLOW_START;
    uint32_t recover = 0;
    BbrState bbr;

    uint16_t lastAdvertised = 0;
    int error = 0;

    int backlog = 0;
    std::deque<int> acceptQueue;

    TimePoint timeWaitStart;
    TimePoint lastCcLog;
};

std::map<int, std::unique_ptr<TcpConn>> connections;
int nextHandle = 1;
uint32_t nextEphemeralPort = 49152;
bool logStates = false;
bool logCc = false;
TcpCongestionControl defaultCc = TcpCongestionControl::Reno;

const char* stateName(TcpState state) {
    switch (state) {
    case TcpState::Closed:
        return "CLOSED";
    case TcpState::Listen:
        return "LISTEN";
    case TcpState::SynSent:
        return "SYN_SENT";
    case TcpState::SynReceived:
        return "SYN_RECEIVED";
    case TcpState::Established:
        return "ESTABLISHED";
    case TcpState::FinWait1:
        return "FIN_WAIT_1";
    case TcpState::FinWait2:
        return "FIN_WAIT_2";
    case TcpState::Closing:
        return "CLOSING";
    case TcpState::TimeWait:
        return "TIME_WAIT";
    case TcpState::CloseWait:
        return "CLOSE_WAIT";
    case TcpState::LastAck:
        return "LAST_ACK";
    }
    return "?";
}

const char* addressText(in_addr address) {
    static char buffers[4][INET_ADDRSTRLEN];
    static int next = 0;
    char* buffer = buffers[next];
    next = (next + 1) % 4;
    return inet_ntop(AF_INET, &address, buffer, INET_ADDRSTRLEN);
}

void setState(TcpConn& conn, TcpState state, const char* reason) {
    if (conn.state == state) {
        return;
    }
    if (logStates) {
        fprintf(stderr, "TCP %s:%u -> %s:%u %s -> %s (%s)\n",
                addressText(conn.localAddress), conn.localPort,
                addressText(conn.remoteAddress), conn.remotePort,
                stateName(conn.state), stateName(state), reason);
    }
    conn.state = state;
}

uint32_t elapsedMs(TimePoint now, TimePoint start) {
    const auto value = std::chrono::duration_cast<std::chrono::milliseconds>(
                           now - start)
                           .count();
    return value < 0 ? 0 : uint32_t(value);
}

uint32_t generateIss() {
    static uint32_t state = 0;
    if (state == 0) {
        const auto ticks = std::chrono::steady_clock::now().time_since_epoch();
        state = uint32_t(
            std::chrono::duration_cast<std::chrono::microseconds>(ticks).count()) ^
            uint32_t(getpid() << 16);
    }
    state = state * 1664525u + 1013904223u;
    return state;
}

TcpConn* getConn(int id) {
    auto it = connections.find(id);
    return it == connections.end() ? nullptr : it->second.get();
}

uint16_t advertisedWindow(const TcpConn& conn) {
    const size_t used = conn.recvBuf.size() + conn.outOfOrderBytes;
    const size_t free = used >= TCP_RECV_CAPACITY ? 0 : TCP_RECV_CAPACITY - used;
    return uint16_t(std::min<size_t>(free, 65535));
}

void checksumAdd(uint32_t& sum, const uint8_t* data, size_t len) {
    size_t index = 0;
    for (; index + 1 < len; index += 2) {
        sum += (uint16_t(data[index]) << 8) | data[index + 1];
    }
    if (index < len) {
        sum += uint16_t(data[index]) << 8;
    }
}

int sendSegmentRaw(in_addr src, in_addr dst, uint16_t sport, uint16_t dport,
                   uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window,
                   const void* data, size_t len, bool withMss) {
    if (len > TCP_LOCAL_MSS) {
        return -1;
    }
    uint8_t segment[TCP_MAX_SEGMENT] = {};
    const size_t headerLen = TCP_HEADER_LEN + (withMss ? 4 : 0);
    writeU16(segment, sport);
    writeU16(segment + 2, dport);
    writeU32(segment + 4, seq);
    writeU32(segment + 8, ack);
    segment[12] = uint8_t(headerLen / 4) << 4;
    segment[13] = flags;
    writeU16(segment + 14, window);
    writeU16(segment + 16, 0); // checksum
    writeU16(segment + 18, 0); // urgent pointer
    if (withMss) {
        segment[20] = 2; // MSS option
        segment[21] = 4;
        writeU16(segment + 22, TCP_LOCAL_MSS);
    }
    if (len > 0) {
        std::memcpy(segment + headerLen, data, len);
    }
    const size_t total = headerLen + len;
    writeU16(segment + 16, tcpChecksum(src, dst, segment, total));
    return sendIPPacket(src, dst, IPPROTO_TCP, segment, int(total));
}

int sendSegment(TcpConn& conn, uint8_t flags, uint32_t seq, uint32_t ack,
                uint16_t window, const void* data, size_t len, bool withMss) {
    return sendSegmentRaw(conn.localAddress, conn.remoteAddress, conn.localPort,
                          conn.remotePort, seq, ack, flags, window, data, len,
                          withMss);
}

int sendSyn(TcpConn& conn) {
    return sendSegment(conn, TH_SYN, conn.iss, 0, advertisedWindow(conn),
                       nullptr, 0, true);
}

int sendSynAck(TcpConn& conn) {
    return sendSegment(conn, TH_SYN | TH_ACK, conn.iss, conn.rcvNxt,
                       advertisedWindow(conn), nullptr, 0, true);
}

int sendAck(TcpConn& conn) {
    uint8_t flags = TH_ACK;
    uint32_t seq = conn.sndNxt;
    if (conn.state == TcpState::SynReceived) {
        flags |= TH_SYN;
        seq = conn.iss;
    }
    conn.lastAdvertised = advertisedWindow(conn);
    return sendSegment(conn, flags, seq, conn.rcvNxt, conn.lastAdvertised,
                       nullptr, 0, false);
}

void sendReset(in_addr src, in_addr dst, uint16_t sport, uint16_t dport,
               uint32_t seq, uint32_t ack, bool ackValid) {
    if (ackValid) {
        sendSegmentRaw(src, dst, sport, dport, ack, 0, TH_RST, 0, nullptr, 0,
                       false);
    } else {
        sendSegmentRaw(src, dst, sport, dport, 0, seq, TH_RST | TH_ACK, 0,
                       nullptr, 0, false);
    }
}

uint16_t parseMss(const uint8_t* options, int len) {
    int index = 0;
    while (index < len) {
        const uint8_t kind = options[index];
        if (kind == 0) { // end of options
            break;
        }
        if (kind == 1) { // no-op
            ++index;
            continue;
        }
        if (index + 1 >= len) {
            break;
        }
        const uint8_t length = options[index + 1];
        if (length < 2 || index + length > len) {
            break;
        }
        if (kind == 2 && length == 4) {
            const uint16_t value = readU16(options + index + 2);
            return uint16_t(std::clamp<int>(value, 64, TCP_LOCAL_MSS));
        }
        index += length;
    }
    return TCP_DEFAULT_MSS;
}

void updateRtt(TcpConn& conn, uint32_t sampleMs) {
    sampleMs = std::max(sampleMs, 1u);
    if (conn.srttMs == 0) {
        conn.srttMs = sampleMs;
        conn.rttvarMs = sampleMs / 2;
    } else {
        const uint32_t delta = conn.srttMs > sampleMs
                                   ? conn.srttMs - sampleMs
                                   : sampleMs - conn.srttMs;
        conn.rttvarMs = (3 * conn.rttvarMs + delta) / 4;
        conn.srttMs = (7 * conn.srttMs + sampleMs) / 8;
    }
    const uint32_t base = conn.srttMs + std::max(4 * conn.rttvarMs, 10u);
    conn.rtoMs = std::clamp(base, uint32_t(TCP_MIN_RTO_MS),
                            uint32_t(TCP_MAX_RTO_MS));
}

void bbrSampleRtt(TcpConn& conn, uint32_t sampleMs, TimePoint now) {
    BbrState& bbr = conn.bbr;
    if (sampleMs < bbr.minRttMs ||
        elapsedMs(now, bbr.minRttTime) >= TCP_BBR_MIN_RTT_WINDOW_MS) {
        bbr.minRttMs = sampleMs;
        bbr.minRttTime = now;
    }
}

void congestionOnAck(TcpConn& conn, size_t ackedBytes, TimePoint now) {
    if (ackedBytes == 0) {
        return;
    }
    if (conn.cc == TcpCongestionControl::Bbr) {
        BbrState& bbr = conn.bbr;
        bbr.delivered += ackedBytes;

        const uint32_t sampleElapsed = elapsedMs(now, bbr.sampleTime);
        if (sampleElapsed >= uint32_t(TCP_BBR_BW_SAMPLE_MS)) {
            const double rate =
                double(bbr.delivered - bbr.deliveredAtSample) * 1000.0 /
                double(sampleElapsed);
            if (rate > bbr.btlbw) {
                bbr.btlbw = rate;
            }
            bbr.deliveredAtSample = bbr.delivered;
            bbr.sampleTime = now;
        }

        const uint32_t minRtt =
            bbr.minRttMs == UINT32_MAX ? 1000 : bbr.minRttMs;
        if (elapsedMs(now, bbr.modeStart) >= std::max(minRtt, 50u)) {
            bbr.modeStart = now;
            if (bbr.mode == BBR_STARTUP) {
                if (bbr.btlbw > 0 && bbr.btlbw < bbr.lastBtlBw * 1.25) {
                    if (++bbr.steadyRounds >= 3) {
                        bbr.mode = BBR_DRAIN;
                    }
                } else {
                    bbr.steadyRounds = 0;
                }
                bbr.lastBtlBw = bbr.btlbw;
            } else if (bbr.mode == BBR_DRAIN) {
                const double bdp = bbr.btlbw * minRtt / 1000.0;
                if (double(conn.sndNxt - conn.sndUna) <= bdp) {
                    bbr.mode = BBR_PROBE_BW;
                    bbr.cycleIndex = 0;
                }
            } else if (bbr.mode == BBR_PROBE_BW) {
                bbr.cycleIndex = (bbr.cycleIndex + 1) % 8;
                if (elapsedMs(now, bbr.probeRttTime) >=
                    TCP_BBR_MIN_RTT_WINDOW_MS) {
                    bbr.mode = BBR_PROBE_RTT;
                    bbr.probeRttStart = now;
                    bbr.priorCwnd = conn.cwnd;
                }
            }
        }
        if (bbr.mode == BBR_PROBE_RTT &&
            elapsedMs(now, bbr.probeRttStart) >= TCP_BBR_PROBE_RTT_MS) {
            bbr.mode = BBR_PROBE_BW;
            bbr.probeRttTime = now;
            bbr.cycleIndex = 0;
            conn.cwnd = std::max(bbr.priorCwnd, TCP_INITIAL_CWND);
        }

        switch (bbr.mode) {
        case BBR_STARTUP:
            bbr.pacingGain = 2.885;
            bbr.cwndGain = 2.885;
            break;
        case BBR_DRAIN:
            bbr.pacingGain = 1.0 / 2.885;
            bbr.cwndGain = 2.885;
            break;
        case BBR_PROBE_RTT:
            bbr.pacingGain = 1.0;
            bbr.cwndGain = 0.5;
            break;
        default: {
            static constexpr double gains[8] = {1.25, 0.75, 1, 1,
                                                1,    1,    1, 1};
            bbr.pacingGain = gains[bbr.cycleIndex % 8];
            bbr.cwndGain = 2.0;
            break;
        }
        }

        if (bbr.mode == BBR_PROBE_RTT) {
            conn.cwnd = 4 * TCP_LOCAL_MSS;
        } else if (bbr.btlbw > 0) {
            const double bdp = bbr.btlbw * minRtt / 1000.0;
            const double target = bbr.cwndGain * bdp;
            conn.cwnd = std::clamp<uint32_t>(
                uint32_t(target), 4 * TCP_LOCAL_MSS, TCP_MAX_CWND);
        } else {
            conn.cwnd = std::min<uint32_t>(
                conn.cwnd + uint32_t(ackedBytes), TCP_MAX_CWND);
        }
        conn.ssthresh = conn.cwnd;
        return;
    }

    if (conn.ccState == CC_FAST_RECOVERY) {
        if (!tcpSeqLess(conn.sndUna, conn.recover)) {
            conn.ccState = CC_CONGESTION_AVOIDANCE;
            conn.cwnd = conn.ssthresh;
        } else {
            conn.cwnd = conn.ssthresh + 3 * TCP_LOCAL_MSS;
        }
        return;
    }
    if (conn.cwnd < conn.ssthresh) {
        conn.cwnd += uint32_t(std::min<size_t>(ackedBytes, TCP_LOCAL_MSS));
    } else {
        conn.cwnd += std::max<uint32_t>(
            1, uint32_t(TCP_LOCAL_MSS) * TCP_LOCAL_MSS / conn.cwnd);
    }
    conn.cwnd = std::min(conn.cwnd, TCP_MAX_CWND);
}

void congestionOnTimeout(TcpConn& conn) {
    const uint32_t flight = conn.sndNxt - conn.sndUna;
    if (conn.cc == TcpCongestionControl::Bbr) {
        conn.cwnd = std::max<uint32_t>(4 * TCP_LOCAL_MSS, conn.cwnd / 2);
        conn.ssthresh = conn.cwnd;
        return;
    }
    conn.ssthresh = std::max<uint32_t>(flight / 2, 2 * TCP_LOCAL_MSS);
    conn.cwnd = TCP_LOCAL_MSS;
    conn.ccState = CC_SLOW_START;
    conn.dupAcks = 0;
}

void congestionOnFastRetransmit(TcpConn& conn) {
    if (conn.cc == TcpCongestionControl::Bbr) {
        return;
    }
    const uint32_t flight = conn.sndNxt - conn.sndUna;
    conn.ssthresh = std::max<uint32_t>(flight / 2, 2 * TCP_LOCAL_MSS);
    conn.cwnd = conn.ssthresh + 3 * TCP_LOCAL_MSS;
    conn.ccState = CC_FAST_RECOVERY;
    conn.recover = conn.sndNxt;
}

bool pacingAllows(TcpConn& conn, size_t bytes, TimePoint now) {
    BbrState& bbr = conn.bbr;
    double rate = bbr.pacingGain * bbr.btlbw;
    if (rate <= 0) {
        rate = double(TCP_INITIAL_CWND) * 10.0;
    }
    const double elapsed =
        std::chrono::duration<double>(now - bbr.pacingTime).count();
    bbr.pacingTokens =
        std::min(bbr.pacingTokens + rate * elapsed,
                 rate * 0.1 + double(TCP_LOCAL_MSS));
    bbr.pacingTime = now;
    if (bbr.pacingTokens < double(bytes)) {
        return false;
    }
    bbr.pacingTokens -= double(bytes);
    return true;
}

void outputData(TcpConn& conn, TimePoint now) {
    if (conn.state != TcpState::Established &&
        conn.state != TcpState::CloseWait &&
        conn.state != TcpState::FinWait1 &&
        conn.state != TcpState::LastAck) {
        return;
    }

    while (size_t(conn.sndNxt - conn.sndUna) < conn.sendBuf.size()) {
        const size_t flight = size_t(conn.sndNxt - conn.sndUna);
        const uint32_t limit = std::min<uint32_t>(conn.sndWnd, conn.cwnd);
        if (flight >= limit) {
            break;
        }
        size_t chunk = std::min<size_t>(conn.peerMss, conn.sendBuf.size() - flight);
        chunk = std::min<size_t>(chunk, size_t(limit - flight));
        if (chunk == 0) {
            break;
        }
        if (conn.cc == TcpCongestionControl::Bbr &&
            !pacingAllows(conn, chunk, now)) {
            break;
        }
        if (sendSegment(conn, TH_ACK, conn.sndNxt, conn.rcvNxt,
                        advertisedWindow(conn), conn.sendBuf.data() + flight,
                        chunk, false) < 0) {
            break;
        }
        if (!conn.timerRunning) {
            conn.timerRunning = true;
            conn.timerStart = now;
            conn.rttPending = true;
            conn.rttStart = now;
            conn.retransmitted = false;
        }
        conn.sndNxt += uint32_t(chunk);
    }

    if (conn.finQueued && !conn.finSent && conn.sndNxt == conn.finSeq) {
        const uint32_t flight = conn.sndNxt - conn.sndUna;
        const uint32_t limit = std::min<uint32_t>(conn.sndWnd, conn.cwnd);
        if (flight < limit) {
            if (sendSegment(conn, TH_FIN | TH_ACK, conn.finSeq, conn.rcvNxt,
                            advertisedWindow(conn), nullptr, 0, false) < 0) {
                return;
            }
            conn.finSent = true;
            conn.sndNxt = conn.finSeq + 1;
            if (conn.state == TcpState::Established) {
                setState(conn, TcpState::FinWait1, "close");
            } else if (conn.state == TcpState::CloseWait) {
                setState(conn, TcpState::LastAck, "close");
            }
            if (!conn.timerRunning) {
                conn.timerRunning = true;
                conn.timerStart = now;
                conn.rttPending = true;
                conn.rttStart = now;
                conn.retransmitted = false;
            }
        }
    }
}

void maybeFinishFin(TcpConn& conn, TimePoint now) {
    if (!conn.peerFinQueued || conn.finReceived ||
        conn.rcvNxt != conn.peerFinSeq) {
        return;
    }
    ++conn.rcvNxt;
    conn.finReceived = true;
    switch (conn.state) {
    case TcpState::Established:
    case TcpState::CloseWait:
        setState(conn, TcpState::CloseWait, "peer fin");
        break;
    case TcpState::FinWait1:
        setState(conn, TcpState::Closing, "peer fin");
        break;
    case TcpState::FinWait2:
        conn.timeWaitStart = now;
        setState(conn, TcpState::TimeWait, "peer fin");
        conn.timerRunning = false;
        break;
    case TcpState::TimeWait:
        conn.timeWaitStart = now;
        break;
    default:
        break;
    }
    sendAck(conn);
}

void receiveData(TcpConn& conn, uint32_t seq, const uint8_t* data, int len) {
    if (len <= 0) {
        return;
    }
    if (tcpSeqLess(seq, conn.rcvNxt)) {
        const int32_t skip = int32_t(conn.rcvNxt - seq);
        if (skip >= len) {
            return;
        }
        seq += uint32_t(skip);
        data += skip;
        len -= skip;
    }

    const int32_t offset = int32_t(seq - conn.rcvNxt);
    if (offset < 0) {
        return;
    }
    if (size_t(offset) >= TCP_RECV_CAPACITY) {
        return;
    }
    const size_t limit = TCP_RECV_CAPACITY - size_t(offset);
    if (size_t(len) > limit) {
        len = int(limit);
    }
    const size_t buffered = conn.recvBuf.size() + conn.outOfOrderBytes;
    if (buffered + size_t(len) > TCP_RECV_CAPACITY) {
        len = int(TCP_RECV_CAPACITY - buffered);
        if (len <= 0) {
            return;
        }
    }

    if (offset == 0) {
        conn.recvBuf.insert(conn.recvBuf.end(), data, data + len);
        conn.rcvNxt += uint32_t(len);
    } else {
        auto [entry, inserted] = conn.outOfOrder.try_emplace(seq);
        if (inserted) {
            entry->second.assign(data, data + len);
            conn.outOfOrderBytes += size_t(len);
        }
    }

    for (auto it = conn.outOfOrder.begin(); it != conn.outOfOrder.end();) {
        if (tcpSeqLess(it->first, conn.rcvNxt)) {
            const int32_t skip = int32_t(conn.rcvNxt - it->first);
            if (skip >= int32_t(it->second.size())) {
                conn.outOfOrderBytes -= it->second.size();
                it = conn.outOfOrder.erase(it);
            } else {
                conn.recvBuf.insert(conn.recvBuf.end(),
                                    it->second.begin() + skip,
                                    it->second.end());
                conn.rcvNxt += uint32_t(it->second.size() - size_t(skip));
                conn.outOfOrderBytes -= it->second.size();
                it = conn.outOfOrder.erase(it);
            }
        } else if (it->first == conn.rcvNxt) {
            conn.recvBuf.insert(conn.recvBuf.end(), it->second.begin(),
                                it->second.end());
            conn.rcvNxt += uint32_t(it->second.size());
            conn.outOfOrderBytes -= it->second.size();
            it = conn.outOfOrder.erase(it);
        } else {
            break;
        }
    }
}

void retransmit(TcpConn& conn) {
    if (conn.state == TcpState::SynSent) {
        sendSyn(conn);
        return;
    }
    if (conn.state == TcpState::SynReceived) {
        sendSynAck(conn);
        return;
    }
    const uint32_t flight = conn.sndNxt - conn.sndUna;
    size_t dataOutstanding = std::min<size_t>(flight, conn.sendBuf.size());
    if (dataOutstanding > 0) {
        size_t sent = 0;
        while (sent < dataOutstanding) {
            const size_t chunk =
                std::min<size_t>(conn.peerMss, dataOutstanding - sent);
            sendSegment(conn, TH_ACK, conn.sndUna + uint32_t(sent),
                        conn.rcvNxt, advertisedWindow(conn),
                        conn.sendBuf.data() + sent, chunk, false);
            sent += chunk;
        }
        conn.retransmitted = true;
        return;
    }
    if (conn.finSent && !conn.finAcked) {
        sendSegment(conn, TH_FIN | TH_ACK, conn.finSeq, conn.rcvNxt,
                    advertisedWindow(conn), nullptr, 0, false);
        conn.retransmitted = true;
    }
}

TcpConn* findConnection(in_addr local, uint16_t localPort, in_addr remote,
                        uint16_t remotePort) {
    for (auto& [id, conn] : connections) {
        if (conn->state == TcpState::Listen ||
            conn->state == TcpState::Closed) {
            continue;
        }
        if (conn->localPort != localPort || conn->remotePort != remotePort) {
            continue;
        }
        if (conn->localAddress.s_addr != 0 &&
            conn->localAddress.s_addr != local.s_addr) {
            continue;
        }
        if (conn->remoteAddress.s_addr != remote.s_addr) {
            continue;
        }
        return conn.get();
    }
    return nullptr;
}

TcpConn* findListener(in_addr local, uint16_t localPort) {
    for (auto& [id, conn] : connections) {
        if (conn->state != TcpState::Listen || conn->localPort != localPort) {
            continue;
        }
        if (conn->localAddress.s_addr != 0 &&
            conn->localAddress.s_addr != local.s_addr) {
            continue;
        }
        return conn.get();
    }
    return nullptr;
}

bool portInUse(uint16_t port) {
    for (const auto& [id, conn] : connections) {
        if (conn->isChild || conn->state == TcpState::Closed) {
            continue;
        }
        if (conn->localPort == port) {
            return true;
        }
    }
    return false;
}

uint16_t allocateEphemeralPort() {
    for (int attempt = 0; attempt < 16384; ++attempt) {
        const uint16_t port = uint16_t(nextEphemeralPort);
        nextEphemeralPort = nextEphemeralPort >= 65535 ? 49152
                                                       : nextEphemeralPort + 1;
        if (!portInUse(port)) {
            return port;
        }
    }
    return 0;
}

bool selectSource(in_addr remote, in_addr& source) {
    RouteResult route{};
    if (!routingLookup(remote, route)) {
        return false;
    }
    const auto addresses = getDeviceAddresses(route.deviceId);
    if (addresses.empty()) {
        return false;
    }
    source = addresses[0].address;
    return true;
}

std::unique_ptr<TcpConn> newConn() {
    auto conn = std::make_unique<TcpConn>();
    conn->id = nextHandle++;
    conn->cc = defaultCc;
    conn->cwnd = TCP_INITIAL_CWND;
    conn->ssthresh = 65535;
    const TimePoint now = std::chrono::steady_clock().now();
    conn->bbr.sampleTime = now;
    conn->bbr.minRttTime = now;
    conn->bbr.modeStart = now;
    conn->bbr.probeRttTime = now;
    conn->bbr.pacingTime = now;
    conn->bbr.pacingTokens = TCP_INITIAL_CWND;
    conn->lastCcLog = now;
    return conn;
}

TcpConn* createChild(TcpConn& listener, in_addr local, in_addr remote,
                     uint16_t remotePort, uint32_t seq, uint16_t window,
                     uint16_t mss, TimePoint now) {
    if (int(listener.acceptQueue.size()) >= std::max(listener.backlog, 1)) {
        return nullptr;
    }
    auto child = newConn();
    child->isChild = true;
    child->parent = listener.id;
    child->localAddress = local;
    child->localPort = listener.localPort;
    child->remoteAddress = remote;
    child->remotePort = remotePort;
    child->iss = generateIss();
    child->sndUna = child->iss;
    child->sndNxt = child->iss + 1;
    child->sndWnd = window;
    child->peerMss = mss;
    child->rcvNxt = seq + 1;
    child->synSent = true;
    child->synSentAt = now;
    child->state = TcpState::SynReceived;
    const int id = child->id;
    connections[id] = std::move(child);
    TcpConn& result = *connections[id];
    sendSynAck(result);
    if (logStates) {
        fprintf(stderr, "TCP %s:%u -> %s:%u LISTEN -> SYN_RECEIVED (child)\n",
                addressText(result.localAddress), result.localPort,
                addressText(result.remoteAddress), result.remotePort);
    }
    return &result;
}

void completeHandshake(TcpConn& conn, uint32_t ack, uint16_t window) {
    conn.sndUna = ack;
    conn.sndWnd = window;
    conn.synAcked = true;
    setState(conn, TcpState::Established, "handshake");
    conn.timerRunning = false;
    if (conn.parent >= 0) {
        TcpConn* parent = getConn(conn.parent);
        if (parent != nullptr && parent->state == TcpState::Listen) {
            parent->acceptQueue.push_back(conn.id);
        }
    }
}

void processSegment(TcpConn& conn, uint32_t seq, uint32_t ack, uint8_t flags,
                    uint16_t window, const uint8_t* payload, int payloadLen,
                    uint16_t mss, TimePoint now) {
    if (flags & TH_RST) {
        conn.error = (conn.state == TcpState::SynSent) ? ECONNREFUSED
                                                       : ECONNRESET;
        setState(conn, TcpState::Closed, "reset");
        return;
    }

    if (flags & TH_SYN) {
        if (conn.state == TcpState::SynSent) {
            conn.rcvNxt = seq + 1;
            conn.peerMss = mss;
            if (flags & TH_ACK) {
                if (ack != conn.iss + 1) {
                    return;
                }
                completeHandshake(conn, ack, window);
            } else {
                conn.sndWnd = window;
                setState(conn, TcpState::SynReceived, "simultaneous open");
                conn.synSentAt = now;
                conn.synRetries = 0;
                sendSynAck(conn);
            }
            return;
        }
        if (conn.state == TcpState::SynReceived) {
            if ((flags & TH_ACK) != 0 && ack == conn.iss + 1) {
                completeHandshake(conn, ack, window);
                sendAck(conn);
            } else {
                sendSynAck(conn);
            }
            return;
        }
        return;
    }

    if (flags & TH_ACK) {
        if (conn.state == TcpState::SynSent) {
            if (ack == conn.iss + 1) {
                completeHandshake(conn, ack, window);
            }
            return;
        }
        if (conn.state == TcpState::SynReceived) {
            if (ack == conn.iss + 1) {
                completeHandshake(conn, ack, window);
            } else {
                return;
            }
        } else {
            const int32_t diff = int32_t(ack - conn.sndUna);
            if (diff > 0 && int32_t(ack - conn.sndNxt) <= 0) {
                const uint32_t ackedTotal = ack - conn.sndUna;
                const size_t dataAcked =
                    std::min<size_t>(ackedTotal, conn.sendBuf.size());

                if (conn.rttPending && !conn.retransmitted) {
                    const uint32_t sample = std::max(1u, elapsedMs(now, conn.rttStart));
                    updateRtt(conn, sample);
                    if (conn.cc == TcpCongestionControl::Bbr) {
                        bbrSampleRtt(conn, sample, now);
                    }
                }
                conn.rttPending = false;
                conn.retransmitted = false;

                if (dataAcked > 0) {
                    conn.sendBuf.erase(conn.sendBuf.begin(),
                                       conn.sendBuf.begin() + dataAcked);
                }
                conn.sndUna = ack;
                conn.sndWnd = window;
                conn.dupAcks = 0;
                conn.retries = 0;
                if (conn.srttMs != 0) {
                    conn.rtoMs = std::clamp(
                        conn.srttMs + std::max(4 * conn.rttvarMs, 10u),
                        uint32_t(TCP_MIN_RTO_MS), uint32_t(TCP_MAX_RTO_MS));
                }

                congestionOnAck(conn, dataAcked, now);

                if (conn.finSent && !conn.finAcked &&
                    int32_t(ack - (conn.finSeq + 1)) >= 0) {
                    conn.finAcked = true;
                    if (conn.state == TcpState::FinWait1) {
                        setState(conn, TcpState::FinWait2, "fin acked");
                    } else if (conn.state == TcpState::Closing) {
                        conn.timeWaitStart = now;
                        setState(conn, TcpState::TimeWait, "fin acked");
                    } else if (conn.state == TcpState::LastAck) {
                        setState(conn, TcpState::Closed, "fin acked");
                    }
                }

                if (conn.sndUna == conn.sndNxt) {
                    conn.timerRunning = false;
                    conn.probePending = false;
                } else {
                    conn.timerRunning = true;
                    conn.timerStart = now;
                    conn.rttPending = true;
                    conn.rttStart = now;
                }
            } else if (ack == conn.sndUna && payloadLen == 0 &&
                       (flags & (TH_SYN | TH_FIN)) == 0 &&
                       conn.sndUna != conn.sndNxt) {
                // A pure window update is not a duplicate ACK (RFC 793
                // SND.WL1/SND.WL2).
                if (window == conn.sndWnd) {
                    if (++conn.dupAcks == 3) {
                        congestionOnFastRetransmit(conn);
                        retransmit(conn);
                    }
                } else {
                    conn.dupAcks = 0;
                }
                conn.sndWnd = window;
            } else {
                conn.sndWnd = window;
            }
        }
    }

    if (payloadLen > 0) {
        if (conn.state == TcpState::Established ||
            conn.state == TcpState::CloseWait ||
            conn.state == TcpState::FinWait1 ||
            conn.state == TcpState::FinWait2) {
            receiveData(conn, seq, payload, payloadLen);
            if (!conn.finReceived) {
                sendAck(conn);
            }
        } else {
            sendAck(conn);
        }
    }

    if (flags & TH_FIN) {
        const uint32_t finAt = seq + uint32_t(payloadLen);
        if (!conn.peerFinQueued) {
            conn.peerFinQueued = true;
            conn.peerFinSeq = finAt;
        }
        maybeFinishFin(conn, now);
    }

    outputData(conn, now);
}

} // namespace

uint16_t tcpChecksum(in_addr src, in_addr dst, const void* segment, size_t len) {
    uint8_t pseudo[12] = {};
    std::memcpy(pseudo, &src.s_addr, 4);
    std::memcpy(pseudo + 4, &dst.s_addr, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    writeU16(pseudo + 10, uint16_t(len));

    uint32_t sum = 0;
    checksumAdd(sum, pseudo, sizeof(pseudo));
    checksumAdd(sum, static_cast<const uint8_t*>(segment), len);
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return uint16_t(~sum);
}

void tcpInitCongestionControl() {
    const char* value = std::getenv("NETSTACK_CC");
    defaultCc = (value != nullptr && strcasecmp(value, "bbr") == 0)
                    ? TcpCongestionControl::Bbr
                    : TcpCongestionControl::Reno;
}

void tcpInit() {
    connections.clear();
    nextHandle = 1;
    nextEphemeralPort = 49152;
    logStates = std::getenv("NETSTACK_TCP_LOG") != nullptr;
    logCc = std::getenv("NETSTACK_CC_LOG") != nullptr;
    tcpInitCongestionControl();
}

int tcpReceivePacket(const void* packet, int len) {
    if (packet == nullptr || len < int(IP_HEADER_LEN + TCP_HEADER_LEN)) {
        return 0;
    }
    const auto* ip = static_cast<const uint8_t*>(packet);
    const int ihl = (ip[0] & 0x0f) * 4;
    if (ihl < int(IP_HEADER_LEN) || len < ihl + int(TCP_HEADER_LEN)) {
        return 0;
    }
    if (ip[9] != IPPROTO_TCP) {
        return 0;
    }
    const int totalLen = readU16(ip + 2);
    if (totalLen < ihl + int(TCP_HEADER_LEN) || totalLen > len) {
        return 0;
    }

    in_addr src{};
    in_addr dst{};
    std::memcpy(&src, ip + 12, sizeof(src));
    std::memcpy(&dst, ip + 16, sizeof(dst));

    const uint8_t* tcp = ip + ihl;
    const int tcpLen = totalLen - ihl;
    const int dataOffset = (tcp[12] >> 4) * 4;
    if (dataOffset < int(TCP_HEADER_LEN) || dataOffset > tcpLen) {
        return 0;
    }
    if (tcpChecksum(src, dst, tcp, size_t(tcpLen)) != 0) {
        return 0;
    }

    const uint16_t sport = readU16(tcp);
    const uint16_t dport = readU16(tcp + 2);
    const uint32_t seq = readU32(tcp + 4);
    const uint32_t ack = readU32(tcp + 8);
    const uint8_t flags = tcp[13];
    const uint16_t window = readU16(tcp + 14);
    const uint8_t* payload = tcp + dataOffset;
    const int payloadLen = tcpLen - dataOffset;
    const TimePoint now = std::chrono::steady_clock().now();

    TcpConn* conn = findConnection(dst, dport, src, sport);
    if (conn == nullptr) {
        if ((flags & TH_SYN) != 0 && (flags & (TH_RST | TH_ACK)) == 0) {
            TcpConn* listener = findListener(dst, dport);
            if (listener != nullptr) {
                const uint16_t mss = parseMss(tcp + TCP_HEADER_LEN,
                                              dataOffset - int(TCP_HEADER_LEN));
                createChild(*listener, dst, src, sport, seq, window, mss, now);
                return 0;
            }
        }
        if ((flags & TH_RST) == 0) {
            const bool ackValid = (flags & TH_ACK) != 0;
            sendReset(dst, src, dport, sport, seq, ack, ackValid);
        }
        return 0;
    }

    const uint16_t mss =
        (flags & TH_SYN) != 0
            ? parseMss(tcp + TCP_HEADER_LEN, dataOffset - int(TCP_HEADER_LEN))
            : conn->peerMss;
    processSegment(*conn, seq, ack, flags, window, payload, payloadLen, mss,
                   now);
    return 0;
}

void tcpTick(TimePoint now) {
    std::vector<int> removeList;
    for (auto& [id, connPtr] : connections) {
        TcpConn& conn = *connPtr;
        if (conn.state == TcpState::Listen) {
            continue;
        }
        if (conn.state == TcpState::Closed) {
            continue;
        }

        if (conn.state == TcpState::SynSent ||
            conn.state == TcpState::SynReceived) {
            if (elapsedMs(now, conn.synSentAt) >= conn.rtoMs) {
                if (conn.synRetries >= TCP_SYN_RETRIES) {
                    conn.error = ETIMEDOUT;
                    setState(conn, TcpState::Closed, "syn timeout");
                } else {
                    if (conn.state == TcpState::SynSent) {
                        sendSyn(conn);
                    } else {
                        sendSynAck(conn);
                    }
                    ++conn.synRetries;
                    conn.rtoMs =
                        std::min<uint32_t>(conn.rtoMs * 2, TCP_MAX_RTO_MS);
                    conn.synSentAt = now;
                }
            }
            continue;
        }

        if (conn.state == TcpState::TimeWait) {
            if (elapsedMs(now, conn.timeWaitStart) >= TCP_TIME_WAIT_MS) {
                setState(conn, TcpState::Closed, "time-wait expired");
                removeList.push_back(id);
            }
            continue;
        }

        if (conn.sndUna != conn.sndNxt) {
            if (!conn.timerRunning) {
                conn.timerRunning = true;
                conn.timerStart = now;
                conn.rttPending = true;
                conn.rttStart = now;
            } else if (elapsedMs(now, conn.timerStart) >= conn.rtoMs) {
                if (conn.retries >= TCP_MAX_RETRIES) {
                    conn.error = ETIMEDOUT;
                    setState(conn, TcpState::Closed, "retry limit");
                    continue;
                }
                retransmit(conn);
                ++conn.retries;
                conn.rtoMs = std::min<uint32_t>(conn.rtoMs * 2, TCP_MAX_RTO_MS);
                conn.timerStart = now;
                congestionOnTimeout(conn);
            }
        } else {
            conn.timerRunning = false;
            conn.rttPending = false;
        }

        const size_t unsent = conn.sendBuf.size() -
                              std::min<size_t>(conn.sndNxt - conn.sndUna,
                                               conn.sendBuf.size());
        if (conn.sndWnd == 0 && unsent > 0) {
            if (!conn.probePending) {
                conn.probePending = true;
                conn.probeStart = now;
            } else if (elapsedMs(now, conn.probeStart) >= conn.rtoMs) {
                const size_t offset = size_t(conn.sndNxt - conn.sndUna);
                if (offset < conn.sendBuf.size()) {
                    sendSegment(conn, TH_ACK, conn.sndNxt, conn.rcvNxt,
                                advertisedWindow(conn),
                                conn.sendBuf.data() + offset, 1, false);
                    conn.sndNxt += 1;
                }
                conn.probeStart = now;
            }
        } else {
            conn.probePending = false;
        }

        outputData(conn, now);

        if (logCc && elapsedMs(now, conn.lastCcLog) >= TCP_CC_LOG_INTERVAL_MS) {
            conn.lastCcLog = now;
            const uint64_t flight = conn.sndNxt - conn.sndUna;
            const uint32_t minRtt =
                conn.bbr.minRttMs == UINT32_MAX ? 0 : conn.bbr.minRttMs;
            const uint32_t pacing =
                uint32_t(conn.bbr.pacingGain * conn.bbr.btlbw);
            fprintf(stderr,
                    "CC %u->%u t=%u cwnd=%u ssthresh=%u inflight=%llu "
                    "srtt=%u rto=%u minrtt=%u mode=%d pacing=%u\n",
                    conn.localPort, conn.remotePort,
                    uint32_t(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 now.time_since_epoch())
                                 .count()),
                    conn.cwnd, conn.ssthresh,
                    static_cast<unsigned long long>(flight), conn.srttMs,
                    conn.rtoMs, minRtt, conn.bbr.mode, pacing);
        }
    }

    for (int id : removeList) {
        connections.erase(id);
    }
}

int tcpOpen() {
    auto conn = newConn();
    const int id = conn->id;
    connections[id] = std::move(conn);
    return id;
}

int tcpBind(int conn, in_addr address, uint16_t port) {
    TcpConn* state = getConn(conn);
    if (state == nullptr || state->state != TcpState::Closed) {
        errno = EINVAL;
        return -1;
    }
    if (state->localPort != 0) {
        errno = EINVAL;
        return -1;
    }
    if (port == 0) {
        port = allocateEphemeralPort();
        if (port == 0) {
            errno = EADDRINUSE;
            return -1;
        }
    } else if (portInUse(port)) {
        errno = EADDRINUSE;
        return -1;
    }
    state->localAddress = address;
    state->localPort = port;
    return 0;
}

int tcpListen(int conn, int backlog) {
    TcpConn* state = getConn(conn);
    if (state == nullptr || state->state != TcpState::Closed) {
        errno = EINVAL;
        return -1;
    }
    if (state->localPort == 0) {
        state->localPort = allocateEphemeralPort();
        if (state->localPort == 0) {
            errno = EADDRINUSE;
            return -1;
        }
    }
    state->backlog = std::max(backlog, 1);
    setState(*state, TcpState::Listen, "listen");
    return 0;
}

int tcpConnect(int conn, in_addr remoteAddress, uint16_t remotePort) {
    TcpConn* state = getConn(conn);
    if (state == nullptr) {
        errno = EBADF;
        return -1;
    }
    if (state->state != TcpState::Closed) {
        errno = EISCONN;
        return -1;
    }
    if (state->localPort == 0) {
        state->localPort = allocateEphemeralPort();
        if (state->localPort == 0) {
            errno = EADDRINUSE;
            return -1;
        }
    }
    if (state->localAddress.s_addr == 0 &&
        !selectSource(remoteAddress, state->localAddress)) {
        errno = ENETUNREACH;
        return -1;
    }
    state->remoteAddress = remoteAddress;
    state->remotePort = remotePort;
    state->iss = generateIss();
    state->sndUna = state->iss;
    state->sndNxt = state->iss;
    state->sndWnd = 0;
    state->cwnd = TCP_INITIAL_CWND;
    state->ssthresh = 65535;
    state->synSent = true;
    state->synSentAt = std::chrono::steady_clock().now();
    state->synRetries = 0;
    setState(*state, TcpState::SynSent, "connect");
    if (sendSyn(*state) < 0) {
        state->error = ENETUNREACH;
        setState(*state, TcpState::Closed, "send failed");
        errno = ENETUNREACH;
        return -1;
    }
    state->sndNxt = state->iss + 1;
    return 0;
}

int tcpAccept(int listener) {
    TcpConn* state = getConn(listener);
    if (state == nullptr || state->state != TcpState::Listen) {
        errno = EBADF;
        return -1;
    }
    if (state->acceptQueue.empty()) {
        errno = EAGAIN;
        return -1;
    }
    const int id = state->acceptQueue.front();
    state->acceptQueue.pop_front();
    return id;
}

ssize_t tcpRead(int conn, void* buffer, size_t length) {
    TcpConn* state = getConn(conn);
    if (state == nullptr) {
        errno = EBADF;
        return -1;
    }
    if (length == 0) {
        return 0;
    }
    if (state->state == TcpState::Listen || state->state == TcpState::SynSent ||
        state->state == TcpState::SynReceived) {
        errno = ENOTCONN;
        return -1;
    }
    if (state->recvBuf.empty()) {
        if (state->error != 0) {
            errno = state->error;
            return -1;
        }
        if (state->finReceived || state->state == TcpState::Closed) {
            return 0;
        }
        errno = EAGAIN;
        return -1;
    }

    const size_t count = std::min(length, state->recvBuf.size());
    std::memcpy(buffer, state->recvBuf.data(), count);
    state->recvBuf.erase(state->recvBuf.begin(),
                         state->recvBuf.begin() + count);

    const uint16_t window = advertisedWindow(*state);
    if (window >= uint32_t(state->lastAdvertised) + state->peerMss ||
        state->lastAdvertised == 0) {
        sendAck(*state);
    }
    return ssize_t(count);
}

ssize_t tcpWrite(int conn, const void* buffer, size_t length) {
    TcpConn* state = getConn(conn);
    if (state == nullptr) {
        errno = EBADF;
        return -1;
    }
    if (state->error != 0) {
        errno = state->error;
        return -1;
    }
    if (state->state == TcpState::Closed || state->finQueued) {
        errno = EPIPE;
        return -1;
    }
    if (state->state != TcpState::Established &&
        state->state != TcpState::CloseWait) {
        errno = ENOTCONN;
        return -1;
    }
    if (length == 0) {
        return 0;
    }
    const size_t space = TCP_SEND_CAPACITY - state->sendBuf.size();
    if (space == 0) {
        return 0;
    }
    const size_t count = std::min(length, space);
    const auto* bytes = static_cast<const uint8_t*>(buffer);
    state->sendBuf.insert(state->sendBuf.end(), bytes, bytes + count);
    outputData(*state, std::chrono::steady_clock().now());
    return ssize_t(count);
}

void tcpClose(int conn) {
    TcpConn* state = getConn(conn);
    if (state == nullptr) {
        return;
    }
    if (state->state == TcpState::Listen) {
        for (auto& [id, child] : connections) {
            if (child->parent == state->id) {
                setState(*child, TcpState::Closed, "parent closed");
            }
        }
        setState(*state, TcpState::Closed, "close");
        return;
    }
    if (state->state == TcpState::Closed ||
        state->state == TcpState::TimeWait) {
        return;
    }
    if (state->state == TcpState::SynSent ||
        state->state == TcpState::SynReceived) {
        setState(*state, TcpState::Closed, "close");
        return;
    }
    if (!state->finQueued) {
        state->finQueued = true;
        state->finSeq = state->sndUna + uint32_t(state->sendBuf.size());
    }
    outputData(*state, std::chrono::steady_clock().now());
}

void tcpRelease(int conn) {
    TcpConn* state = getConn(conn);
    if (state == nullptr) {
        return;
    }
    if (state->state == TcpState::Listen) {
        for (auto& [id, child] : connections) {
            if (child->parent == state->id) {
                child->parent = -1;
            }
        }
    }
    connections.erase(conn);
}

size_t tcpPendingBytes(int conn) {
    TcpConn* state = getConn(conn);
    return state == nullptr ? 0 : state->sendBuf.size();
}

int tcpError(int conn) {
    TcpConn* state = getConn(conn);
    return state == nullptr ? EBADF : state->error;
}

TcpState tcpState(int conn) {
    TcpConn* state = getConn(conn);
    return state == nullptr ? TcpState::Closed : state->state;
}

in_addr tcpLocalAddress(int conn) {
    TcpConn* state = getConn(conn);
    return state == nullptr ? in_addr{} : state->localAddress;
}

uint16_t tcpLocalPort(int conn) {
    TcpConn* state = getConn(conn);
    return state == nullptr ? 0 : state->localPort;
}

in_addr tcpPeerAddress(int conn) {
    TcpConn* state = getConn(conn);
    return state == nullptr ? in_addr{} : state->remoteAddress;
}

uint16_t tcpPeerPort(int conn) {
    TcpConn* state = getConn(conn);
    return state == nullptr ? 0 : state->remotePort;
}

bool tcpGetCongestionInfo(int conn, TcpCongestionInfo& info) {
    TcpConn* state = getConn(conn);
    if (state == nullptr) {
        return false;
    }
    info.algorithm = state->cc;
    info.cwnd = state->cwnd;
    info.ssthresh = state->ssthresh;
    info.bytesInFlight = state->sndNxt - state->sndUna;
    info.bytesQueued = state->sendBuf.size();
    info.srttMs = state->srttMs;
    info.rtoMs = state->rtoMs;
    info.minRttMs =
        state->bbr.minRttMs == UINT32_MAX ? 0 : state->bbr.minRttMs;
    info.pacingRate = uint32_t(state->bbr.pacingGain * state->bbr.btlbw);
    info.mode = state->bbr.mode;
    return true;
}
