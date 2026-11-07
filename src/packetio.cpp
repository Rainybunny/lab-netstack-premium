#include "packetio.h"

#include <cstdlib>
#include <cstring>

namespace {

FrameReceiveCallback receiveCallback = nullptr;

// Loss emulation for evaluating TCP retransmission. NETSTACK_LOSS is a
// percentage; only IPv4 TCP frames are dropped, so ARP and the control plane
// still work. NETSTACK_LOSS_SEED makes a run reproducible.
int lossPercent = -1;
uint32_t lossState = 1;

void configureLoss() {
    if (lossPercent >= 0) {
        return;
    }
    lossPercent = 0;
    const char* percent = std::getenv("NETSTACK_LOSS");
    if (percent != nullptr) {
        lossPercent = std::clamp(std::atoi(percent), 0, 100);
    }
    const char* seed = std::getenv("NETSTACK_LOSS_SEED");
    if (seed != nullptr) {
        lossState = uint32_t(std::strtoul(seed, nullptr, 10));
    }
    if (lossState == 0) {
        lossState = 1;
    }
}

bool shouldDrop(const void* buf, int len, int ethType) {
    configureLoss();
    if (lossPercent == 0 || ethType != ETH_TYPE_IPV4 ||
        len < int(IP_HEADER_LEN)) {
        return false;
    }
    const auto* packet = static_cast<const uint8_t*>(buf);
    if (packet[9] != IPPROTO_TCP) {
        return false;
    }
    lossState = lossState * 1664525u + 1013904223u;
    return int((lossState >> 16) % 100u) < lossPercent;
}

} // namespace

int sendFrame(const void* buf, int len,
              int ethType, const void* destMac, int id) {
    if (len < 0 || static_cast<size_t>(len) > ETH_PAYLOAD_MAX ||
        destMac == nullptr || (buf == nullptr && len != 0) ||
        ethType < 0x0600 || ethType > 0xffff) {
        return -1;
    }
    if (shouldDrop(buf, len, ethType)) {
        return 0;
    }

    auto src = getMac(id);
    if (!src.has_value()) { // no mac address available
        return -1;
    }

    eth_buf_t pktBuf{};
    uint16_t networkEthType = htons(static_cast<uint16_t>(ethType));
    std::memcpy(pktBuf, destMac, 6);
    std::memcpy(pktBuf + 6, src.value().data(), src.value().size());
    std::memcpy(pktBuf + 12, &networkEthType, 2);
    if (len != 0) {
        std::memcpy(pktBuf + ETH_HEADER_LEN, buf, static_cast<size_t>(len));
    }

    // Ethernet payloads shorter than 46 bytes require zero padding.
    return injectFrame(id, pktBuf, len < 46 ? 60 : len + static_cast<int>(ETH_HEADER_LEN));
}

int setFrameReceiveCallback(FrameReceiveCallback callback) {
    receiveCallback = callback;
    return 0;
}

namespace {

void dispatchFrame(const void* bytes, int len, int id) {
    if (len < static_cast<int>(ETH_HEADER_LEN) || receiveCallback == nullptr) {
        return;
    }
    const auto* frame = static_cast<const uint8_t*>(bytes);
    if (readU16(frame + 12) < 0x0600) {
        return; // IEEE 802.3 length fields are not Ethernet II EtherTypes.
    }
    if (receiveCallback(bytes, len, id) != 0) {
        WARN("dispatchFrame: callback failed on device %d\n", id);
    }
}

} // namespace

int runReceiveLoop() {
    if (receiveCallback == nullptr) {
        WARN("runReceiveLoop: no callback registered\n");
        return -1;
    }
    return runDeviceReceiveLoop(dispatchFrame);
}

int pollReceive(int timeoutMs) {
    if (receiveCallback == nullptr) {
        WARN("pollReceive: no callback registered\n");
        return -1;
    }
    return pollDevicesOnce(dispatchFrame, timeoutMs);
}

void stopReceiveLoop() {
    stopDeviceReceiveLoop();
}
