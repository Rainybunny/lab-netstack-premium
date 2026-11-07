#include "packetio.h"

#include <cstring>

namespace {

FrameReceiveCallback receiveCallback = nullptr;

} // namespace

int sendFrame(const void* buf, int len,
              int ethType, const void* destMac, int id) {
    if (len < 0 || static_cast<size_t>(len) > ETH_PAYLOAD_MAX ||
        destMac == nullptr || (buf == nullptr && len != 0) ||
        ethType < 0x0600 || ethType > 0xffff) {
        return -1;
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
