#include "packetio.h"

static recv_callback_t receive_callback = nullptr;

int send_frame(const void* buf, int len,
               int ethtype, const void* destmac, int id) {
    if (len < 0 || static_cast<size_t>(len) > ETH_PAYLOAD_MAX ||
        destmac == nullptr || (buf == nullptr && len != 0) ||
        ethtype < 0x0600 || ethtype > 0xffff) {
        return -1;
    }

    auto src = get_mac(id);
    if (!src.has_value()) { // no mac address available
        return -1;
    }

    eth_buf_t pktbuf{};
    uint16_t ns_ethtype = htons((uint16_t)ethtype);
    memcpy(pktbuf, destmac, 6);
    memcpy(pktbuf + 6, src.value().data(), 6);
    memcpy(pktbuf + 12, &ns_ethtype, 2);
    if (len != 0) {
        memcpy(pktbuf + 14, buf, len);
    }

    // Ethernet payloads shorter than 46 bytes require zero padding.
    return inject_frame(id, pktbuf, len < 46 ? 60 : len + 14);
}

int set_frame_receive_callback(recv_callback_t callback) {
    receive_callback = callback;
    return 0;
}

static void dispatch_frame(const void* bytes, int len, int id) {
    if (len < 14 || receive_callback == nullptr) {
        return;
    }
    const auto* frame = static_cast<const u_char*>(bytes);
    if ((static_cast<unsigned>(frame[12]) << 8 | frame[13]) < 0x0600) {
        return; // IEEE 802.3 length fields are not Ethernet II EtherTypes.
    }
    if (receive_callback(bytes, len, id) != 0) {
        WARN("dispatch_frame: callback failed on device %d\n", id);
    }
}

int run_receive_loop() {
    if (receive_callback == nullptr) {
        WARN("run_receive_loop: no callback registered\n");
        return -1;
    }
    return run_device_receive_loop(dispatch_frame);
}

void stop_receive_loop() {
    stop_device_receive_loop();
}
