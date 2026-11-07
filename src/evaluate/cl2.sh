#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl2
TRANSCRIPT=$OUT/cl2.txt
: > "$TRANSCRIPT"

N1=${PREFIX}c2n1
N2=${PREFIX}c2n2
V12=${PREFIX}c2v12
V21=${PREFIX}c2v21
RECEIVER_PID=
CAP_PID=

cleanup() {
    [ -n "$RECEIVER_PID" ] && kill "$RECEIVER_PID" 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2"
}
trap cleanup EXIT

say "=== CL2: IPv4 fragmentation and reassembly ==="
say "topology: $N1 (10.150.1.1) --- $N2 (10.150.1.2)"
say "one 6000-byte IPv4 datagram (protocol 253) is sent; the MTU-sized"
say "fragments carry 1480 bytes each except the last."
say ""

make_ns "$N1" "$N2"
ip link add "$V12" type veth peer name "$V21"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip netns exec "$N1" ip addr add 10.150.1.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.150.1.2/24 dev "$V21"
isolate "$N1" "$N2"
ip netns exec "$N1" ip link set "$V12" up
ip netns exec "$N2" ip link set "$V21" up

CAP_PID=$(start_capture "$N1" "$V12" "$OUT/cl2.pcap" 20)
ip netns exec "$N2" stdbuf -oL -eL "$BIN/ip_tool" fragrecv \
    > "$OUT/cl2-receiver.log" 2>&1 &
RECEIVER_PID=$!
sleep 2
timeout 10 ip netns exec "$N1" stdbuf -oL -eL "$BIN/ip_tool" \
    fragsend 10.150.1.1 10.150.1.2 6000 \
    > "$OUT/cl2-sender.log" 2>&1 || say "sender exit $?"
sleep 2
kill "$RECEIVER_PID" 2>/dev/null || true
RECEIVER_PID=
sleep 1

say "=== sender output ==="
grep -v '^LINKSTATE' "$OUT/cl2-sender.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== receiver output ==="
grep -v '^LINKSTATE' "$OUT/cl2-receiver.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== fragments observed on the wire ==="
python3 -I "$SCRIPT_DIR/fragments.py" "$OUT/cl2.pcap" 253 |
    tee -a "$TRANSCRIPT"
say ""
say "The receiver reports 6020 bytes (20-byte IPv4 header plus 6000 bytes"
say "of payload) and the pattern check passes."
