#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl4
TRANSCRIPT=$OUT/cl4.txt
: > "$TRANSCRIPT"

N1=${PREFIX}c4n1
N2=${PREFIX}c4n2
V12=${PREFIX}c4v12
V21=${PREFIX}c4v21
SINK_PID=
SOURCE_PID=
CAP_PID=

cleanup() {
    [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
    [ -n "$SOURCE_PID" ] && kill "$SOURCE_PID" 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2"
}
trap cleanup EXIT

say "=== CL4: TCP flow control with a slow receiver ==="
say "topology: $N1 (source, 10.170.1.1) --- $N2 (sink, 10.170.1.2)"
say "the sink reads 1024 bytes and then keeps pumping the stack for 20 ms"
say "without reading, so its 65535-byte receive buffer fills and the"
say "advertised window closes; the source is throttled instead of dropping."
say ""

make_ns "$N1" "$N2"
ip link add "$V12" type veth peer name "$V21"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip netns exec "$N1" ip addr add 10.170.1.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.170.1.2/24 dev "$V21"
isolate "$N1" "$N2"
ip netns exec "$N1" ip link set "$V12" up
ip netns exec "$N2" ip link set "$V21" up

CAP_PID=$(start_capture "$N1" "$V12" "$OUT/cl4.pcap" 25)
ip netns exec "$N2" stdbuf -oL -eL "$BIN/tcp_tool" sink 10086 1 15 slow \
    > "$OUT/cl4-sink.log" 2>&1 &
SINK_PID=$!
sleep 2
NETSTACK_CC_LOG=1 timeout 18 ip netns exec "$N1" stdbuf -oL -eL \
    "$BIN/tcp_tool" source 10.170.1.2 10086 50000000 \
    > "$OUT/cl4-source.log" 2> "$OUT/cl4-cc.log" &
SOURCE_PID=$!
wait "$SOURCE_PID" 2>/dev/null || true
SOURCE_PID=
wait "$SINK_PID" 2>/dev/null || true
SINK_PID=
sleep 1

say "=== slow sink output ==="
grep -E '^(ACCEPT|FLOW|TOTAL)' "$OUT/cl4-sink.log" | tail -6 |
    tee -a "$TRANSCRIPT" || true
say ""
say "=== source progress (last samples) ==="
grep '^PROGRESS' "$OUT/cl4-source.log" | tail -4 |
    tee -a "$TRANSCRIPT" || true
say ""
say "=== advertised window analysis ==="
python3 -I "$SCRIPT_DIR/window.py" "$OUT/cl4.pcap" | tee -a "$TRANSCRIPT"
say ""
say "The receive window reaches zero while the application is not reading,"
say "and reopens in small increments as the slow sink consumes data."
