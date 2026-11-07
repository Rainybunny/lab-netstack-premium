#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl5
TRANSCRIPT=$OUT/cl5.txt
: > "$TRANSCRIPT"

N1=${PREFIX}c5n1
N2=${PREFIX}c5n2
N3=${PREFIX}c5n3
V12=${PREFIX}c5v12
V21=${PREFIX}c5v21
V23=${PREFIX}c5v23
V32=${PREFIX}c5v32
BACKGROUND=

cleanup() {
    [ -n "$BACKGROUND" ] && kill $BACKGROUND 2>/dev/null || true
    del_ns "$N1" "$N2" "$N3"
}
trap cleanup EXIT

say "=== CL5: Reno congestion control over a FIFO bottleneck ==="
say "topology: $N1 (source) --- $N2 (router) --- $N3 (sink)"
say "router egress: $V23, FIFO rate 200000 B/s, queue 16384 B"
say "the source logs cwnd every 100 ms with NETSTACK_CC_LOG=1."
say ""

make_ns "$N1" "$N2" "$N3"
ip link add "$V12" type veth peer name "$V21"
ip link add "$V23" type veth peer name "$V32"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip link set "$V23" netns "$N2"
ip link set "$V32" netns "$N3"
ip netns exec "$N1" ip addr add 10.180.1.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.180.1.2/24 dev "$V21"
ip netns exec "$N2" ip addr add 10.180.2.1/24 dev "$V23"
ip netns exec "$N3" ip addr add 10.180.2.2/24 dev "$V32"
isolate "$N1" "$N2" "$N3"
for binding in "$N1 $V12" "$N2 $V21" "$N2 $V23" "$N3 $V32"; do
    set -- $binding
    ip netns exec "$1" ip link set "$2" up
done

NETSTACK_EGRESS_DEV="$V23" NETSTACK_EGRESS_RATE=200000 \
NETSTACK_EGRESS_QUEUE=16384 NETSTACK_EGRESS_MODE=fifo \
    ip netns exec "$N2" stdbuf -oL -eL "$BIN/lab3_router" \
    > "$OUT/cl5-router.log" 2>&1 &
BACKGROUND="$!"
ip netns exec "$N3" stdbuf -oL -eL "$BIN/tcp_tool" sink 10086 1 20 \
    > "$OUT/cl5-sink.log" 2>&1 &
BACKGROUND="$BACKGROUND $!"
say "waiting 5 s for link-state convergence"
sleep 5

NETSTACK_CC=reno NETSTACK_CC_LOG=1 timeout 22 ip netns exec "$N1" \
    stdbuf -oL -eL "$BIN/tcp_tool" source 10.180.2.2 10086 50000000 \
    > "$OUT/cl5-source.log" 2> "$OUT/cl5-cc.log" &
SOURCE_PID=$!
BACKGROUND="$BACKGROUND $SOURCE_PID"
wait "$SOURCE_PID" 2>/dev/null || true
sleep 1

say "=== sink totals ==="
grep -E '^(ACCEPT|TOTAL)' "$OUT/cl5-sink.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== source progress (last samples) ==="
grep '^PROGRESS' "$OUT/cl5-source.log" | tail -4 |
    tee -a "$TRANSCRIPT" || true
say ""
say "=== cwnd trace ==="
python3 -I "$SCRIPT_DIR/plot_cc.py" "$OUT/cl5-cc.log" \
    "$OUT/cl5-cwnd.svg" "Reno cwnd over a 200000 B/s bottleneck" |
    tee -a "$TRANSCRIPT"
say ""
say "The plot is saved as lab3/checkpoints/cl5-cwnd.svg."
