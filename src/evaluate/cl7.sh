#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl7
TRANSCRIPT=$OUT/cl7.txt
: > "$TRANSCRIPT"

S1=${PREFIX}c7s1
S2=${PREFIX}c7s2
S3=${PREFIX}c7s3
S4=${PREFIX}c7s4
S5=${PREFIX}c7s5
R=${PREFIX}c7r
K=${PREFIX}c7k
BACKGROUND=
SOURCE_PIDS=

cleanup() {
    [ -n "$BACKGROUND" ] && kill $BACKGROUND 2>/dev/null || true
    del_ns "$S1" "$S2" "$S3" "$S4" "$S5" "$R" "$K"
}
trap cleanup EXIT

say "=== CL7: fairness of five TCP flows sharing one bottleneck ==="
say "topology: $S1..$S5 --- $R --- $K"
say "router egress: ${PREFIX}c7vrs, FIFO rate 500000 B/s, queue 32768 B"
say "each source offers 50 MB; the sink reports per-peer bytes for 25 s."
say ""

make_ns "$S1" "$S2" "$S3" "$S4" "$S5" "$R" "$K"
HOSTS=("$S1" "$S2" "$S3" "$S4" "$S5")
for index in 1 2 3 4 5; do
    host=${HOSTS[index - 1]}
    ip link add "${PREFIX}c7v${index}r" type veth peer name "${PREFIX}c7vr${index}"
    ip link set "${PREFIX}c7v${index}r" netns "$host"
    ip link set "${PREFIX}c7vr${index}" netns "$R"
    ip netns exec "$host" ip addr add \
        "10.130.$index.1/24" dev "${PREFIX}c7v${index}r"
    ip netns exec "$R" ip addr add "10.130.$index.2/24" \
        dev "${PREFIX}c7vr${index}"
done
ip link add "${PREFIX}c7vrs" type veth peer name "${PREFIX}c7vsr"
ip link set "${PREFIX}c7vrs" netns "$R"
ip link set "${PREFIX}c7vsr" netns "$K"
ip netns exec "$R" ip addr add 10.130.6.1/24 dev "${PREFIX}c7vrs"
ip netns exec "$K" ip addr add 10.130.6.2/24 dev "${PREFIX}c7vsr"

isolate "$S1" "$S2" "$S3" "$S4" "$S5" "$R" "$K"
for index in 1 2 3 4 5; do
    ip netns exec "${HOSTS[index - 1]}" ip link set \
        "${PREFIX}c7v${index}r" up
    ip netns exec "$R" ip link set "${PREFIX}c7vr${index}" up
done
ip netns exec "$R" ip link set "${PREFIX}c7vrs" up
ip netns exec "$K" ip link set "${PREFIX}c7vsr" up

NETSTACK_EGRESS_DEV="${PREFIX}c7vrs" NETSTACK_EGRESS_RATE=500000 \
NETSTACK_EGRESS_QUEUE=32768 NETSTACK_EGRESS_MODE=fifo \
    ip netns exec "$R" stdbuf -oL -eL "$BIN/lab3_router" \
    > "$OUT/cl7-router.log" 2>&1 &
BACKGROUND="$!"
ip netns exec "$K" stdbuf -oL -eL "$BIN/tcp_tool" sink 10086 5 25 \
    > "$OUT/cl7-sink.log" 2>&1 &
BACKGROUND="$BACKGROUND $!"
say "waiting 6 s for link-state convergence"
sleep 6

for index in 1 2 3 4 5; do
    timeout 30 ip netns exec "${HOSTS[index - 1]}" stdbuf -oL -eL \
        "$BIN/tcp_tool" source 10.130.6.2 10086 50000000 \
        > "$OUT/cl7-source$index.log" 2>&1 &
    pid=$!
    SOURCE_PIDS="$SOURCE_PIDS $pid"
    BACKGROUND="$BACKGROUND $pid"
done
for pid in $SOURCE_PIDS; do
    wait "$pid" 2>/dev/null || true
done
sleep 1

say "=== sink accept and final totals ==="
grep -E '^(ACCEPT|TOTAL)' "$OUT/cl7-sink.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== fairness index ==="
python3 -I "$SCRIPT_DIR/fairness.py" "$OUT/cl7-sink.log" |
    tee -a "$TRANSCRIPT"
say ""
say "Jain's index is 1.0 for perfectly equal shares."
