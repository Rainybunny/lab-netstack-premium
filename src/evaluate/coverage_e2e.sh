#!/bin/bash
# Extra coverage workload: a two-node length-prefixed echo through the
# instrumented stack. Sourced by coverage.sh with BIN pointing at the
# coverage build.
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

N1=${PREFIX}ten1
N2=${PREFIX}ten2
V12=${PREFIX}tev12
V21=${PREFIX}tev21
SERVER_PID=

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    del_ns "$N1" "$N2"
}
trap cleanup EXIT

make_ns "$N1" "$N2"
ip link add "$V12" type veth peer name "$V21"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip netns exec "$N1" ip addr add 10.190.1.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.190.1.2/24 dev "$V21"
isolate "$N1" "$N2"
ip netns exec "$N1" ip link set "$V12" up
ip netns exec "$N2" ip link set "$V21" up
ip netns exec "$N2" stdbuf -oL -eL "$BIN/tcp_tool" echoserver 10086 \
    > "$OUT/cl10-e2e.log" 2>&1 &
SERVER_PID=$!
sleep 2
timeout 30 ip netns exec "$N1" stdbuf -oL -eL "$BIN/tcp_tool" \
    echoclient 10.190.1.2 10086 200000 >> "$OUT/cl10-e2e.log" 2>&1 ||
    echo "e2e client exit $?" >> "$OUT/cl10-e2e.log"
sleep 1
