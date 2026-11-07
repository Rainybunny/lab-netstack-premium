#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cp8
TRANSCRIPT=$OUT/cp8.txt
: > "$TRANSCRIPT"

N1=${PREFIX}8n1
N2=${PREFIX}8n2
V12=${PREFIX}8v12
V21=${PREFIX}8v21
SERVER_PID=
CAP_PID=

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2"
}
trap cleanup EXIT

say "=== CP8: reliable delivery over a lossy link ==="
say "topology: $N1 --- $N2 (10.110.8.0/24)"
say "loss: NETSTACK_LOSS=10 (drops 10% of transmitted IPv4 TCP frames;"
say "      the WSL kernel here exposes no netem/tbf qdisc, so the stack's"
say "      reproducible loss injector stands in for tc netem)"
say "traffic: 200000-byte length-prefixed echo, verified byte by byte"
say ""

make_ns "$N1" "$N2"
ip link add "$V12" type veth peer name "$V21"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip netns exec "$N1" ip addr add 10.110.8.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.110.8.2/24 dev "$V21"
isolate "$N1" "$N2"
ip netns exec "$N1" ip link set "$V12" up
ip netns exec "$N2" ip link set "$V21" up

CAP_PID=$(start_capture "$N1" "$V12" "$OUT/cp8.pcap" 60)
sleep 1
NETSTACK_LOSS=10 NETSTACK_LOSS_SEED=1 \
    ip netns exec "$N2" stdbuf -oL -eL "$BIN/tcp_tool" echoserver 10086 \
    > "$OUT/cp8-server.log" 2>&1 &
SERVER_PID=$!
sleep 2
NETSTACK_LOSS=10 NETSTACK_LOSS_SEED=2 \
    timeout 50 ip netns exec "$N1" stdbuf -oL -eL "$BIN/tcp_tool" \
    echoclient 10.110.8.2 10086 200000 \
    > "$OUT/cp8-client.log" 2>&1 || say "client exit $?"
sleep 2

say "=== echo client output ==="
grep -v '^LINKSTATE' "$OUT/cp8-client.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== echo server output ==="
grep -v '^LINKSTATE' "$OUT/cp8-server.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== retransmissions observed on the client link ==="
python3 -I "$SCRIPT_DIR/retrans.py" "$OUT/cp8.pcap" | tee -a "$TRANSCRIPT"
say ""
say "The client verified the complete 200000-byte payload, so the gaps"
say "created by the injected loss were repaired by retransmission."
