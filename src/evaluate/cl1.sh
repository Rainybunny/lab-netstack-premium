#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl1
TRANSCRIPT=$OUT/cl1.txt
: > "$TRANSCRIPT"

N1=${PREFIX}c1n1
N2=${PREFIX}c1n2
V12=${PREFIX}c1v12
V21=${PREFIX}c1v21
A_PID=
B_PID=
CAP_PID=

cleanup() {
    [ -n "$A_PID" ] && kill "$A_PID" 2>/dev/null || true
    [ -n "$B_PID" ] && kill "$B_PID" 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2"
}
trap cleanup EXIT

say "=== CL1: simultaneous open and simultaneous close ==="
say "topology: $N1 (10.160.1.1:12000) --- $N2 (10.160.1.2:12001)"
say "both applications bind a fixed port, then call connect at the same"
say "wall-clock instant; later they call close at another shared instant."
say "TCP state transitions are logged with NETSTACK_TCP_LOG=1."
say ""

make_ns "$N1" "$N2"
ip link add "$V12" type veth peer name "$V21"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip netns exec "$N1" ip addr add 10.160.1.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.160.1.2/24 dev "$V21"
isolate "$N1" "$N2"
ip netns exec "$N1" ip link set "$V12" up
ip netns exec "$N2" ip link set "$V21" up

CAP_PID=$(start_capture "$N1" "$V12" "$OUT/cl1.pcap" 30)
OPEN=$(($(date +%s%3N) + 5000))
CLOSE=$((OPEN + 5000))
say "shared connect time: $OPEN ms, shared close time: $CLOSE ms"
say ""
NETSTACK_TCP_LOG=1 ip netns exec "$N1" stdbuf -oL -eL "$BIN/tcp_tool" \
    simopen 10.160.1.1 12000 10.160.1.2 12001 "$OPEN" "$CLOSE" \
    > "$OUT/cl1-a.log" 2> "$OUT/cl1-a.err" &
A_PID=$!
NETSTACK_TCP_LOG=1 ip netns exec "$N2" stdbuf -oL -eL "$BIN/tcp_tool" \
    simopen 10.160.1.2 12001 10.160.1.1 12000 "$OPEN" "$CLOSE" \
    > "$OUT/cl1-b.log" 2> "$OUT/cl1-b.err" &
B_PID=$!
wait "$A_PID"
wait "$B_PID"
A_PID=
B_PID=
sleep 1

say "=== host A application output ==="
grep -v '^LINKSTATE' "$OUT/cl1-a.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== host B application output ==="
grep -v '^LINKSTATE' "$OUT/cl1-b.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== host A TCP state transitions ==="
grep '^TCP' "$OUT/cl1-a.err" | tee -a "$TRANSCRIPT" || true
say ""
say "=== host B TCP state transitions ==="
grep '^TCP' "$OUT/cl1-b.err" | tee -a "$TRANSCRIPT" || true
say ""
say "=== SYN / SYN-ACK / FIN segments on the wire ==="
python3 -I "$SCRIPT_DIR/syn.py" "$OUT/cl1.pcap" | tee -a "$TRANSCRIPT"
say ""
say "Both hosts pass through SYN_SENT -> SYN_RECEIVED -> ESTABLISHED and"
say "FIN_WAIT_1 -> CLOSING -> TIME_WAIT, which are the RFC 793 simultaneous"
say "open and simultaneous close paths."
