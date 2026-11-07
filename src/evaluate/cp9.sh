#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cp9
TRANSCRIPT=$OUT/cp9.txt
: > "$TRANSCRIPT"

N1=${PREFIX}9n1
N2=${PREFIX}9n2
N3=${PREFIX}9n3
N4=${PREFIX}9n4
V12=${PREFIX}9v12
V21=${PREFIX}9v21
V23=${PREFIX}9v23
V32=${PREFIX}9v32
V34=${PREFIX}9v34
V43=${PREFIX}9v43
ROUTER_PIDS=
CAP_PID=

cleanup() {
    [ -n "$ROUTER_PIDS" ] && kill $ROUTER_PIDS 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2" "$N3" "$N4"
}
trap cleanup EXIT

say "=== CP9: official echo client/server across four nodes ==="
say "topology: $N1 --- $N2 --- $N3 --- $N4"
say "addresses: 10.110.91.0/24, 10.110.92.0/24, 10.110.93.0/24"
say "ns2 and ns3 run lab3_router; ns4 runs the unmodified echo_server;"
say "ns1 runs the unmodified echo_client."
say ""

make_ns "$N1" "$N2" "$N3" "$N4"
ip link add "$V12" type veth peer name "$V21"
ip link add "$V23" type veth peer name "$V32"
ip link add "$V34" type veth peer name "$V43"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip link set "$V23" netns "$N2"
ip link set "$V32" netns "$N3"
ip link set "$V34" netns "$N3"
ip link set "$V43" netns "$N4"
ip netns exec "$N1" ip addr add 10.110.91.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.110.91.2/24 dev "$V21"
ip netns exec "$N2" ip addr add 10.110.92.1/24 dev "$V23"
ip netns exec "$N3" ip addr add 10.110.92.2/24 dev "$V32"
ip netns exec "$N3" ip addr add 10.110.93.1/24 dev "$V34"
ip netns exec "$N4" ip addr add 10.110.93.2/24 dev "$V43"
isolate "$N1" "$N2" "$N3" "$N4"
for binding in "$N1 $V12" "$N2 $V21" "$N2 $V23" "$N3 $V32" \
               "$N3 $V34" "$N4 $V43"; do
    set -- $binding
    ip netns exec "$1" ip link set "$2" up
done

ip netns exec "$N2" stdbuf -oL -eL "$BIN/lab3_router" \
    > "$OUT/cp9-ns2.log" 2>&1 &
P2=$!
ip netns exec "$N3" stdbuf -oL -eL "$BIN/lab3_router" \
    > "$OUT/cp9-ns3.log" 2>&1 &
P3=$!
ROUTER_PIDS="$P2 $P3"

CAP_PID=$(start_capture "$N1" "$V12" "$OUT/cp9.pcap" 90)
sleep 1
ip netns exec "$N4" stdbuf -oL -eL "$BIN/echo_server" \
    > "$OUT/cp9-server.log" 2>&1 &
SERVER_PID=$!
ROUTER_PIDS="$ROUTER_PIDS $SERVER_PID"
say "waiting 6 s for link-state convergence"
sleep 6
timeout 90 ip netns exec "$N1" stdbuf -oL -eL "$BIN/echo_client" 10.110.93.2 \
    > "$OUT/cp9-client.log" 2>&1 || say "client exit $?"
sleep 2

say ""
say "=== echo client output (LINKSTATE control-plane lines removed) ==="
grep -v '^LINKSTATE' "$OUT/cp9-client.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== echo server output (LINKSTATE control-plane lines removed) ==="
grep -v '^LINKSTATE' "$OUT/cp9-server.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== captured TCP segment summary ==="
python3 -I "$SCRIPT_DIR/retrans.py" "$OUT/cp9.pcap" | tee -a "$TRANSCRIPT"
say ""
say "=== router route counts ==="
grep -h 'LINKSTATE spf' "$OUT/cp9-ns2.log" "$OUT/cp9-ns3.log" | tail -4 |
    tee -a "$TRANSCRIPT" || true
