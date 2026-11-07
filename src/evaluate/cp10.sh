#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cp10
TRANSCRIPT=$OUT/cp10.txt
: > "$TRANSCRIPT"

N1=${PREFIX}an1
N2=${PREFIX}an2
N3=${PREFIX}an3
N4=${PREFIX}an4
V12=${PREFIX}av12
V21=${PREFIX}av21
V23=${PREFIX}av23
V32=${PREFIX}av32
V34=${PREFIX}av34
V43=${PREFIX}av43
BACKGROUND=
CAP_PID=

cleanup() {
    [ -n "$BACKGROUND" ] && kill $BACKGROUND 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2" "$N3" "$N4"
}
trap cleanup EXIT

say "=== CP10: official perf client/server across four nodes ==="
say "topology: $N1 --- $N2 --- $N3 --- $N4"
say "addresses: 10.110.101.0/24, 10.110.102.0/24, 10.110.103.0/24"
say "ns2 and ns3 run lab3_router; ns4 runs the unmodified perf_server;"
say "ns1 runs the unmodified perf_client."
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
ip netns exec "$N1" ip addr add 10.110.101.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.110.101.2/24 dev "$V21"
ip netns exec "$N2" ip addr add 10.110.102.1/24 dev "$V23"
ip netns exec "$N3" ip addr add 10.110.102.2/24 dev "$V32"
ip netns exec "$N3" ip addr add 10.110.103.1/24 dev "$V34"
ip netns exec "$N4" ip addr add 10.110.103.2/24 dev "$V43"
isolate "$N1" "$N2" "$N3" "$N4"
for binding in "$N1 $V12" "$N2 $V21" "$N2 $V23" "$N3 $V32" \
               "$N3 $V34" "$N4 $V43"; do
    set -- $binding
    ip netns exec "$1" ip link set "$2" up
done

ip netns exec "$N2" stdbuf -oL -eL "$BIN/lab3_router" \
    > "$OUT/cp10-ns2.log" 2>&1 &
BACKGROUND="$!"
ip netns exec "$N3" stdbuf -oL -eL "$BIN/lab3_router" \
    > "$OUT/cp10-ns3.log" 2>&1 &
BACKGROUND="$BACKGROUND $!"

CAP_PID=$(start_capture "$N1" "$V12" "$OUT/cp10.pcap" 60)
sleep 1
ip netns exec "$N4" stdbuf -oL -eL "$BIN/perf_server" \
    > "$OUT/cp10-server.log" 2>&1 &
BACKGROUND="$BACKGROUND $!"
say "waiting 6 s for link-state convergence"
sleep 6
timeout 120 ip netns exec "$N1" stdbuf -oL -eL "$BIN/perf_client" 10.110.103.2 \
    > "$OUT/cp10-client.log" 2>&1 || say "client exit $?"
sleep 2

say ""
say "=== perf client output (LINKSTATE control-plane lines removed) ==="
grep -v '^LINKSTATE' "$OUT/cp10-client.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== perf server output (LINKSTATE control-plane lines removed) ==="
grep -v '^LINKSTATE' "$OUT/cp10-server.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== captured TCP segment summary ==="
python3 -I "$SCRIPT_DIR/retrans.py" "$OUT/cp10.pcap" | tee -a "$TRANSCRIPT"
