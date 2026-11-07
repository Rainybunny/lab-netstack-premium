#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl3
TRANSCRIPT=$OUT/cl3.txt
: > "$TRANSCRIPT"

N1=${PREFIX}c3n1
N2=${PREFIX}c3n2
N3=${PREFIX}c3n3
N4=${PREFIX}c3n4
V14=${PREFIX}c3v14
V41=${PREFIX}c3v41
V24=${PREFIX}c3v24
V42=${PREFIX}c3v42
V34=${PREFIX}c3v34
V43=${PREFIX}c3v43
BACKGROUND=
CAP_PID=

cleanup() {
    [ -n "$BACKGROUND" ] && kill $BACKGROUND 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2" "$N3" "$N4"
}
trap cleanup EXIT

say "=== CL3: weighted fair queueing at the router ==="
say "topology: $N1 --- $N4 --- $N3"
say "          $N2 ---/"
say "weights: 10.120.1.1 = 1, 10.120.2.1 = 2"
say "router egress: $V43, rate 120000 B/s, queue 16384 B, WFQ"
say ""

make_ns "$N1" "$N2" "$N3" "$N4"
ip link add "$V14" type veth peer name "$V41"
ip link add "$V24" type veth peer name "$V42"
ip link add "$V43" type veth peer name "$V34"
ip link set "$V14" netns "$N1"
ip link set "$V41" netns "$N4"
ip link set "$V24" netns "$N2"
ip link set "$V42" netns "$N4"
ip link set "$V43" netns "$N4"
ip link set "$V34" netns "$N3"
ip netns exec "$N1" ip addr add 10.120.1.1/24 dev "$V14"
ip netns exec "$N4" ip addr add 10.120.1.2/24 dev "$V41"
ip netns exec "$N2" ip addr add 10.120.2.1/24 dev "$V24"
ip netns exec "$N4" ip addr add 10.120.2.2/24 dev "$V42"
ip netns exec "$N4" ip addr add 10.120.3.1/24 dev "$V43"
ip netns exec "$N3" ip addr add 10.120.3.2/24 dev "$V34"
isolate "$N1" "$N2" "$N3" "$N4"
for binding in "$N1 $V14" "$N4 $V41" "$N2 $V24" "$N4 $V42" \
               "$N4 $V43" "$N3 $V34"; do
    set -- $binding
    ip netns exec "$1" ip link set "$2" up
done

NETSTACK_EGRESS_DEV="$V43" NETSTACK_EGRESS_RATE=120000 \
NETSTACK_EGRESS_QUEUE=16384 NETSTACK_EGRESS_MODE=wfq \
NETSTACK_EGRESS_WEIGHTS="10.120.1.1=1,10.120.2.1=2" \
    ip netns exec "$N4" stdbuf -oL -eL "$BIN/lab3_router" \
    > "$OUT/cl3-router.log" 2>&1 &
BACKGROUND="$!"
ip netns exec "$N3" stdbuf -oL -eL "$BIN/tcp_tool" sink 10086 2 20 \
    > "$OUT/cl3-sink.log" 2>&1 &
BACKGROUND="$BACKGROUND $!"
say "waiting 6 s for link-state convergence"
sleep 6

timeout 24 ip netns exec "$N1" stdbuf -oL -eL "$BIN/tcp_tool" \
    source 10.120.3.2 10086 50000000 > "$OUT/cl3-source1.log" 2>&1 &
S1=$!
timeout 24 ip netns exec "$N2" stdbuf -oL -eL "$BIN/tcp_tool" \
    source 10.120.3.2 10086 50000000 > "$OUT/cl3-source2.log" 2>&1 &
S2=$!
BACKGROUND="$BACKGROUND $S1 $S2"
wait "$S1" 2>/dev/null || true
wait "$S2" 2>/dev/null || true
sleep 1

say "=== sink accept and final totals ==="
grep -E '^(ACCEPT|TOTAL)' "$OUT/cl3-sink.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== last per-flow samples ==="
grep '^FLOW' "$OUT/cl3-sink.log" | tail -4 | tee -a "$TRANSCRIPT" || true
say ""
say "=== weighted ratio ==="
python3 -I - "$OUT/cl3-sink.log" <<'PY' | tee -a "$TRANSCRIPT"
import sys
values = {}
for line in open(sys.argv[1]):
    if line.startswith("TOTAL "):
        fields = line.split()
        values[fields[1]] = int(fields[2])
items = sorted(values.items())
for peer, value in items:
    print("%s %d bytes" % (peer, value))
if len(items) == 2 and items[0][1] > 0:
    print("ratio = %.2f (weights are 1:2)" % (items[1][1] / items[0][1]))
PY
say ""
say "=== router route state ==="
grep -h 'LINKSTATE spf' "$OUT/cl3-router.log" | tail -3 |
    tee -a "$TRANSCRIPT" || true
