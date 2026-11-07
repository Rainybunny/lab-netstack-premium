#!/bin/bash

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
OUT=${OUT:?Set OUT to a new evidence directory}
mkdir -p "$OUT"
BIN=${BIN:-$ROOT/build/lab2_demo}
CAP=$SCRIPT_DIR/capture.py
PREFIX=l2cp4
WORK=$(mktemp -d)
NAMES=("${PREFIX}n1" "${PREFIX}n2" "${PREFIX}n3" "${PREFIX}n4")

cleanup() {
    for ns in "${NAMES[@]}"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "missing binary: $BIN" >&2; exit 1; }

for ns in "${NAMES[@]}"; do ip netns add "$ns"; done

ip link add ${PREFIX}v12 type veth peer name ${PREFIX}v21
ip link add ${PREFIX}v23 type veth peer name ${PREFIX}v32
ip link add ${PREFIX}v34 type veth peer name ${PREFIX}v43
ip link set ${PREFIX}v12 netns ${PREFIX}n1
ip link set ${PREFIX}v21 netns ${PREFIX}n2
ip link set ${PREFIX}v23 netns ${PREFIX}n2
ip link set ${PREFIX}v32 netns ${PREFIX}n3
ip link set ${PREFIX}v34 netns ${PREFIX}n3
ip link set ${PREFIX}v43 netns ${PREFIX}n4

ip netns exec ${PREFIX}n1 ip addr add 10.100.1.1/24 dev ${PREFIX}v12
ip netns exec ${PREFIX}n2 ip addr add 10.100.1.2/24 dev ${PREFIX}v21
ip netns exec ${PREFIX}n2 ip addr add 10.100.2.1/24 dev ${PREFIX}v23
ip netns exec ${PREFIX}n3 ip addr add 10.100.2.2/24 dev ${PREFIX}v32
ip netns exec ${PREFIX}n3 ip addr add 10.100.3.1/24 dev ${PREFIX}v34
ip netns exec ${PREFIX}n4 ip addr add 10.100.3.2/24 dev ${PREFIX}v43
for ns in "${NAMES[@]}"; do
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.arp_ignore=8
    ip netns exec "$ns" iptables -t filter -I INPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I OUTPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I FORWARD -j DROP
done
ip netns exec ${PREFIX}n1 ip link set ${PREFIX}v12 up
ip netns exec ${PREFIX}n2 ip link set ${PREFIX}v21 up
ip netns exec ${PREFIX}n2 ip link set ${PREFIX}v23 up
ip netns exec ${PREFIX}n3 ip link set ${PREFIX}v32 up
ip netns exec ${PREFIX}n3 ip link set ${PREFIX}v34 up
ip netns exec ${PREFIX}n4 ip link set ${PREFIX}v43 up

: > "$OUT/transcript.txt"
say() { echo "$*" | tee -a "$OUT/transcript.txt"; }

mkfifo "$WORK/n1.in" "$WORK/n2.in" "$WORK/n3.in" "$WORK/n4.in"
ip netns exec ${PREFIX}n1 python3 -I "$CAP" ${PREFIX}v12 "$OUT/ns1.pcap" \
    --seconds 55 &
CAP_PID=$!
for i in 1 2 3 4; do
    ip netns exec "${PREFIX}n$i" "$BIN" < "$WORK/n$i.in" \
        > "$OUT/ns$i.log" 2>&1 &
done
exec 3>"$WORK/n1.in"
exec 4>"$WORK/n2.in"
exec 5>"$WORK/n3.in"
exec 6>"$WORK/n4.in"

cmd1() {
    say "[ns1] $*"
    printf '%s\n' "$*" >&3
}

sleep 6
say "=== converged: distances, route lookup, ping ==="
cmd1 distances
cmd1 lookup 10.100.3.2
cmd1 ping 10.100.3.2 3
sleep 5

say "=== disconnect ns2 (both links down) ==="
ip netns exec ${PREFIX}n2 ip link set ${PREFIX}v21 down
ip netns exec ${PREFIX}n2 ip link set ${PREFIX}v23 down
sleep 7
cmd1 distances
cmd1 lookup 10.100.3.2
cmd1 ping 10.100.3.2 2
sleep 4

say "=== reconnect ns2 ==="
ip netns exec ${PREFIX}n2 ip link set ${PREFIX}v21 up
ip netns exec ${PREFIX}n2 ip link set ${PREFIX}v23 up
sleep 7
cmd1 distances
cmd1 lookup 10.100.3.2
cmd1 ping 10.100.3.2 3
sleep 5

for fd in 3 4 5 6; do printf 'quit\n' >&$fd; done
sleep 1
kill "$CAP_PID" 2>/dev/null || true
wait 2>/dev/null || true
say "=== evidence written to $OUT ==="
