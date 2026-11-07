#!/bin/bash

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
OUT=${OUT:?Set OUT to a new evidence directory}
mkdir -p "$OUT"
BIN=${BIN:-$ROOT/build/lab2_demo}
CAP=$SCRIPT_DIR/capture.py
NS1=l2cp3n1
NS2=l2cp3n2
LINK1=l2cp3v12
LINK2=l2cp3v21
WORK=$(mktemp -d)

cleanup() {
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    ip link del "$LINK1" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "missing binary: $BIN" >&2; exit 1; }

ip netns add "$NS1"
ip netns add "$NS2"
ip link add "$LINK1" type veth peer name "$LINK2"
ip link set "$LINK1" netns "$NS1"
ip link set "$LINK2" netns "$NS2"
ip netns exec "$NS1" ip addr add 10.100.1.1/24 dev "$LINK1"
ip netns exec "$NS2" ip addr add 10.100.1.2/24 dev "$LINK2"
ip netns exec "$NS1" ip link set lo up
ip netns exec "$NS2" ip link set lo up
ip netns exec "$NS1" ip link set "$LINK1" up
ip netns exec "$NS2" ip link set "$LINK2" up
for ns in "$NS1" "$NS2"; do
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.arp_ignore=8
    ip netns exec "$ns" iptables -t filter -I INPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I OUTPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I FORWARD -j DROP
done

mkfifo "$WORK/n1.in" "$WORK/n2.in"
ip netns exec "$NS1" python3 -I "$CAP" "$LINK1" "$OUT/cp3.pcap" \
    --seconds 14 &
CAP_PID=$!
ip netns exec "$NS1" "$BIN" < "$WORK/n1.in" > "$OUT/ns1.log" 2>&1 &
P1=$!
ip netns exec "$NS2" "$BIN" < "$WORK/n2.in" > "$OUT/ns2.log" 2>&1 &
P2=$!
exec 3>"$WORK/n1.in"
exec 4>"$WORK/n2.in"

sleep 3
printf 'ping 10.100.1.2 3\n' >&3
sleep 4
printf 'quit\n' >&3
printf 'quit\n' >&4
sleep 1

kill "$CAP_PID" 2>/dev/null || true
wait "$P1" "$P2" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
echo "wrote $OUT/cp3.pcap and ns logs"
