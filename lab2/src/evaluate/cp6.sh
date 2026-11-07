#!/bin/bash

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
OUT=${OUT:?Set OUT to a new evidence directory}
mkdir -p "$OUT"
BIN=${BIN:-$ROOT/build/lab2_demo}
CAP=$SCRIPT_DIR/capture.py
PREFIX=l2cp6
WORK=$(mktemp -d)
NS1=${PREFIX}n1
NS2=${PREFIX}n2

cleanup() {
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "missing binary: $BIN" >&2; exit 1; }

ip netns add "$NS1"
ip netns add "$NS2"
ip link add ${PREFIX}v12 type veth peer name ${PREFIX}v21
ip link set ${PREFIX}v12 netns "$NS1"
ip link set ${PREFIX}v21 netns "$NS2"
ip netns exec "$NS1" ip addr add 10.100.1.1/24 dev ${PREFIX}v12
ip netns exec "$NS2" ip addr add 10.100.1.2/24 dev ${PREFIX}v21
ip netns exec "$NS1" ip link set lo up
ip netns exec "$NS2" ip link set lo up
ip netns exec "$NS1" ip link set ${PREFIX}v12 up
ip netns exec "$NS2" ip link set ${PREFIX}v21 up
for ns in "$NS1" "$NS2"; do
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.arp_ignore=8
    ip netns exec "$ns" iptables -t filter -I INPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I OUTPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I FORWARD -j DROP
done

: > "$OUT/transcript.txt"
say() { echo "$*" | tee -a "$OUT/transcript.txt"; }

mkfifo "$WORK/n1.in"
ip netns exec "$NS1" python3 -I "$CAP" ${PREFIX}v12 "$OUT/ns1.pcap" \
    --seconds 14 &
CAP_PID=$!
ip netns exec "$NS1" "$BIN" < "$WORK/n1.in" > "$OUT/ns1.log" 2>&1 &
P1=$!
exec 3>"$WORK/n1.in"

sleep 3
say "=== before installing the /25 route ==="
printf 'lookup 10.100.1.200\n' >&3
sleep 1
say "=== install 10.100.1.128/25 via a dummy MAC ==="
printf 'setroute 10.100.1.128 255.255.255.128 02:00:00:00:00:01 %sv12\n' \
    "$PREFIX" >&3
sleep 1
say "=== lookup inside and outside the /25 ==="
printf 'lookup 10.100.1.200\n' >&3
printf 'lookup 10.100.1.100\n' >&3
say "=== data path: ping 10.100.1.200 uses the static next hop ==="
printf 'ping 10.100.1.200 1\n' >&3
sleep 3
printf 'quit\n' >&3
sleep 1

kill "$CAP_PID" 2>/dev/null || true
wait "$P1" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
say "=== evidence written to $OUT ==="
