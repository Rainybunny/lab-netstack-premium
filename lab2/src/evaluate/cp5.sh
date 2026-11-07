#!/bin/bash

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
OUT=${OUT:?Set OUT to a new evidence directory}
mkdir -p "$OUT"
BIN=${BIN:-$ROOT/build/lab2_demo}
PREFIX=l2cp5
WORK=$(mktemp -d)
NAMES=("${PREFIX}n1" "${PREFIX}n2" "${PREFIX}n3" "${PREFIX}n4" \
       "${PREFIX}n5" "${PREFIX}n6")

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
ip link add ${PREFIX}v25 type veth peer name ${PREFIX}v52
ip link add ${PREFIX}v36 type veth peer name ${PREFIX}v63
ip link add ${PREFIX}v56 type veth peer name ${PREFIX}v65
ip link set ${PREFIX}v12 netns ${PREFIX}n1
ip link set ${PREFIX}v21 netns ${PREFIX}n2
ip link set ${PREFIX}v23 netns ${PREFIX}n2
ip link set ${PREFIX}v32 netns ${PREFIX}n3
ip link set ${PREFIX}v34 netns ${PREFIX}n3
ip link set ${PREFIX}v43 netns ${PREFIX}n4
ip link set ${PREFIX}v25 netns ${PREFIX}n2
ip link set ${PREFIX}v52 netns ${PREFIX}n5
ip link set ${PREFIX}v36 netns ${PREFIX}n3
ip link set ${PREFIX}v63 netns ${PREFIX}n6
ip link set ${PREFIX}v56 netns ${PREFIX}n5
ip link set ${PREFIX}v65 netns ${PREFIX}n6

ip netns exec ${PREFIX}n1 ip addr add 10.100.1.1/24 dev ${PREFIX}v12
ip netns exec ${PREFIX}n2 ip addr add 10.100.1.2/24 dev ${PREFIX}v21
ip netns exec ${PREFIX}n2 ip addr add 10.100.2.1/24 dev ${PREFIX}v23
ip netns exec ${PREFIX}n2 ip addr add 10.100.5.1/24 dev ${PREFIX}v25
ip netns exec ${PREFIX}n3 ip addr add 10.100.2.2/24 dev ${PREFIX}v32
ip netns exec ${PREFIX}n3 ip addr add 10.100.3.1/24 dev ${PREFIX}v34
ip netns exec ${PREFIX}n3 ip addr add 10.100.6.1/24 dev ${PREFIX}v36
ip netns exec ${PREFIX}n4 ip addr add 10.100.3.2/24 dev ${PREFIX}v43
ip netns exec ${PREFIX}n5 ip addr add 10.100.5.2/24 dev ${PREFIX}v52
ip netns exec ${PREFIX}n5 ip addr add 10.100.56.1/24 dev ${PREFIX}v56
ip netns exec ${PREFIX}n6 ip addr add 10.100.6.2/24 dev ${PREFIX}v63
ip netns exec ${PREFIX}n6 ip addr add 10.100.56.2/24 dev ${PREFIX}v65
for ns in "${NAMES[@]}"; do
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.arp_ignore=8
    ip netns exec "$ns" iptables -t filter -I INPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I OUTPUT -j DROP
    ip netns exec "$ns" iptables -t filter -I FORWARD -j DROP
done
for entry in v12:1 v21:2 v23:2 v32:3 v34:3 v43:4 v25:2 v52:5 \
             v36:3 v63:6 v56:5 v65:6; do
    dev=${entry%%:*}
    ns=${entry##*:}
    ip netns exec "${PREFIX}n$ns" ip link set "${PREFIX}$dev" up
done

: > "$OUT/transcript.txt"
say() { echo "$*" | tee -a "$OUT/transcript.txt"; }

mkfifo "$WORK/n1.in" "$WORK/n2.in" "$WORK/n3.in" \
       "$WORK/n4.in" "$WORK/n5.in" "$WORK/n6.in"
for i in 1 2 3 4 5 6; do
    ip netns exec "${PREFIX}n$i" "$BIN" < "$WORK/n$i.in" \
        > "$OUT/ns$i.log" 2>&1 &
done
exec 3>"$WORK/n1.in"
exec 4>"$WORK/n2.in"
exec 5>"$WORK/n3.in"
exec 6>"$WORK/n4.in"
exec 7>"$WORK/n5.in"
exec 8>"$WORK/n6.in"

all_distances() {
    printf 'distances\n' >&3
    printf 'distances\n' >&4
    printf 'distances\n' >&5
    printf 'distances\n' >&6
    printf 'distances\n' >&7
    printf 'distances\n' >&8
    sleep 1
}

sleep 8
say "=== distances before disconnecting ns5 ==="
all_distances

say "=== disconnect ns5 (both links down) ==="
ip netns exec ${PREFIX}n5 ip link set ${PREFIX}v52 down
ip netns exec ${PREFIX}n5 ip link set ${PREFIX}v56 down
sleep 7
say "=== distances after disconnecting ns5 ==="
all_distances

for fd in 3 4 5 6 7 8; do printf 'quit\n' >&$fd; done
sleep 1
wait 2>/dev/null || true
say "=== evidence written to $OUT ==="
