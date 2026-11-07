#!/bin/bash
# Shared helpers for the Lab 3 checkpoint scripts. Source this file.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BIN=${BIN:-$ROOT/build}
CAP=$ROOT/src/evaluate/capture.py
OUT=${OUT:?Set OUT to an evidence directory}
PREFIX=${PREFIX:-l3}
TRANSCRIPT=${TRANSCRIPT:-$OUT/transcript.txt}
export XTABLES_LOCKFILE=${XTABLES_LOCKFILE:-/tmp/xtables.lock}

mkdir -p "$OUT"

say() {
    echo "$*" | tee -a "$TRANSCRIPT"
}

make_ns() {
    local name
    for name in "$@"; do
        ip netns add "$name"
    done
}

del_ns() {
    local name
    for name in "$@"; do
        ip netns del "$name" 2>/dev/null || true
    done
}

isolate() {
    local name
    for name in "$@"; do
        ip netns exec "$name" ip link set lo up
        ip netns exec "$name" sysctl -qw net.ipv4.conf.all.arp_ignore=8
        ip netns exec "$name" iptables -t filter -I INPUT -j DROP
        ip netns exec "$name" iptables -t filter -I OUTPUT -j DROP
        ip netns exec "$name" iptables -t filter -I FORWARD -j DROP
    done
}

start_capture() {
    local ns=$1 iface=$2 file=$3 seconds=$4
    # Keep the capture's stdout away from the caller's command-substitution
    # pipe; otherwise $(start_capture ...) waits for the capture to exit.
    ip netns exec "$ns" python3 -I "$CAP" "$iface" "$file" \
        --seconds "$seconds" >/dev/null 2>&1 &
    echo $!
}
