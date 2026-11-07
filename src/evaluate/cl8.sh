#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl8
TRANSCRIPT=$OUT/cl8.txt
: > "$TRANSCRIPT"

N1=${PREFIX}c8n1
N2=${PREFIX}c8n2
V12=${PREFIX}c8v12
V21=${PREFIX}c8v21
ORIGIN_PID=
PROXY_PID=
CAP_PID=

cleanup() {
    [ -n "$ORIGIN_PID" ] && kill "$ORIGIN_PID" 2>/dev/null || true
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
    del_ns "$N1" "$N2"
}
trap cleanup EXIT

say "=== CL8: HTTP proxy built atop the user-space TCP stack ==="
say "topology: $N1 (proxy + browser) --- $N2 (origin)"
say "browser side: kernel loopback 127.0.0.1:8080"
say "origin side: user-space TCP to 10.140.1.2:80"
say ""

make_ns "$N1" "$N2"
ip link add "$V12" type veth peer name "$V21"
ip link set "$V12" netns "$N1"
ip link set "$V21" netns "$N2"
ip netns exec "$N1" ip addr add 10.140.1.1/24 dev "$V12"
ip netns exec "$N2" ip addr add 10.140.1.2/24 dev "$V21"
for binding in "$N1 $V12" "$N2 $V21"; do
    set -- $binding
    ip netns exec "$1" ip link set lo up
    ip netns exec "$1" sysctl -qw net.ipv4.conf.all.arp_ignore=8
    ip netns exec "$1" iptables -t filter -A INPUT -i "$2" -j DROP
    ip netns exec "$1" iptables -t filter -A OUTPUT -o "$2" -j DROP
done
ip netns exec "$N1" ip link set "$V12" up
ip netns exec "$N2" ip link set "$V21" up

CAP_PID=$(start_capture "$N1" "$V12" "$OUT/cl8.pcap" 25)
ip netns exec "$N2" stdbuf -oL -eL "$BIN/http_origin" 80 \
    > "$OUT/cl8-origin.log" 2>&1 &
ORIGIN_PID=$!
say "waiting 5 s for link-state convergence"
sleep 5
ip netns exec "$N1" stdbuf -oL -eL "$BIN/http_proxy" 8080 10.140.1.2 80 \
    > "$OUT/cl8-proxy.log" 2>&1 &
PROXY_PID=$!
sleep 1

W3M=${W3M:-/tmp/browser/usr/bin/w3m}
if [ -x "$W3M" ]; then
    W3M_PREFIX=$(cd "$(dirname "$W3M")/.." && pwd)
    say "browser: $W3M (text browser)"
    ip netns exec "$N1" env \
        LD_LIBRARY_PATH="$W3M_PREFIX/lib/x86_64-linux-gnu" \
        timeout 20 "$W3M" -dump -o http_proxy=http://127.0.0.1:8080 \
        http://10.140.1.2/ > "$OUT/cl8-browser.log" 2>&1 ||
        say "browser exit $?"
else
    say "browser: w3m not found, falling back to curl"
    ip netns exec "$N1" timeout 20 curl -s -x http://127.0.0.1:8080 \
        http://10.140.1.2/ > "$OUT/cl8-browser.log" 2>&1 ||
        say "curl exit $?"
fi
sleep 1
kill "$PROXY_PID" "$ORIGIN_PID" 2>/dev/null || true
PROXY_PID=
ORIGIN_PID=
sleep 1

say "=== browser output ==="
cat "$OUT/cl8-browser.log" | tee -a "$TRANSCRIPT"
say ""
say "=== proxy output ==="
grep -v '^LINKSTATE' "$OUT/cl8-proxy.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== origin output ==="
grep -v '^LINKSTATE' "$OUT/cl8-origin.log" | tee -a "$TRANSCRIPT" || true
say ""
say "=== TCP connection on the stack side ==="
python3 -I "$SCRIPT_DIR/retrans.py" "$OUT/cl8.pcap" | tee -a "$TRANSCRIPT"
