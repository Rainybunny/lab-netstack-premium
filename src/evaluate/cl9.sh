#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/lab3lib.sh"

CP=cl9
TRANSCRIPT=$OUT/cl9.txt
: > "$TRANSCRIPT"

say "=== CL9: unit tests ==="
say "the tests cover IPv4 checksums, TCP checksums (including odd lengths),"
say "sequence-number wrap arithmetic, routing lookup, getaddrinfo and IPv4"
say "reassembly. They run without pcap devices."
say ""

"$BIN/unit_tests" 2>&1 | tee -a "$TRANSCRIPT"
