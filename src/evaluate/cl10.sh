#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
OUT=${OUT:?Set OUT to an evidence directory}
mkdir -p "$OUT"

bash "$SCRIPT_DIR/coverage.sh" 2>&1 | tee "$OUT/cl10.txt"
echo "HTML report: $OUT/cl10-coverage.html" | tee -a "$OUT/cl10.txt"
