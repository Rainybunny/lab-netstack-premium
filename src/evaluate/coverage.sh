#!/bin/bash
# Build the stack with gcov instrumentation, run the unit tests, and turn
# the .gcov files into an HTML report.
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
OUT=${OUT:?Set OUT to an evidence directory}
BUILD=$ROOT/build/coverage
mkdir -p "$OUT"

rm -rf "$BUILD"
cmake -S "$ROOT" -B "$BUILD" -DNETSTACK_COVERAGE=ON \
    -DCMAKE_BUILD_TYPE=Debug >/dev/null
cmake --build "$BUILD" -j4 >/dev/null
"$BUILD/unit_tests" > "$OUT/cl9-tests.txt" 2>&1 || true

if [ "${COVERAGE_E2E:-1}" != "0" ]; then
    BIN="$BUILD" OUT="$OUT" PREFIX="${PREFIX:-l3}" \
        bash "$SCRIPT_DIR/coverage_e2e.sh"
    echo "=== end-to-end coverage workload ==="
    grep -v '^LINKSTATE' "$OUT/cl10-e2e.log" || true
fi

cd "$BUILD/CMakeFiles/netstack.dir/src"
rm -f ./*.gcov
gcov -b -c ./*.gcno > "$OUT/gcov-raw.txt" 2>&1 || true
python3 -I "$SCRIPT_DIR/coverage_report.py" "$OUT" .
