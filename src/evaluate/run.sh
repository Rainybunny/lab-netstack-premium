#!/bin/bash
# Run one Lab 3 checkpoint in private user, mount and network namespaces.
set -eu
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
case ${1:-} in
    cp7|cp8|cp9|cp10|cl1|cl2|cl3|cl4|cl5|cl6|cl7|cl8|cl9|cl10) CP=$1 ;;
    *) echo "usage: $0 cp7..cp10|cl1..cl10 OUTPUT_DIR" >&2; exit 1 ;;
esac
OUT=$(realpath -m "${2:?Specify an output directory}")
mkdir -p "$OUT"
export OUT
export XTABLES_LOCKFILE=${XTABLES_LOCKFILE:-/tmp/xtables.lock}
unshare --user --map-root-user --mount --net --fork bash -eu -c '
    mount --make-rprivate /
    mount -t tmpfs tmpfs /run
    mkdir /run/netns
    exec bash "$1"
' _ "$SCRIPT_DIR/$CP.sh"
