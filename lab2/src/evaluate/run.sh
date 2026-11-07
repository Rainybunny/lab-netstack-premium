#!/bin/bash
# Run one checkpoint in private user, mount and network namespaces.
set -eu
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
case ${1:-} in
    cp3|cp4|cp5|cp6) CP=$1 ;;
    *) echo "usage: $0 cp3|cp4|cp5|cp6 NEW_OUTPUT_DIR" >&2; exit 1 ;;
esac
OUT=$(realpath -m "${2:?Specify a new output directory}")
mkdir "$OUT"
export OUT
unshare --user --map-root-user --mount --net --fork bash -eu -c '
    mount --make-rprivate /
    mount -t tmpfs tmpfs /run
    mkdir /run/netns
    exec bash "$1"
' _ "$SCRIPT_DIR/$CP.sh"
