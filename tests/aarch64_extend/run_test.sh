#!/bin/bash
# Drive the aarch64_extend_shim end-to-end test.
#
# Strategy: open a sentinel "PG blob" file as a numbered fd in this
# shell, then exec the test binary so the fd inherits across.  Set
# ANTIREV_FD_MAP="fake.elf=<that fd>" so the shim's eager-mode resolve
# returns the inherited fd; ANTIREV_MAIN_FD presence makes the shim's
# owner-detection short-circuit succeed (we are not actually a memfd
# process); LD_PRELOAD pulls the shim into the test binary.

set -eu

if [ "${1:-}" = "" ] || [ ! -x "$1" ]; then
    echo "usage: $0 <build-dir>" >&2
    exit 2
fi
BUILD_DIR="$1"

TEST_BIN="$BUILD_DIR/test_aarch64_extend_bin"
SHIM="$BUILD_DIR/aarch64_extend_shim.so"
LIBREAL_DIR="$BUILD_DIR"

for f in "$TEST_BIN" "$SHIM" "$LIBREAL_DIR/libreal_anti.so"; do
    if [ ! -f "$f" ]; then
        echo "[run_test] missing artefact: $f" >&2
        exit 2
    fi
done

# Cross-arch hosts (e.g. x86 with QEMU) skip cleanly.
if [ "$(uname -m)" != "aarch64" ]; then
    echo "[run_test] host is $(uname -m), aarch64_extend test skipped"
    exit 0
fi

# Sentinel file the "real" ANTI_LoadProcess will read after the shim
# rewrites info->ltrBin to /proc/self/fd/<N>.
BLOB="$(mktemp -t aarch64_extend_blob.XXXXXX)"
trap 'rm -f "$BLOB"' EXIT
printf 'PG_BLOB_OK\n' > "$BLOB"

# Open as fd 9 in this shell, hand it to the test via env.
exec 9<"$BLOB"

ANTIREV_FD_MAP="fake.elf=9" \
ANTIREV_ENC_LIBS="fake.elf" \
ANTIREV_MAIN_FD="9" \
LD_PRELOAD="$SHIM" \
LD_LIBRARY_PATH="$LIBREAL_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
"$TEST_BIN"
