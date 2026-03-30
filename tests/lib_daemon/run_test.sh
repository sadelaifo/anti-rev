#!/bin/bash
# test_lib_daemon — daemon-mode end-to-end test
#
# Usage: run_test.sh <stub> <dlopen_main> <linked_main> <mylib.so> <liblinkedmath.so>
#
# 1. Builds a daemon binary with both libs
# 2. Builds two client exes (daemon-libs mode)
# 3. Starts daemon, runs both clients, verifies success

set -e

STUB="$1"
DLOPEN_MAIN="$2"
LINKED_MAIN="$3"
MYLIB="$4"
LIBLINKEDMATH="$5"
PROTECT="$(dirname "$0")/../../encryptor/protect.py"
TD="$(dirname "$STUB")/daemon_test"

rm -rf "$TD"
mkdir -p "$TD"

# Build daemon with both libs
python3 "$PROTECT" protect-daemon \
    --stub "$STUB" --key "$TD/daemon.key" \
    --libs "$MYLIB" "$LIBLINKEDMATH" \
    --output "$TD/antirev-libd"

# Build client exes (daemon-libs mode, same key)
python3 "$PROTECT" protect-exe \
    --stub "$STUB" --main "$DLOPEN_MAIN" --key "$TD/daemon.key" \
    --daemon-libs --output "$TD/dlopen.protected"

python3 "$PROTECT" protect-exe \
    --stub "$STUB" --main "$LINKED_MAIN" --key "$TD/daemon.key" \
    --daemon-libs --output "$TD/linked.protected"

# Start daemon
"$TD/antirev-libd" 2>&1
sleep 0.5

cleanup() {
    pkill -f "$TD/antirev-libd" 2>/dev/null || true
}
trap cleanup EXIT

# Run clients
echo "--- dlopen via daemon ---"
"$TD/dlopen.protected"

echo "--- DT_NEEDED via daemon ---"
"$TD/linked.protected"

echo "PASS: lib daemon served both dlopen and DT_NEEDED libs"
