#!/bin/bash
# multi_process end-to-end test runner
#
# Usage: run_test.sh <grpc_daemon.protected> <pm.protected> \
#                    <work_process.protected> <encrypted_libwork.so>
#
# Starts grpc_daemon in background, waits for it to bind its socket,
# runs pm (which sends INIT and waits for OK/FAIL), then cleans up.

set -e

GRPC_DAEMON="$1"
PM="$2"
WORK_PROCESS="$3"
LIB_PATH="$4"

if [ -z "$GRPC_DAEMON" ] || [ -z "$PM" ] || [ -z "$WORK_PROCESS" ] || [ -z "$LIB_PATH" ]; then
    echo "usage: run_test.sh <grpc_daemon> <pm> <work_process> <lib>" >&2
    exit 1
fi

SOCK="/tmp/antirev_mp_$$.sock"

cleanup() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    rm -f "$SOCK"
}
trap cleanup EXIT

# Start grpc_daemon in background
"$GRPC_DAEMON" "$SOCK" &
DAEMON_PID=$!

# Wait up to 5 seconds for socket to appear
for i in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done

if [ ! -S "$SOCK" ]; then
    echo "FAIL: grpc_daemon did not create socket within 5s" >&2
    exit 1
fi

# Run PM (blocks until it receives response from grpc_daemon)
"$PM" "$SOCK" "$WORK_PROCESS" "$LIB_PATH"
