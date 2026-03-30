#!/bin/bash
# Stress test: launch N protected workers concurrently.
# All race to create/connect to the lib daemon.
set -e

BINARY="$1"
N="${2:-10}"

echo "=== concurrent_daemon: launching $N workers ==="

# Launch all workers in background
pids=""
for i in $(seq 1 "$N"); do
    "$BINARY" &
    pids="$pids $!"
done

# Wait for all and collect exit codes
fail=0
for pid in $pids; do
    if ! wait "$pid"; then
        echo "FAIL: worker pid=$pid exited non-zero"
        fail=$((fail + 1))
    fi
done

# Clean up daemon
pkill -f "$(basename "$BINARY")" 2>/dev/null || true
sleep 0.2

if [ "$fail" -eq 0 ]; then
    echo "PASS: concurrent_daemon ($N workers, 0 failures)"
    exit 0
else
    echo "FAIL: $fail/$N workers failed"
    exit 1
fi
