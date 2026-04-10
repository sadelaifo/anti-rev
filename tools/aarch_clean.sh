#!/bin/sh
# Kill old protected binary instances running under QEMU user-mode via anti-rev.
# Under anti-rev + QEMU, "ps -ef" shows "qemu-aarch64-static /proc/self/fd/<N>"
# but exe_shim sets the comm name via prctl(PR_SET_NAME), so we can find
# the process by comm name or by the QEMU cmdline pattern.

# Usage: ./aarch_clean.sh [binary_comm_name]
# Example: ./aarch_clean.sh DophiServer

COMM_NAME="${1:-}"

if [ -n "$COMM_NAME" ]; then
    # Kill by comm name (set by exe_shim's prctl(PR_SET_NAME))
    pkill -x "$COMM_NAME" && echo "Killed $COMM_NAME" || echo "No $COMM_NAME found"
else
    # Kill all QEMU anti-rev instances by cmdline pattern
    pkill -f "/proc/self/fd/" && echo "Killed old instance" || echo "No instance found"
fi
