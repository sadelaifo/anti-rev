#!/bin/sh
# Kill old protected binary instances running under QEMU user-mode via anti-rev.
# Under anti-rev, the process appears as "qemu-aarch64-static /proc/self/fd/<N>"
# instead of the binary's own name, so normal process cleanup won't find it.

pkill -f "/usr/bin/qemu-aarch64-static /proc/self/fd/" && echo "Killed old instance" || echo "No instance found"
