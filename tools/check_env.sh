#!/bin/sh
# Check anti-rev environment state for a running process.
# Usage: ./check_env.sh <pid_or_name>
# Example: ./check_env.sh WAP
#          ./check_env.sh 12345

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <pid_or_name>"
    exit 1
fi

# Resolve PID from name if needed
if echo "$TARGET" | grep -q '^[0-9]*$'; then
    PID="$TARGET"
else
    PID=$(ps -eo pid,comm --no-headers 2>/dev/null | grep -w "$TARGET" | awk '{print $1}' | head -1)
    if [ -z "$PID" ]; then
        PID=$(ps -ef 2>/dev/null | grep "$TARGET" | grep -v grep | awk '{print $2}' | head -1)
    fi
fi

if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
    echo "Process not found: $TARGET"
    exit 1
fi

echo "=== Process $PID ==="
echo ""

# 1. Anti-rev environment variables
echo "--- Environment Variables ---"
if [ -r "/proc/$PID/environ" ]; then
    echo "LD_PRELOAD:"
    cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | grep "^LD_PRELOAD=" || echo "  (not set)"
    echo ""
    echo "LD_LIBRARY_PATH:"
    cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | grep "^LD_LIBRARY_PATH=" || echo "  (not set)"
    echo ""
    echo "ANTIREV vars:"
    cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | grep "^ANTIREV" || echo "  (none)"
else
    echo "  (cannot read environ)"
fi
echo ""

# 2. Open file descriptors
echo "--- File Descriptors ---"
fd_count=$(ls /proc/$PID/fd 2>/dev/null | wc -l)
echo "Total open fds: $fd_count"
echo "Memfd fds:"
ls -la /proc/$PID/fd 2>/dev/null | grep memfd || echo "  (none)"
echo "Antirev fds:"
ls -la /proc/$PID/fd 2>/dev/null | grep antirev || echo "  (none)"
echo ""

# 3. Memory maps
echo "--- Anti-rev Memory Maps ---"
cat /proc/$PID/maps 2>/dev/null | grep -E "memfd|antirev|/proc/self/fd" || echo "  (none)"
echo ""

# 4. Test popen/date from this process's env
echo "--- popen test (simulated) ---"
if [ -r "/proc/$PID/environ" ]; then
    # Extract env and run date +%z with it
    env_file=$(mktemp /tmp/antirev_env_XXXXXX)
    cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' > "$env_file"
    result=$(env -i sh -c ". $env_file 2>/dev/null; date +%z" 2>/dev/null)
    echo "date +%z with process env: [$result]"
    rm -f "$env_file"
else
    echo "  (cannot read environ)"
fi
echo ""

echo "Done."
