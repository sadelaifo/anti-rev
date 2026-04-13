#!/bin/sh
# Check for duplicate library loading in anti-rev protected processes.
# Duplicate .so loading causes global variable isolation issues
# (e.g., init writes to copy A, read gets NULL from copy B).
#
# Usage: ./check_duplibs.sh <pid>
#        ./check_duplibs.sh <pid> <symbol_name>
#
# Examples:
#   ./check_duplibs.sh 12345
#   ./check_duplibs.sh 12345 g_logGlobalPtTableCp

PID="${1:-}"
SYMBOL="${2:-}"

if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
    echo "Usage: $0 <pid> [symbol_name]"
    echo ""
    echo "  pid          Process ID to check"
    echo "  symbol_name  Optional: grep for specific symbol in loaded libs"
    exit 1
fi

echo "=== Process $PID: $(cat /proc/$PID/cmdline 2>/dev/null | tr '\0' ' ') ==="
echo ""

# Step 1: Find duplicate .so files (same basename loaded from different paths)
echo "--- Checking for duplicate library loading ---"
dup_found=0
cat /proc/$PID/maps 2>/dev/null | grep '\.so' | awk '{print $NF}' | sort -u | while read -r path; do
    basename=$(basename "$path" 2>/dev/null)
    echo "$basename $path"
done | sort | awk '
{
    name = $1
    path = $2
    if (name == prev_name && path != prev_path) {
        if (printed_prev == 0) {
            printf "[DUP] %s\n      -> %s\n", prev_name, prev_path
            printed_prev = 1
        }
        printf "      -> %s\n", path
        found = 1
    } else {
        prev_name = name
        prev_path = path
        printed_prev = 0
    }
}
END {
    if (!found) print "No duplicates found."
}'

echo ""

# Step 2: Show all memfd and antirev-related mappings
echo "--- Anti-rev related mappings (memfd / antirev / proc/self/fd) ---"
cat /proc/$PID/maps 2>/dev/null | grep -E "memfd|antirev|/proc/self/fd" | awk '{print $NF}' | sort -u
echo ""

# Step 3: Show LD_PRELOAD and related env vars
echo "--- Anti-rev environment variables ---"
if [ -r "/proc/$PID/environ" ]; then
    cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | grep -E "^LD_PRELOAD=|^LD_LIBRARY_PATH=|^ANTIREV_"
else
    echo "(cannot read /proc/$PID/environ)"
fi
echo ""

# Step 4: If symbol name provided, search for it in loaded libraries
if [ -n "$SYMBOL" ]; then
    echo "--- Searching for symbol: $SYMBOL ---"
    cat /proc/$PID/maps 2>/dev/null | grep '\.so' | awk '{print $NF}' | sort -u | while read -r lib; do
        [ -f "$lib" ] || continue
        result=$(nm -D "$lib" 2>/dev/null | grep "$SYMBOL")
        if [ -n "$result" ]; then
            echo "  $lib"
            echo "    $result"
        fi
    done
    echo ""
fi

echo "Done."
