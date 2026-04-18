#!/usr/bin/env bash
# Diagnose DecodeMap symbol resolution in antirev-encrypted binary.
# Usage:  ./diag_decodemap.sh ./加密bin [lib_regex] [symbol]
# Example: ./diag_decodemap.sh ./myapp 'libRH(ROE|AXE)' DecodeMap

set -u

BIN="${1:?usage: $0 <encrypted_bin> [lib_regex] [symbol]}"
LIB_RE="${2:-libRH(ROE|AXE)}"
SYM="${3:-DecodeMap}"
LOG=/tmp/antirev_dl_$$.log
WAIT=3

[[ -x "$BIN" ]] || { echo "not executable: $BIN" >&2; exit 1; }

echo "=== launching: $BIN (dlopen log -> $LOG) ==="
ANTIREV_DLOPEN_LOG="$LOG" "$BIN" >/tmp/antirev_stdout_$$.log 2>/tmp/antirev_stderr_$$.log &
PID=$!
sleep "$WAIT"

if ! kill -0 "$PID" 2>/dev/null; then
    echo "process exited early. stderr:"
    cat /tmp/antirev_stderr_$$.log
    exit 1
fi

echo
echo "=== stub startup log (relevant lines) ==="
grep -E 'split|compat|DT_NEEDED|symlink dir|enc libs' /tmp/antirev_stderr_$$.log || echo "(no antirev log lines)"

echo
echo "=== /proc/$PID/maps entries matching $LIB_RE ==="
grep -E "$LIB_RE" "/proc/$PID/maps" | awk '{print $1, $2, $NF}' | sort -u

echo
echo "=== base address of each matching lib (first r-xp segment) ==="
declare -A BASE
declare -A PATHS
while IFS= read -r line; do
    name=$(basename "${line##* }")
    # only the first occurrence of that basename (that's the lowest address)
    [[ -n "${BASE[$name]:-}" ]] && continue
    range=$(echo "$line" | awk '{print $1}')
    start=${range%%-*}
    BASE[$name]="$start"
    PATHS[$name]="${line##* }"
    echo "$name  base=0x$start  path=${PATHS[$name]}"
done < <(grep -E "$LIB_RE" "/proc/$PID/maps" | awk '$2 ~ /x/ {print}')

echo
echo "=== $SYM symbol offset in each lib (from in-memory image) ==="
for name in "${!BASE[@]}"; do
    # Prefer map_files path (stable kernel-backed view), fall back to /proc/PID/root + original path
    mf=""
    for m in /proc/$PID/map_files/*; do
        t=$(readlink "$m" 2>/dev/null) || continue
        [[ "$t" == *"$name"* ]] && { mf="$m"; break; }
    done
    if [[ -n "$mf" ]]; then
        off=$(nm -D "$mf" 2>/dev/null | awk -v s="$SYM" '$3==s && $2 ~ /[Tt]/ {print $1; exit}')
    else
        off=""
    fi
    if [[ -z "$off" ]]; then
        # fallback: nm on the path from maps (may be /proc/self/fd/N — won't resolve from outside)
        off=$(nm -D "${PATHS[$name]}" 2>/dev/null | awk -v s="$SYM" '$3==s && $2 ~ /[Tt]/ {print $1; exit}')
    fi
    if [[ -n "$off" ]]; then
        # compute runtime VA = base + offset (subtract lowest loadable vaddr if PIE — for most .so it's 0)
        runtime=$(printf '0x%x' $((0x${BASE[$name]} + 0x$off)))
        echo "$name  offset=0x$off  runtime_addr=$runtime"
    else
        echo "$name  $SYM: NOT FOUND (lib may not export it, or nm couldn't read the image)"
    fi
done

echo
echo "=== any dlopen of matching libs via dlopen_shim ==="
if [[ -s "$LOG" ]]; then
    grep -E "$LIB_RE" "$LOG" || echo "(no dlopen events for matching libs)"
else
    echo "(no dlopen log produced — ANTIREV_DLOPEN_LOG not honored, or no dlopen traffic)"
fi

echo
echo "=== other loaded .so that export $SYM (scope check) ==="
awk '$2 ~ /x/ && /\.so/ {print $NF}' "/proc/$PID/maps" | awk '!seen[$0]++' | while read -r so; do
    [[ -r "$so" ]] || continue
    nm -D "$so" 2>/dev/null | awk -v s="$SYM" '$3==s && $2 ~ /[Tt]/ {found=1} END{exit !found}' \
        && echo "  $so exports $SYM"
done

echo
echo "=== cleanup ==="
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
rm -f /tmp/antirev_stdout_$$.log /tmp/antirev_stderr_$$.log
echo "dlopen log kept at: $LOG"
