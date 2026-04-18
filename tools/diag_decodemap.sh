#!/usr/bin/env bash
# Diagnose DecodeMap symbol resolution in antirev-encrypted binary.
# Usage:  ./diag_decodemap.sh <bin> [bin args...]
#         LIB_RE=... SYM=... WAIT=... ./diag_decodemap.sh <bin> [args...]
# Example: LIB_RE='libRH(ROE|AXE)' SYM=DecodeMap ./diag_decodemap.sh ./myapp -c config.yaml

set -u

BIN="${1:?usage: $0 <encrypted_bin> [args...]   (env: LIB_RE, SYM, WAIT)}"
shift
LIB_RE="${LIB_RE:-libRH(ROE|AXE)}"
SYM="${SYM:-DecodeMap}"
WAIT="${WAIT:-3}"
LOG=/tmp/antirev_dl_$$.log

[[ -x "$BIN" ]] || { echo "not executable: $BIN" >&2; exit 1; }

echo "=== launching: $BIN $* (dlopen log -> $LOG) ==="
ANTIREV_DLOPEN_LOG="$LOG" "$BIN" "$@" >/tmp/antirev_stdout_$$.log 2>/tmp/antirev_stderr_$$.log &
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
echo "=== $SYM symbol offset in each lib (demangled substring match) ==="
for name in "${!BASE[@]}"; do
    # Prefer map_files path (stable kernel-backed view), fall back to the path from maps
    mf=""
    for m in /proc/$PID/map_files/*; do
        t=$(readlink "$m" 2>/dev/null) || continue
        [[ "$t" == *"$name"* ]] && { mf="$m"; break; }
    done
    src="$mf"
    [[ -z "$src" || ! -r "$src" ]] && src="${PATHS[$name]}"

    # nm -C demangles; match SYM anywhere in the (demangled) name, pick T/t/W/w (defined text/weak)
    mapfile -t hits < <(nm -D -C "$src" 2>/dev/null | \
        awk -v s="$SYM" '$2 ~ /[TtWw]/ && index($0, s) > 0 {print}')

    if [[ ${#hits[@]} -eq 0 ]]; then
        echo "$name  $SYM: NOT FOUND"
        echo "  -- showing any symbols containing the substring (if any) --"
        nm -D -C "$src" 2>/dev/null | grep -i -- "$SYM" | head -10 | sed 's/^/    /'
        echo "  -- first 5 defined T symbols (for sanity) --"
        nm -D -C "$src" 2>/dev/null | awk '$2=="T" {print}' | head -5 | sed 's/^/    /'
        continue
    fi

    echo "$name:"
    for h in "${hits[@]}"; do
        off=$(echo "$h" | awk '{print $1}')
        # strip leading 0s so arithmetic works, but keep as hex
        off_hex=${off##0000000000}
        [[ -z "$off_hex" ]] && off_hex="$off"
        runtime=$(printf '0x%x' $((16#${off} + 16#${BASE[$name]})))
        demangled=$(echo "$h" | awk '{$1=""; $2=""; sub(/^  */,""); print}')
        echo "    offset=0x$off  runtime=$runtime  $demangled"
    done
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
