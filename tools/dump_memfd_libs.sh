#!/bin/bash
# dump_memfd_libs — copy all memfd-backed libraries out of a running
# antirev-packed process into a directory, so they can be scanned by
# regular tools (strings, nm, readelf, find_duplicate_proto.sh).
#
# Usage:
#   dump_memfd_libs.sh <pid> [out-dir]
#
# Example:
#   dump_memfd_libs.sh 12345 /tmp/dumped
#   ./tools/find_duplicate_proto.sh myapp.RequestConfig /tmp/dumped

set -u

PID="${1:-}"
OUT="${2:-/tmp/antirev_memfd_dump_$$}"

if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
    echo "usage: $0 <pid> [out-dir]" >&2
    exit 1
fi

mkdir -p "$OUT"

# Walk /proc/<pid>/fd and pick out memfd entries. readlink on a memfd
# returns "/memfd:<name> (deleted)" — we parse that to get the name.
count=0
for fd_link in /proc/$PID/fd/*; do
    [ -L "$fd_link" ] || continue
    target=$(readlink "$fd_link" 2>/dev/null) || continue
    case "$target" in
        /memfd:*)
            # Extract original name (strip "/memfd:" prefix and " (deleted)" suffix)
            name="${target#/memfd:}"
            name="${name% (deleted)}"
            # Sanitize name for filesystem
            safe=$(echo "$name" | tr -c 'A-Za-z0-9._-' '_')
            fd_num=$(basename "$fd_link")
            out_file="$OUT/${safe}.fd${fd_num}"
            if cp "$fd_link" "$out_file" 2>/dev/null; then
                count=$((count+1))
                printf '  dumped fd=%-3s  %s  ->  %s\n' "$fd_num" "$name" "$(basename "$out_file")"
            fi
            ;;
    esac
done

echo
echo "dumped $count memfd(s) into $OUT"
echo
echo "next:"
echo "  ./tools/find_duplicate_proto.sh <message.full.name> $OUT"
