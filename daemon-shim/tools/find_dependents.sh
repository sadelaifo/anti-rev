#!/bin/bash
# find_dependents.sh — find all ELFs that directly DT_NEED a given library.
#
# Usage: find_dependents.sh <libname> [search_dir]
#   libname:    bare soname, e.g. "libfoo.so" or "libfoo.so.1"
#   search_dir: directory to scan (default: current dir)

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <libname> [search_dir]" >&2
    exit 1
fi

LIB="$1"
DIR="${2:-.}"

find "$DIR" -type f | while read -r f; do
    # Quick ELF magic check (first 4 bytes: 7f 45 4c 46)
    head -c4 "$f" 2>/dev/null | grep -qP '^\x7fELF' || continue
    # Check DT_NEEDED for exact match
    if readelf -d "$f" 2>/dev/null | grep -q "(NEEDED).*\[$LIB\]"; then
        echo "$f"
    fi
done
