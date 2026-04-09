#!/bin/bash
# find_dependents.sh — find all ELFs that directly DT_NEED a given library.
#
# Usage: find_dependents.sh <libname> [search_dir] [jobs]
#   libname:    bare soname, e.g. "libfoo.so" or "libfoo.so.1"
#   search_dir: directory to scan (default: current dir)
#   jobs:       parallelism (default: nproc)

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <libname> [search_dir] [jobs]" >&2
    exit 1
fi

LIB="$1"
DIR="${2:-.}"
JOBS="${3:-$(nproc 2>/dev/null || echo 4)}"

_check() {
    local f="$1" lib="$2"
    readelf -d "$f" 2>/dev/null | grep -q "(NEEDED).*\[$lib\]" && echo "$f"
    return 0
}
export -f _check

# Find ELF files by magic bytes, then check DT_NEEDED in parallel.
# grep -rl filters to files containing \x7fELF in the first 4 bytes,
# much faster than spawning head+grep per file.
find "$DIR" -type f -print0 \
    | xargs -0 -P "$JOBS" -n 64 grep -lZ $'\x7fELF' -- 2>/dev/null \
    | xargs -0 -P "$JOBS" -I{} bash -c '_check "$@"' _ {} "$LIB"
