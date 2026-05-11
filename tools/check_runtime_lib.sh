#!/usr/bin/env bash
# check_runtime_lib.sh — inspect what the linker actually sees in
# the stub's symlink dir at runtime.
#
# Usage:
#   tools/check_runtime_lib.sh <protected_bin> [libname]
#
# Pass the STUB-wrapped (encrypted) binary you normally run, NOT the
# original unencrypted one — the script needs stub to actually run
# and materialise the symlink dir under /tmp.
#
# Make sure the daemon (lrxd) is up first if your setup needs it,
# otherwise stub will fail before creating the symlink dir.
#
# When set up correctly the linker should find each lib via
# /tmp/<random_prefix>_<pid>_<rand>/<libname.so> and read a valid ELF
# header.  When you hit `error while loading shared libraries: ...:
# invalid ELF header`, run this to see:
#
#   - whether the symlink dir was created
#   - whether the lib has the expected basename in the dir
#   - what SONAME / NEEDED list the decrypted memfd actually carries
#   - what architecture / ELF class the memfd lib is
#
# Mismatch between (lib's SONAME) and (exe's DT_NEEDED string) is the
# most common reason linker rejects a symlinked memfd silently and
# keeps searching — eventually hitting the encrypted on-disk file and
# producing the "invalid ELF header" message.

set -u

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <protected_bin> [libname]" >&2
    echo "  no libname -> inspect every lib in the symlink dir" >&2
    exit 2
fi

BIN=$1
LIBNAME=${2:-}

if [ ! -x "$BIN" ]; then
    echo "not executable: $BIN" >&2
    exit 2
fi

# Run protected bin briefly to materialise the symlink dir.
ANTIREV_LOG=1 "$BIN" >/tmp/run.log 2>&1 &
PID=$!
# 300 ms is enough on most machines for stub to set up symlinks before
# fexecve transfers control to the (failing) business code.
sleep 0.3

# Stub creates /tmp/<prefix><pid>_<XXXXXX>.  Match by PID.
DIR=$(ls -d /tmp/.*_${PID}_* 2>/dev/null | head -1)
if [ -z "$DIR" ]; then
    echo "no symlink dir found for pid $PID -- stub did not create one" >&2
    echo "(or the process exited before sleep finished)" >&2
    echo ""
    echo "--- /tmp/run.log (last 20 lines) ---"
    tail -20 /tmp/run.log
    kill -9 "$PID" 2>/dev/null
    wait 2>/dev/null
    exit 1
fi

echo "===> symlink dir: $DIR"
echo "===> /tmp/run.log first 5 lines"
head -5 /tmp/run.log | sed 's/^/    /'
echo ""

# Inspect one specific lib, or every symlink in the dir.
inspect_lib() {
    lib=$1
    if [ ! -e "$lib" ]; then
        echo "===> $(basename "$lib"): NOT FOUND in symlink dir" >&2
        echo ""
        return
    fi
    echo "===> $(basename "$lib")"
    echo "    symlink -> $(readlink "$lib")"
    echo "    --- readelf -h ---"
    readelf -h "$lib" 2>&1 | grep -E "Class|Data|Machine|Type|OS/ABI" \
        | sed 's/^/    /'
    echo "    --- readelf -d (SONAME + NEEDED) ---"
    readelf -d "$lib" 2>&1 | grep -E "SONAME|NEEDED" | sed 's/^/    /'
    echo ""
}

if [ -n "$LIBNAME" ]; then
    inspect_lib "$DIR/$LIBNAME"
else
    # Plain for-loop over the dir; no mapfile, no process substitution.
    for lib in "$DIR"/*; do
        # Only inspect symlinks (skip the unlikely case of a real file).
        [ -L "$lib" ] || continue
        inspect_lib "$lib"
    done
fi

kill -9 "$PID" 2>/dev/null
wait 2>/dev/null
