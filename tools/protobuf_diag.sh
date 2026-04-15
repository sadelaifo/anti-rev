#!/bin/bash
# protobuf_diag — collect evidence for "json transcoder produced invalid
# protobuf output" failures seen after antirev packing.
#
# Usage:
#   diag.sh <pid>              # attach to a running (broken) process
#   diag.sh --bin <cmd...>     # run <cmd> under diag, attach once it sleeps
#
# Outputs to stderr. Does NOT modify anything. Run on the aarch64 target.
#
# What it collects:
#   1. All loaded libprotobuf* mappings (expect exactly 1 file-backed copy;
#      any memfd:libprotobuf or second disk path = smoking gun).
#   2. gdb batch dump of DescriptorPool::generated_pool() return value
#      AND of every DSO's own copy of that static (if duplicated).
#   3. For each loaded business .so: whether it has an UNDEFINED reference
#      to libprotobuf symbols (= PLT, good) or defines them itself (= static
#      link, potential duplicate).
#   4. dladdr of generated_pool() to see which DSO actually owns it.
#
# Interpretation guide at the bottom of the script.

set -u

PID=""
if [ "${1:-}" = "--bin" ]; then
    shift
    "$@" &
    PID=$!
    sleep 0.5
elif [ -n "${1:-}" ]; then
    PID="$1"
else
    echo "usage: $0 <pid> | --bin <cmd...>" >&2
    exit 1
fi

if [ ! -d "/proc/$PID" ]; then
    echo "FAIL: pid $PID not running" >&2
    exit 1
fi

echo "=== [1] libprotobuf mappings in /proc/$PID/maps ==="
grep -E 'protobuf|memfd.*proto' "/proc/$PID/maps" | awk '{print $NF}' | sort -u
echo
echo "--- any memfd-backed protobuf? ---"
grep -E 'memfd.*protobuf|protobuf.*deleted' "/proc/$PID/maps" || echo "(none — good)"
echo
echo "--- count of distinct libprotobuf files ---"
grep -oE '/[^ ]*libprotobuf[^ ]*\.so[^ ]*' "/proc/$PID/maps" | sort -u | tee /tmp/diag_pb_files.$$
N=$(wc -l < /tmp/diag_pb_files.$$)
echo "N=$N  (expect 1; >1 = duplicate)"
rm -f /tmp/diag_pb_files.$$
echo

echo "=== [2] static/dynamic linkage of protobuf in each loaded business .so ==="
# Every file-backed .so under the process, minus system libs.
grep -oE '/[^ ]*\.so[^ ]*' "/proc/$PID/maps" | sort -u | while read -r so; do
    [ -r "$so" ] || continue
    case "$so" in
        */libc.so*|*/ld-*|*/libm.so*|*/libpthread*|*/libdl*|*/libgcc*|*/libstdc++*)
            continue ;;
    esac
    # Does this .so DEFINE protobuf symbols (T/D/B = own copy, static-linked)?
    defs=$(nm -D --defined-only "$so" 2>/dev/null \
           | grep -cE ' [TDBR] .*(DescriptorPool|generated_pool|InternalAddGeneratedFile|MessageFactory)' \
           || true)
    # Or does it just REFER to them via PLT (U = undefined, dynamic link)?
    undefs=$(nm -D --undefined-only "$so" 2>/dev/null \
             | grep -cE '(DescriptorPool|generated_pool|InternalAddGeneratedFile)' \
             || true)
    if [ "$defs" != "0" ] || [ "$undefs" != "0" ]; then
        printf '  %-60s  defs=%s  undefs=%s\n' "$(basename "$so")" "$defs" "$undefs"
    fi
done
echo "  (defs>0 AND that .so is NOT libprotobuf itself  =>  static-linked duplicate)"
echo

echo "=== [3] gdb: address of generated_pool() and who owns it ==="
if ! command -v gdb >/dev/null; then
    echo "SKIP: gdb not installed"
else
    gdb -batch -p "$PID" \
        -ex 'set pagination off' \
        -ex 'set print address on' \
        -ex 'p (void*)google::protobuf::DescriptorPool::generated_pool()' \
        -ex 'p (void*)google::protobuf::MessageFactory::generated_factory()' \
        -ex 'info symbol (void*)google::protobuf::DescriptorPool::generated_pool()' \
        -ex 'info shared' 2>&1 \
        | grep -E '^\$|generated_pool|libprotobuf|memfd' \
        || echo "(gdb returned nothing — symbols stripped?)"
fi
echo

echo "=== [4] interpretation ==="
cat <<'EOF'
  - If [1] shows >1 libprotobuf OR any memfd-backed protobuf:
      => duplicate libprotobuf loaded. Fix: ensure libprotobuf is loaded
         exactly once (exclude from encryption, or daemon preload with
         RTLD_GLOBAL and make sure l_name dedup hits).

  - If [1] shows exactly 1 libprotobuf AND [2] lists a business .so with
    defs>0 (e.g. libFoo.so defs=5 undefs=0):
      => that .so statically linked protobuf generated code. It has its
         OWN copy of generated_pool static data. RTLD_LOCAL vs GLOBAL
         WILL NOT fix this on its own — the duplicate is by-value, not
         by-reference. Real fix: rebuild that .so to dynamically link
         libprotobuf (or exclude it from encryption so its static copy
         is also normalized on disk).

  - If [1]=1 AND [2] only shows undefs>0 (pure PLT references) AND the
    bug still happens:
      => not a pool duplication issue at all. Look elsewhere:
         * ctor ordering (exe_shim runs late — DT_NEEDED global ctors
           may see partially-initialized libprotobuf state)
         * descriptor pool built from .desc file vs generated pool
         * gRPC transcoder using a different DescriptorPool instance
      Capture the exact error-emitting stack with:
         gdb -p <pid> -ex 'b *<transcoder err fn>' -ex c

  - If [3] prints two different addresses for generated_pool() when
    called from different DSOs (advanced: needs per-DSO breakpoints):
      => confirmed split pool. See case 2.
EOF

# If we spawned the binary, clean up.
if [ -n "${!:-}" ] && kill -0 "$PID" 2>/dev/null && [ "${1:-}" = "--bin" ]; then
    kill "$PID" 2>/dev/null || true
fi
