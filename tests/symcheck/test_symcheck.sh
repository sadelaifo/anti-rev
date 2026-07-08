#!/usr/bin/env bash
#
# Self-contained proof that dlsym_intercept.so + symdiff.py detect a dlsym
# ownership flip (and do NOT false-positive on a stable specific-handle
# lookup).  No daemon / no encryption needed: the flip is produced by loading
# the same two libs in a different ORDER, which is exactly the kind of change
# memfd+daemon loading can introduce and that LD_DEBUG=bindings cannot see.
#
# Usage: test_symcheck.sh <work_dir> <src_root>
set -u

WORK="${1:?work dir}"
SRC="${2:?src root}"
CC="${CC:-gcc}"

fail() { echo "FAIL: $*"; exit 1; }

mkdir -p "$WORK" || fail "mkdir $WORK"
cd "$WORK" || fail "cd $WORK"

# ---- build ---------------------------------------------------------------
$CC -shared -fPIC -O2 -D_GNU_SOURCE \
    -o dlsym_intercept.so "$SRC/tools/symcheck/dlsym_intercept.c" -ldl \
    || fail "build interceptor"
$CC -shared -fPIC -O2 -Wl,-soname,libone.so \
    -o libone.so "$SRC/tests/symcheck/libone.c" || fail "build libone.so"
$CC -shared -fPIC -O2 -Wl,-soname,libtwo.so \
    -o libtwo.so "$SRC/tests/symcheck/libtwo.c" || fail "build libtwo.so"
$CC -O2 -D_GNU_SOURCE -o driver "$SRC/tests/symcheck/driver.c" -ldl \
    || fail "build driver"

# ---- run: PLAIN loads one-then-two, ENC loads two-then-one ---------------
run() { # $1 log  $2 first  $3 second
    LD_PRELOAD=./dlsym_intercept.so ANTIREV_DLSYM_LOG="$1" \
        ./driver "$2" "$3" ./libone.so >/dev/null 2>&1 \
        || fail "driver run for $1"
}
run plain.log ./libone.so ./libtwo.so
run enc.log   ./libtwo.so ./libone.so

echo "--- plain.log ---"; cat plain.log
echo "--- enc.log ---";   cat enc.log

# ---- diff ----------------------------------------------------------------
# symdiff.py exits 1 when it finds a flip; capture output regardless.
out="$(python3 "$SRC/tools/symcheck/symdiff.py" plain.log enc.log)" || true
echo "--- symdiff ---"; echo "$out"

# ---- assertions ----------------------------------------------------------
# 1. The RTLD_DEFAULT lookup of "who" MUST be reported as an ownership flip.
echo "$out" | grep -q "DEFAULT symbol=who" \
    || fail "did not detect the DEFAULT dlsym ownership flip for 'who'"

# 2. The fixed-handle lookup of "who" must NOT be reported (it is stable).
if echo "$out" | grep -q "HANDLE symbol=who"; then
    fail "false positive: the stable specific-handle lookup was flagged"
fi

echo "PASS: dlsym interceptor + symdiff detected the flip and ignored the stable lookup"
exit 0
