#!/bin/bash
# test_scan_root — configurable daemon scan-root ($VCACHE_HOME / <base>/SW)
#
# Usage: run_test.sh <stub>
#
# Proves scan_encrypted_libs() root selection (stub.c):
#   A. default   : $HOME set, VCACHE_HOME unset -> scan root $HOME/SW
#   B. override  : $HOME has no SW, VCACHE_HOME=<root>/SW (verbatim, no subtree
#                  appended) -> scan root is exactly $VCACHE_HOME
#   C. control   : neither valid -> exe-dir fallback (<root>/SW/bin, which holds
#                  no lib) -> the job MUST fail, proving the root is load-bearing
#
# lrxd lives under <root>/SW/bin while the encrypted lib lives under
# <root>/SW/lib, so only a correctly-resolved root (which recurses the whole
# SW tree) can serve the lib — the exe-dir fallback cannot.

STUB="$1"
PROTECT="$(dirname "$0")/../../../shared/protect.py"
TD="$(dirname "$STUB")/scan_root_test"
ROOT="$TD/root"
EMPTY="$TD/emptyhome"

rm -rf "$TD"
mkdir -p "$ROOT/SW/bin" "$ROOT/SW/lib" "$EMPTY" "$TD/src"

cat > "$TD/src/libcompute.c" <<'EOF'
int compute(int x){ return x*2 + 8; }   /* 17*2+8 = 42 */
EOF
cat > "$TD/src/job.c" <<'EOF'
#include <stdio.h>
#include <dlfcn.h>
int main(void){
    void *h = dlopen("libcompute.so", RTLD_NOW);
    if(!h){ fprintf(stderr,"dlopen fail: %s\n", dlerror()); return 2; }
    int (*f)(int) = (int(*)(int))dlsym(h,"compute");
    if(!f){ fprintf(stderr,"dlsym fail\n"); return 3; }
    int r = f(17);
    printf("compute(17)=%d\n", r);
    return (r==42)?0:1;
}
EOF
gcc -O2 -shared -fPIC -Wl,-soname,libcompute.so -o "$TD/src/libcompute.so" "$TD/src/libcompute.c" || exit 1
gcc -O2 -o "$TD/src/job" "$TD/src/job.c" -ldl || exit 1

KEY="$TD/scan.key"
python3 "$PROTECT" encrypt-lib   --key "$KEY" --libs "$TD/src/libcompute.so" --output-dir "$ROOT/SW/lib" || exit 1
python3 "$PROTECT" protect-daemon --key "$KEY" --stub "$STUB" --output "$ROOT/SW/bin/lrxd" || exit 1
python3 "$PROTECT" protect-exe    --key "$KEY" --stub "$STUB" --main "$TD/src/job" --daemon-libs --output "$ROOT/SW/bin/job.protected" || exit 1
chmod +x "$ROOT/SW/bin/lrxd" "$ROOT/SW/bin/job.protected"

kill_all(){ pkill -f "$ROOT/SW/bin/lrxd" 2>/dev/null || true; sleep 0.4; }

# run_phase <label> <ok|fail>  -> returns 0 on expected result, 1 otherwise.
# env (HOME/VCACHE_HOME) must already be exported by the caller.
run_phase(){
    kill_all
    "$ROOT/SW/bin/lrxd" >/dev/null 2>&1 &
    sleep 0.6
    "$ROOT/SW/bin/job.protected" >"$TD/job.out" 2>&1
    local rc=$?
    kill_all
    local line; line="$(head -1 "$TD/job.out" 2>/dev/null)"
    if [ "$2" = ok ]; then
        if [ "$rc" = 0 ]; then echo "  [PASS] $1 (job=42)"; return 0
        else echo "  [FAIL] $1 (rc=$rc: $line)"; return 1; fi
    else
        if [ "$rc" != 0 ]; then echo "  [PASS] $1 (job failed as expected, rc=$rc)"; return 0
        else echo "  [FAIL] $1 (unexpectedly succeeded — root not load-bearing)"; return 1; fi
    fi
}

echo "=== test_scan_root: configurable daemon scan root ==="
FAILS=0
( export HOME="$ROOT"; unset VCACHE_HOME LD_PRELOAD LD_LIBRARY_PATH __r_LS __r_FM __r_EL __r_SD; \
  run_phase "A default \$HOME/SW" ok ); FAILS=$((FAILS + $?))
( export HOME="$EMPTY" VCACHE_HOME="$ROOT/SW"; unset LD_PRELOAD LD_LIBRARY_PATH __r_LS __r_FM __r_EL __r_SD; \
  run_phase "B VCACHE_HOME verbatim root" ok ); FAILS=$((FAILS + $?))
( export HOME="$EMPTY"; unset VCACHE_HOME LD_PRELOAD LD_LIBRARY_PATH __r_LS __r_FM __r_EL __r_SD; \
  run_phase "C control (no valid root)" fail ); FAILS=$((FAILS + $?))

kill_all
if [ "$FAILS" = 0 ]; then echo "PASS: scan-root selection (VCACHE_HOME / <base>/SW) verified"; exit 0; fi
echo "FAIL: $FAILS scan-root check(s) failed"; exit 1
