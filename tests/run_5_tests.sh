#!/bin/bash
# Run the 5 test scenarios:
#   1. dlopen works (bundled .so)
#   2. DT_NEEDED works (bundled .so)
#   3. Child process uses SAME lib as parent (inherited LD_PRELOAD)
#   4. Child process uses DIFFERENT lib from parent (each independently protected)
#   5. Script invokes A and B with shared + different libs

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(dirname "$SCRIPT_DIR")"
BUILD="$PROJ_DIR/build"
STUB="$BUILD/stub"
PROTECT="$PROJ_DIR/encryptor/protect.py"
TD="$BUILD/test5"   # test output directory

rm -rf "$TD"
mkdir -p "$TD"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    echo ""
    echo "=== $name ==="
    if "$@" 2>&1; then
        echo ">>> RESULT: $name — PASS"
        PASS=$((PASS + 1))
    else
        echo ">>> RESULT: $name — FAIL (exit $?)"
        FAIL=$((FAIL + 1))
    fi
}

# ── Build everything ─────────────────────────────────────────────────

echo "Building test binaries..."

# Test 1 & 3: reuse existing mylib.so and dlopen_main from build/
# (cmake already built them)
cmake --build "$BUILD" --target mylib --target dlopen_main 2>/dev/null

# Test 2: reuse existing linked_main and liblinkedmath from build/
cmake --build "$BUILD" --target linked_main --target liblinkedmath 2>/dev/null

# Test 3: fork_same_lib — compile parent and child
gcc -O2 -o "$TD/fork_same_parent" "$SCRIPT_DIR/fork_same_lib/parent.c" -ldl
gcc -O2 -o "$TD/fork_same_child"  "$SCRIPT_DIR/fork_same_lib/child.c"  -ldl

# Test 4: fork_diff_lib — compile parent, child, and their libs
gcc -shared -fPIC -O2 -Wl,-soname,libparent.so \
    -o "$TD/libparent.so" "$SCRIPT_DIR/fork_diff_lib/libparent.c"
gcc -shared -fPIC -O2 -Wl,-soname,libchild.so \
    -o "$TD/libchild.so"  "$SCRIPT_DIR/fork_diff_lib/libchild.c"
gcc -O2 -o "$TD/fork_diff_parent" "$SCRIPT_DIR/fork_diff_lib/parent.c" -ldl
gcc -O2 -o "$TD/fork_diff_child"  "$SCRIPT_DIR/fork_diff_lib/child.c"  -ldl

# Test 5: script_multi_bin — compile processes and libs
gcc -shared -fPIC -O2 -Wl,-soname,libcommon.so \
    -o "$TD/libcommon.so" "$SCRIPT_DIR/script_multi_bin/libcommon.c"
gcc -shared -fPIC -O2 -Wl,-soname,libA_only.so \
    -o "$TD/libA_only.so" "$SCRIPT_DIR/script_multi_bin/libA_only.c"
gcc -shared -fPIC -O2 -Wl,-soname,libB_only.so \
    -o "$TD/libB_only.so" "$SCRIPT_DIR/script_multi_bin/libB_only.c"
gcc -O2 -o "$TD/proc_a" "$SCRIPT_DIR/script_multi_bin/proc_a.c" -ldl
gcc -O2 -o "$TD/proc_b" "$SCRIPT_DIR/script_multi_bin/proc_b.c" -ldl

echo "Build complete."

# ── Test 1: dlopen (bundled .so) ─────────────────────────────────────

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$BUILD/dlopen_main" \
    --key  "$TD/t1.key" \
    --libs "$BUILD/mylib.so" \
    --output "$TD/dlopen_main.protected" \
    > /dev/null

run_test "Test 1: dlopen (bundled .so)" \
    "$TD/dlopen_main.protected"

# ── Test 2: DT_NEEDED (bundled .so) ─────────────────────────────────

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$BUILD/linked_main" \
    --key  "$TD/t2.key" \
    --libs "$BUILD/liblinkedmath.so" \
    --output "$TD/linked_main.protected" \
    > /dev/null

run_test "Test 2: DT_NEEDED (bundled .so)" \
    "$TD/linked_main.protected"

# ── Test 3: child uses SAME lib as parent ────────────────────────────

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$TD/fork_same_parent" \
    --key  "$TD/t3.key" \
    --libs "$BUILD/mylib.so" \
    --output "$TD/fork_same_parent.protected" \
    > /dev/null

run_test "Test 3: child inherits same lib via LD_PRELOAD" \
    "$TD/fork_same_parent.protected" "$TD/fork_same_child"

# ── Test 4: child uses DIFFERENT lib from parent ─────────────────────

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$TD/fork_diff_parent" \
    --key  "$TD/t4.key" \
    --libs "$TD/libparent.so" \
    --output "$TD/fork_diff_parent.protected" \
    > /dev/null

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$TD/fork_diff_child" \
    --key  "$TD/t4_child.key" \
    --libs "$TD/libchild.so" \
    --output "$TD/fork_diff_child.protected" \
    > /dev/null

run_test "Test 4: parent(libparent.so) fork+exec child(libchild.so)" \
    "$TD/fork_diff_parent.protected" "$TD/fork_diff_child.protected"

# ── Test 5: script invokes A and B with shared + different libs ──────

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$TD/proc_a" \
    --key  "$TD/t5.key" \
    --libs "$TD/libcommon.so" "$TD/libA_only.so" \
    --output "$TD/proc_a.protected" \
    > /dev/null

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$TD/proc_b" \
    --key  "$TD/t5.key" \
    --libs "$TD/libcommon.so" "$TD/libB_only.so" \
    --output "$TD/proc_b.protected" \
    > /dev/null

run_test_5() {
    echo "--- Running process A ---"
    "$TD/proc_a.protected" || return 1
    echo "--- Running process B ---"
    "$TD/proc_b.protected" || return 1
    echo "Both A and B succeeded"
}

run_test "Test 5: script invokes A(common+A_only) and B(common+B_only)" \
    run_test_5

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  SUMMARY: $PASS passed, $FAIL failed"
echo "============================================"

[ "$FAIL" -eq 0 ]
