#!/bin/bash
# opcua_enc test — verifies OPC UA client init works from encrypted binaries.
#
# Builds open62541 as a shared lib, compiles two test processes that link
# to it, encrypts the processes (NOT open62541), and runs them.
#
# Usage: ./run_test.sh [path/to/antirev/build_dir]
#   build_dir defaults to ../../build
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
BUILD_DIR="${1:-$REPO/build}"
WORK="$DIR/_workdir"

STUB="$BUILD_DIR/stub"
PROTECT="$REPO/encryptor/protect.py"

# Sanity checks
if [ ! -x "$STUB" ]; then
    echo "ERROR: stub not found at $STUB — build the project first" >&2
    exit 1
fi

echo "=== opcua_enc: OPC UA client init under encryption ==="
echo "    work dir: $WORK"

rm -rf "$WORK"
mkdir -p "$WORK"

# ── Step 1: Build open62541 as a shared library ─────────────────────
O62_SRC="$WORK/open62541_src"
O62_BUILD="$WORK/open62541_build"
O62_INSTALL="$WORK/open62541_install"

if [ ! -d "$O62_SRC" ]; then
    echo "[1/5] Cloning open62541 v1.3.9 (shallow)..."
    git clone --depth 1 --branch v1.3.9 \
        https://github.com/open62541/open62541.git "$O62_SRC" 2>&1 | tail -1
fi

echo "[2/5] Building open62541 as shared library..."
mkdir -p "$O62_BUILD"
cmake -S "$O62_SRC" -B "$O62_BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_INSTALL_PREFIX="$O62_INSTALL" \
    -DUA_ENABLE_ENCRYPTION=OFF \
    -DUA_BUILD_EXAMPLES=OFF \
    -DUA_BUILD_UNIT_TESTS=OFF \
    > "$WORK/cmake_config.log" 2>&1

cmake --build "$O62_BUILD" -j"$(nproc)" > "$WORK/cmake_build.log" 2>&1
cmake --install "$O62_BUILD" > "$WORK/cmake_install.log" 2>&1

# Find the built .so
O62_LIB=$(find "$O62_INSTALL" -name "libopen62541.so*" -not -type l | head -1)
O62_INC="$O62_INSTALL/include"
O62_LIBDIR=$(dirname "$O62_LIB")

if [ -z "$O62_LIB" ] || [ ! -f "$O62_LIB" ]; then
    echo "ERROR: libopen62541.so not found after build" >&2
    echo "  cmake config log:" >&2
    tail -20 "$WORK/cmake_config.log" >&2
    echo "  cmake build log:" >&2
    tail -20 "$WORK/cmake_build.log" >&2
    exit 1
fi
echo "    open62541 lib: $O62_LIB"
echo "    open62541 inc: $O62_INC"

# ── Step 2: Compile test processes ───────────────────────────────────
echo "[3/5] Compiling proc_a and proc_b..."

gcc -O2 -I"$O62_INC" -o "$WORK/proc_a" "$DIR/proc_a.c" \
    -L"$O62_LIBDIR" -lopen62541 -Wl,-rpath,'$ORIGIN'

gcc -O2 -I"$O62_INC" -o "$WORK/proc_b" "$DIR/proc_b.c" \
    -L"$O62_LIBDIR" -lopen62541 -Wl,-rpath,'$ORIGIN'

# Copy open62541 .so next to binaries (for $ORIGIN rpath)
cp -a "$O62_LIBDIR"/libopen62541.so* "$WORK/"

echo "    Verify unencrypted run..."
"$WORK/proc_a" || { echo "FAIL: proc_a failed even without encryption"; exit 1; }
"$WORK/proc_b" || { echo "FAIL: proc_b failed even without encryption"; exit 1; }
echo "    Both pass unencrypted."

# ── Step 3: Encrypt proc_a and proc_b (NOT open62541) ───────────────
echo "[4/5] Encrypting proc_a and proc_b..."

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$WORK/proc_a" \
    --key "$WORK/test.key" \
    --output "$WORK/proc_a.protected"

python3 "$PROTECT" protect-exe \
    --stub "$STUB" \
    --main "$WORK/proc_b" \
    --key "$WORK/test.key" \
    --output "$WORK/proc_b.protected"

# ── Step 4: Run encrypted processes ─────────────────────────────────
echo "[5/5] Running encrypted proc_a and proc_b..."

# open62541 is on disk in $WORK/ — the encrypted binary needs to find it.
# $ORIGIN rpath won't work from memfd, so set LD_LIBRARY_PATH.
export LD_LIBRARY_PATH="$WORK:${LD_LIBRARY_PATH:-}"

FAIL=0

echo ""
echo "--- proc_a.protected (encrypted) ---"
if "$WORK/proc_a.protected"; then
    echo "  => proc_a PASS"
else
    RET=$?
    echo "  => proc_a FAIL (exit $RET)"
    # Check dmesg for signal info
    dmesg 2>/dev/null | tail -5 || true
    FAIL=1
fi

echo ""
echo "--- proc_b.protected (encrypted) ---"
if "$WORK/proc_b.protected"; then
    echo "  => proc_b PASS"
else
    RET=$?
    echo "  => proc_b FAIL (exit $RET)"
    dmesg 2>/dev/null | tail -5 || true
    FAIL=1
fi

echo ""
if [ $FAIL -eq 0 ]; then
    echo "=== opcua_enc: ALL PASS ==="
    echo "Encryption does NOT cause OPC UA client init crash."
    echo "The production crash is likely caused by business software"
    echo "infrastructure (signal handler / .debug file scanning)."
else
    echo "=== opcua_enc: FAIL ==="
    echo "Encryption DOES affect OPC UA client init — the bug is in"
    echo "the antirev loading path, not in business software."
fi

exit $FAIL
