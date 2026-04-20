#!/bin/bash
# Minimal reproducer for JsonStringToMessage failing under antirev.
#
# Runs on the aarch64 target (or any Linux with protobuf 3.x installed).
# Not wired into CMakeLists — invoke manually:
#
#   tests/protobuf_json/run_test.sh <build_dir>
#
# Where <build_dir> is the antirev build tree containing stub + test.key.

set -e
cd "$(dirname "$0")"

BUILD_DIR="${1:-../../build}"
STUB="$BUILD_DIR/stub"
KEY="$BUILD_DIR/test.key"
PROTECT="../../encryptor/protect.py"

if [ ! -x "$STUB" ]; then echo "FAIL: stub not found at $STUB" >&2; exit 1; fi
if [ ! -f "$KEY"  ]; then echo "FAIL: key not found at $KEY"  >&2; exit 1; fi

echo "=== [1] generate protobuf code ==="
protoc --cpp_out=. foo.proto

echo "=== [2] build main ==="
g++ -O0 -g -std=c++17 -o main main.cc foo.pb.cc \
    -lprotobuf -lpthread

echo "=== [3] plain run ==="
./main data.config > plain.stdout 2> plain.stderr || {
    echo "FAIL: plain run exited non-zero" >&2
    cat plain.stderr >&2
    exit 2
}
cat plain.stderr
cat plain.stdout

echo "=== [4] pack ==="
python3 "$PROTECT" protect-exe \
    --stub   "$STUB" \
    --main   ./main \
    --key    "$KEY" \
    --output ./main.protected

echo "=== [5] packed run ==="
./main.protected data.config > packed.stdout 2> packed.stderr || {
    echo "=== PACKED RUN FAILED — this may be the bug ===" >&2
    echo "--- packed.stderr ---" >&2
    cat packed.stderr >&2
    echo "--- packed.stdout ---" >&2
    cat packed.stdout >&2
    exit 3
}
cat packed.stderr
cat packed.stdout

echo "=== [6] diff ==="
if diff -u plain.stdout packed.stdout; then
    echo "PASS: plain and packed outputs match"
else
    echo "FAIL: plain vs packed output differs — reproduction successful"
    exit 4
fi
