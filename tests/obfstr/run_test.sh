#!/bin/bash
# tests/obfstr — smoke test for tools/obfstr_gen.py + stub/obfstr.h.
#
# Two things need to hold for the protection to work:
#
#   (A) Runtime correctness.  The codegen-rewritten + obfstr.h-decoded
#       string must exactly match what the source wrote in cleartext.
#       The test binary asserts this internally and exits 0 on PASS.
#
#   (B) Cleartext absence.  Running `strings` on the compiled binary
#       must NOT find any of the marker literals from main.c — those
#       only ever appeared in the source, never the binary, because
#       obfstr_gen.py replaced them with encrypted byte sequences
#       before the C compiler ever saw them.
#
# Usage: run_test.sh <build-dir>

set -eu

if [ "${1:-}" = "" ]; then
    echo "usage: $0 <build-dir>" >&2
    exit 2
fi
BUILD_DIR="$1"
TEST_BIN="$BUILD_DIR/test_obfstr_bin"

if [ ! -x "$TEST_BIN" ]; then
    echo "[obfstr_test] missing test binary: $TEST_BIN" >&2
    exit 2
fi

# (A) runtime correctness
"$TEST_BIN" || { echo "[obfstr_test] runtime sub-tests failed"; exit 1; }

# (B) cleartext absence — every marker literal must be gone from the
# compiled binary.  These marker substrings only exist as source-level
# arguments to OBFSTR / LOG_ERR / OSNPRINTF / PERR; codegen should
# replace each with a sequence of encrypted bytes.  If `strings` finds
# any of them, the codegen never ran or didn't reach this file.
markers=(
    "antirev_secret_marker"
    "antirev_secret_format"
    "antirev_secret_fmt"
    "antirev_secret_perr_label"
)

failed=0
for m in "${markers[@]}"; do
    if strings "$TEST_BIN" | grep -F "$m" >/dev/null 2>&1; then
        echo "[obfstr_test] FAIL: cleartext marker '$m' visible in binary"
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi

echo "[obfstr_test] PASS — markers absent from .rodata, runtime decode OK"
