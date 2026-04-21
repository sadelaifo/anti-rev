#!/usr/bin/env bash
#
# Step 2/3  — run on the x86 machine that has python3-cryptography.
#
# Takes the aarch64 popen_test from step 1 plus an aarch64 antirev stub
# and produces popen_test.protected (aarch64 ELF, antirev-encrypted).
# Next: copy popen_test + popen_test.protected to the aarch64 run
# machine and execute tools/popen_vfork_3_run.sh there.
#
# Usage:
#   tools/popen_vfork_2_encrypt.sh <popen_test> <stub_aarch64> [out_dir]
#
# Args:
#   popen_test     aarch64 plaintext binary from step 1
#   stub_aarch64   aarch64 antirev stub (./build/stub_aarch64 on the
#                  aarch64 compile machine)
#   out_dir        where to write popen_test.protected + key
#                  (default: dir of popen_test)

set -eu

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <popen_test> <stub_aarch64> [out_dir]" >&2
    exit 1
fi

REPO=$(cd "$(dirname "$0")/.." && pwd)
MAIN=$(readlink -f "$1")
STUB=$(readlink -f "$2")
OUT=${3:-$(dirname "$MAIN")}
mkdir -p "$OUT"
OUT=$(readlink -f "$OUT")

[[ -r "$MAIN" ]] || { echo "popen_test not readable: $MAIN" >&2; exit 1; }
[[ -r "$STUB" ]] || { echo "stub not readable: $STUB"       >&2; exit 1; }

# Sanity-check arch tags
echo "[*] inputs:"
file "$MAIN" | sed 's/^/      /'
file "$STUB" | sed 's/^/      /'

python3 "$REPO/encryptor/protect.py" protect-exe \
    --stub   "$STUB" \
    --main   "$MAIN" \
    --key    "$OUT/test.key" \
    --output "$OUT/popen_test.protected"

echo
echo "[+] produced: $OUT/popen_test.protected"
file "$OUT/popen_test.protected" | sed 's/^/            /'
echo
echo "next: scp $MAIN + $OUT/popen_test.protected  aarch64-run-host:/tmp/"
echo "      then on that host run:"
echo "        tools/popen_vfork_3_run.sh /tmp/popen_test /tmp/popen_test.protected"
