#!/bin/bash
# test_patch_shim — lrxd_<arch>.so open()-redirect end-to-end
#
# Usage: run_test.sh <stub> <lrxd_<arch>.so> <open_patch_bin> <mylib.so>
#
# 1. Encrypt a dummy lib (so the daemon has >=1 lib and starts) + a
#    standalone ".patch" file, all with the same key, into the daemon dir.
# 2. Build + start the lightweight daemon (publishes the discovery file).
# 3. Run an UNPROTECTED injector stand-in with lrxd_<arch>.so preloaded;
#    verify it reads the decrypted patch (not ciphertext).
# 4. Negative control: without the shim it must see ciphertext.
set -e

STUB="$1"
PATCH_SHIM="$2"
OPEN_PATCH="$3"
MYLIB="$4"
PROTECT="$(dirname "$0")/../../encryptor/protect.py"
TD="$(dirname "$STUB")/patch_test"
SRC="${TD}_src"

PLAINTEXT="HELLO-ANTIREV-PATCH-PAYLOAD-1234567890-the-quick-brown-fox"

rm -rf "$TD" "$SRC"
mkdir -p "$TD" "$SRC"

# Plaintext patch kept OUTSIDE the scan dir so the only "foo.patch" the
# daemon can resolve is the encrypted one.
printf '%s' "$PLAINTEXT" > "$SRC/foo.patch"

# Dummy lib encrypted into the daemon dir → daemon starts with 1 lib.
python3 "$PROTECT" encrypt-lib \
    --key "$TD/test.key" \
    --libs "$MYLIB" \
    --output-dir "$TD"

# Encrypt the patch (same key) into the daemon dir. encrypt-lib is a raw
# file encrypt that preserves the basename; ".patch" is NOT scanned at
# startup, so it is only ever decrypted lazily via OP_GET_PATCH.
python3 "$PROTECT" encrypt-lib \
    --key "$TD/test.key" \
    --libs "$SRC/foo.patch" \
    --output-dir "$TD"

# Lightweight daemon over the same dir/key.
python3 "$PROTECT" protect-daemon \
    --stub "$STUB" --key "$TD/test.key" \
    --output "$TD/.antirev-libd"

cleanup() {
    pkill -f "$TD/.antirev-libd" 2>/dev/null || true
    rm -rf "$SRC"
}
trap cleanup EXIT

# Start daemon (self-daemonizes; discovery file written before it returns).
"$TD/.antirev-libd" 2>&1
sleep 0.3

if [ ! -e "$TD/.antirev-libd.sock" ]; then
    echo "FAIL: daemon did not publish discovery file"
    exit 1
fi
echo "discovery file: $(cat "$TD/.antirev-libd.sock")"

echo "--- injector WITH lrxd_<arch>.so (expect decrypted) ---"
LD_PRELOAD="$PATCH_SHIM" "$OPEN_PATCH" "$TD/foo.patch" "$PLAINTEXT"

echo "--- negative control: NO shim (expect ciphertext) ---"
if "$OPEN_PATCH" "$TD/foo.patch" "$PLAINTEXT"; then
    echo "FAIL: injector read plaintext without the shim"
    exit 1
fi
echo "OK: without shim the injector sees ciphertext"

echo "PASS: lrxd_<arch>.so served decrypted patch via daemon"
