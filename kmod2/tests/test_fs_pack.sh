#!/bin/bash
# Userspace test for antirev-fs-pack.py (no root / no module needed).
#
# Verifies the kmod2 ciphertext-tree packer:
#   1. every ELF (lib + exe) is encrypted into the mirrored .enc tree (ANTREV01)
#   2. ciphertext != plaintext, and decrypts back byte-identically
#   3. non-ELF files are left untouched (NOT copied into the tree)
#   4. blacklisted ELFs are left plaintext (NOT in the tree)
#   5. symlinks are mirrored verbatim (SONAME chains survive)
#   6. a manifest is written outside the .enc tree
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
PACK="$KMOD/tools/antirev-fs-pack.py"
PROTECT="$ROOT/encryptor/protect.py"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

WORK="$(mktemp -d /tmp/antirev_fspack.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

PROJ="$WORK/proj"; ENC="$WORK/proj/.enc"
mkdir -p "$PROJ/lib" "$PROJ/bin"

echo "== build a tiny install tree =="
cat > "$WORK/t.c" <<'EOF'
int answer(void) { return 42; }
EOF
gcc -shared -fPIC -o "$PROJ/lib/libtest.so.1.0" "$WORK/t.c"
ln -s libtest.so.1.0 "$PROJ/lib/libtest.so.1"          # SONAME chain
ln -s libtest.so.1   "$PROJ/lib/libtest.so"
printf 'int main(void){return 0;}\n' > "$WORK/m.c"
gcc -o "$PROJ/bin/app" "$WORK/m.c"                     # an executable ELF
gcc -shared -fPIC -o "$PROJ/lib/libthird.so" "$WORK/t.c"  # to be blacklisted
echo '{"cfg":1}' > "$PROJ/lib/data.json"               # non-ELF, must be untouched

cat > "$WORK/config.yaml" <<EOF
install_dir: $PROJ
output_dir:  $ENC
key:         key.hex
blacklist:
  - libthird.so*
EOF

echo "== run the packer =="
python3 "$PACK" "$WORK/config.yaml" || { echo "packer failed"; exit 1; }

echo "== 1. ELFs encrypted into mirror with ANTREV01 magic =="
for f in lib/libtest.so.1.0 bin/app; do
	if [[ -f "$ENC/$f" ]] && head -c8 "$ENC/$f" | grep -q "ANTREV01"; then
		ok "encrypted: $f"
	else
		bad "missing/!magic: $f"
	fi
done

echo "== 2. ciphertext differs, decrypts byte-identically =="
cmp -s "$ENC/lib/libtest.so.1.0" "$PROJ/lib/libtest.so.1.0" \
	&& bad "ciphertext == plaintext!" || ok "ciphertext differs from plaintext"
# round-trip: decrypt with the same key via a tiny python check
python3 - "$ENC/bin/app" "$PROJ/bin/app" "$WORK/key.hex" <<'PY'
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
enc, plain, keyf = sys.argv[1:4]
key = bytes.fromhex(open(keyf).read().strip())
blob = open(enc, "rb").read()
magic, iv, tag, ct = blob[:8], blob[8:20], blob[20:36], blob[36:]
dec = AESGCM(key).decrypt(iv, ct + tag, None)
sys.exit(0 if dec == open(plain, "rb").read() else 1)
PY
[[ $? -eq 0 ]] && ok "decrypt round-trips to original plaintext" || bad "decrypt mismatch"

echo "== 3. non-ELF untouched (NOT in tree) =="
[[ ! -e "$ENC/lib/data.json" ]] && ok "data.json not copied into tree" || bad "data.json leaked into tree"
[[ -f "$PROJ/lib/data.json" ]]  && ok "original data.json untouched"   || bad "original data.json modified"

echo "== 4. blacklisted ELF left out of tree =="
[[ ! -e "$ENC/lib/libthird.so" ]] && ok "libthird.so (blacklisted) not in tree" || bad "blacklisted lib in tree"

echo "== 5. symlinks mirrored verbatim =="
if [[ -L "$ENC/lib/libtest.so" && "$(readlink "$ENC/lib/libtest.so")" == "libtest.so.1" ]]; then
	ok "symlink libtest.so -> libtest.so.1 preserved"
else
	bad "symlink not mirrored"
fi

echo "== 6. manifest written outside the .enc tree =="
if [[ -f "$WORK/antirev-fs-manifest.json" ]] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$WORK/antirev-fs-manifest.json"; then
	ok "manifest present and valid JSON, outside the tree"
else
	bad "manifest missing/invalid"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
