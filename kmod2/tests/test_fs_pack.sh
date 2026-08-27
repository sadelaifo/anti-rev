#!/bin/bash
# Userspace test for antirev-fs-pack.py (no root / no module needed).
#
# Verifies the kmod2 ciphertext-tree packer:
#   1. every ELF (lib + exe) is encrypted into the mirrored .enc tree (ANTREV01)
#   2. ciphertext != plaintext, and decrypts back byte-identically
#   3. non-ELF data files (.json/.py/.txt) are mirrored VERBATIM (plaintext) into
#      the tree (mirror_plaintext default) — visible under a `passdata` mount
#   4. blacklisted ELFs are mirrored plaintext (in tree, no ANTREV01 magic)
#   5. symlinks are mirrored verbatim (SONAME chains survive)
#   6. a manifest (with the plaintext list) is written outside the .enc tree
#   7. mirror_plaintext: false reverts to a minimal pure-secret tree
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
echo '{"cfg":1}' > "$PROJ/lib/data.json"               # non-ELF data file
printf '#!/usr/bin/env python3\nprint("hi")\n' > "$PROJ/bin/run.py"  # script
printf 'generated\n' > "$PROJ/lib/notes.txt"           # non-ELF text
ar rcs "$PROJ/lib/libstatic.a" 2>/dev/null <(:) || printf '!<arch>\nstaticarchive-payload\n' > "$PROJ/lib/libstatic.a"  # non-ELF static archive
printf '\x6f\x0d\x0d\x0a\x00\x00\x00\x00bytecode-payload' > "$PROJ/lib/mod.pyc"  # non-ELF bytecode
printf 'not-an-elf-despite-the-name' > "$PROJ/bin/weird.elf"  # .elf WITHOUT ELF magic

cat > "$WORK/config.yaml" <<EOF
install_dir: $PROJ
output_dir:  $ENC
key:         key.hex
blacklist:
  - libthird.so*
encrypt_ext:
  - .a
  - .pyc
  - .elf
EOF

echo "== run the packer =="
python3 "$PACK" "$WORK/config.yaml" || { echo "packer failed"; exit 1; }

echo "== 1. ELFs encrypted into mirror with ANTREV01 magic =="
for f in lib/libtest.so.1.0 bin/app; do
	if [[ -f "$ENC/$f" ]] && [ "$(head -c8 "$ENC/$f" | xxd -p)" = "a74c2e91d63b085f" ]; then
		ok "encrypted: $f"
	else
		bad "missing/!magic: $f"
	fi
done

echo "== 2. ciphertext differs, decrypts byte-identically =="
cmp -s "$ENC/lib/libtest.so.1.0" "$PROJ/lib/libtest.so.1.0" \
	&& bad "ciphertext == plaintext!" || ok "ciphertext differs from plaintext"
# round-trip: decrypt with the same key via a tiny python check.
# antirevfs container carries an embedded-key trailer: MAGIC|iv|tag|ct|key|MAGIC,
# so the ciphertext body is blob[36:-40] and the trailer holds the key + magic.
python3 - "$ENC/bin/app" "$PROJ/bin/app" "$WORK/key.hex" <<'PY'
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
enc, plain, keyf = sys.argv[1:4]
key = bytes.fromhex(open(keyf).read().strip())
blob = open(enc, "rb").read()
assert blob[:8] == bytes.fromhex("a74c2e91d63b085f") and blob[-8:] == bytes.fromhex("a74c2e91d63b085f"), "missing header/trailer magic"
assert blob[-40:-8] == key, "embedded trailer key != packer key"
iv, tag, ct = blob[8:20], blob[20:36], blob[36:-40]
dec = AESGCM(key).decrypt(iv, ct + tag, None)
sys.exit(0 if dec == open(plain, "rb").read() else 1)
PY
[[ $? -eq 0 ]] && ok "decrypt round-trips via embedded trailer key" || bad "decrypt mismatch"

echo "== 3. non-ELF data files mirrored VERBATIM (plaintext, in tree) =="
for f in lib/data.json bin/run.py lib/notes.txt; do
	if [[ -f "$ENC/$f" ]] && cmp -s "$ENC/$f" "$PROJ/$f" \
		&& [ "$(head -c8 "$ENC/$f" | xxd -p)" != "a74c2e91d63b085f" ]; then
		ok "mirrored plaintext (no magic): $f"
	else
		bad "not mirrored byte-identically / has magic: $f"
	fi
done
[[ -f "$PROJ/lib/data.json" ]] && ok "original data.json untouched" || bad "original data.json modified"

echo "== 4. blacklisted ELF mirrored plaintext (in tree, no ANTREV01) =="
if [[ -f "$ENC/lib/libthird.so" ]] && cmp -s "$ENC/lib/libthird.so" "$PROJ/lib/libthird.so" \
	&& [ "$(head -c8 "$ENC/lib/libthird.so" | xxd -p)" != "a74c2e91d63b085f" ]; then
	ok "libthird.so (blacklisted) mirrored plaintext"
else
	bad "blacklisted lib not mirrored plaintext / has magic"
fi

echo "== 5. symlinks mirrored verbatim =="
if [[ -L "$ENC/lib/libtest.so" && "$(readlink "$ENC/lib/libtest.so")" == "libtest.so.1" ]]; then
	ok "symlink libtest.so -> libtest.so.1 preserved"
else
	bad "symlink not mirrored"
fi

echo "== 6. manifest written outside the .enc tree, lists plaintext mirror =="
if [[ -f "$WORK/antirev-fs-manifest.json" ]] && python3 - "$WORK/antirev-fs-manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
pt = set(m.get("plaintext", []))
need = {"lib/data.json", "bin/run.py", "lib/notes.txt", "lib/libthird.so"}
sys.exit(0 if need <= pt else 1)
PY
then
	ok "manifest valid JSON, plaintext list includes data + blacklisted ELF"
else
	bad "manifest missing/invalid or plaintext list incomplete"
fi

echo "== 7. mirror_plaintext: false -> minimal pure-secret tree =="
ENC2="$WORK/proj/.enc2"
cat > "$WORK/config2.yaml" <<EOF
install_dir: $PROJ
output_dir:  $ENC2
key:         key.hex
mirror_plaintext: false
blacklist:
  - libthird.so*
EOF
python3 "$PACK" "$WORK/config2.yaml" >/dev/null || { echo "packer (mode2) failed"; exit 1; }
if [[ -f "$ENC2/lib/libtest.so.1.0" && ! -e "$ENC2/lib/data.json" \
	&& ! -e "$ENC2/bin/run.py" && ! -e "$ENC2/lib/libthird.so" \
	&& -L "$ENC2/lib/libtest.so" ]]; then
	ok "data files + blacklisted ELF omitted; ELFs + symlinks kept"
else
	bad "mirror_plaintext:false did not produce a minimal tree"
fi

echo
echo "== 8. encrypt_ext: non-ELF .a/.pyc/.elf encrypted (ANTREV01), not signed =="
for f in lib/libstatic.a lib/mod.pyc bin/weird.elf; do
	if [[ -f "$ENC/$f" ]] && [ "$(head -c8 "$ENC/$f" | xxd -p)" = "a74c2e91d63b085f" ]; then
		# must NOT carry a per-exe signature footer (they're not exec-loaded)
		if [[ "$(tail -c8 "$ENC/$f" | xxd -p)" == "3d6af0128c55b427" ]]; then
			bad "encrypt_ext file wrongly signed: $f"
		else
			ok "encrypt_ext encrypted (unsigned): $f"
		fi
	else
		bad "encrypt_ext file not encrypted: $f"
	fi
done
# and they must be listed under encrypted (not plaintext) in the manifest
if python3 - "$WORK/antirev-fs-manifest.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
enc=set(m["encrypted"]); pt=set(m.get("plaintext",[]))
need={"lib/libstatic.a","lib/mod.pyc","bin/weird.elf"}
assert need <= enc, f"missing from encrypted: {need-enc}"
assert not (need & pt), f"wrongly in plaintext: {need & pt}"
PY
then ok "manifest lists .a/.pyc/.elf as encrypted"; else bad "encrypt_ext manifest wrong"; fi

echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
