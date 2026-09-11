#!/usr/bin/env bash
# test_fusefs.sh — end-to-end test for vcachefsd (antirev design 3).
#
# Covers: decrypt correctness through the mount, ciphertext-on-disk, plaintext
# passthrough (--passdata), strict-mode reject, and the decrypt-authorization
# gate (authorized reader decrypts; unauthorized -> -EACCES; with
# --passthrough-cipher -> keyless trailer-stripped container).
#
# Requires: a built ./vcachefsd (run `make` first), fusermount3, /dev/fuse,
# python3 with the `cryptography` package (to build containers exactly like
# vcache-pack.py / protect.make_container(embed_key=True, magic=FS_MAGIC)).
# No kernel module and (usually) no root needed — just /dev/fuse access.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/vcachefsd"
WORK="$(mktemp -d)"
LOWER="$WORK/enc"
MNT="$WORK/mnt"
PASS=0 FAIL=0
MOUNTED=""

cleanup() {
	[ -n "$MOUNTED" ] && fusermount3 -u "$MNT" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP: $1"; exit 0; }

command -v fusermount3 >/dev/null 2>&1 || skip "fusermount3 not found"
[ -e /dev/fuse ] || skip "/dev/fuse not present"
[ -x "$BIN" ] || skip "vcachefsd not built — run 'make' in $ROOT first"
python3 -c 'import cryptography' 2>/dev/null || skip "python3 cryptography missing"

mkdir -p "$LOWER" "$MNT"

# ---- build a ciphertext lower tree exactly like the packer ------------------
# FS_MAGIC = a74c2e91d63b085f ; embedded-key form: MAGIC+iv+tag+ct+key+MAGIC
export PYTHONWARNINGS=ignore
python3 - "$LOWER" <<'PY'
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
FS_MAGIC = bytes.fromhex("a74c2e91d63b085f")
lower = sys.argv[1]
def container(data):
    key = os.urandom(32); iv = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(iv, data, None)
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return FS_MAGIC + iv + tag + ct + key + FS_MAGIC
# an "encrypted lib": recognizable plaintext payload
plain = b"FUSEFS-PLAINTEXT-PAYLOAD-" + b"\x7fELF" + os.urandom(4096) + b"-END"
open(os.path.join(lower, "secret.so"), "wb").write(container(plain))
open(os.path.join(lower, "plain.expected"), "wb").write(plain)
# a third-party plaintext data file (no magic) -> passthrough
open(os.path.join(lower, "notes.txt"), "wb").write(b"third-party plaintext\n")
PY
[ -f "$LOWER/secret.so" ] || { bad "pack step produced no container"; echo; echo "$PASS passed, $((FAIL+1)) failed"; exit 1; }

mount_fs() {   # args: extra vcachefsd options...
	[ -n "$MOUNTED" ] && { fusermount3 -u "$MNT" 2>/dev/null; MOUNTED=""; }
	"$BIN" "$LOWER" "$MNT" "$@" >/dev/null 2>&1 &
	for _ in $(seq 1 50); do
		mountpoint -q "$MNT" 2>/dev/null && { MOUNTED=1; return 0; }
		sleep 0.1
	done
	return 1
}

echo "== decrypt / passthrough / strict (gate off) =="
if mount_fs --passdata; then
	MOUNTED=1
	if cmp -s "$MNT/secret.so" "$LOWER/plain.expected"; then
		ok "encrypted lib decrypts through the mount"
	else
		bad "decrypted content mismatch"
	fi
	# ciphertext on disk: lower file carries the magic and differs from plaintext
	if head -c8 "$LOWER/secret.so" | cmp -s - <(printf '\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f'); then
		ok "lower file is ciphertext (FS_MAGIC on disk)"
	else
		bad "lower file missing FS_MAGIC"
	fi
	if [ "$(cat "$MNT/notes.txt")" = "third-party plaintext" ]; then
		ok "non-magic file served verbatim under --passdata"
	else
		bad "passdata passthrough wrong"
	fi
else
	bad "mount (passdata) failed"
fi

echo "== strict mode rejects non-magic files =="
if mount_fs; then           # no --passdata, no --passthrough
	MOUNTED=1
	cmp -s "$MNT/secret.so" "$LOWER/plain.expected" && ok "encrypted still decrypts in strict mode" || bad "strict decrypt broke"
	if cat "$MNT/notes.txt" >/dev/null 2>&1; then
		bad "strict mode served a non-magic file (should -EIO)"
	else
		ok "strict mode rejects non-magic file"
	fi
else
	bad "mount (strict) failed"
fi

echo "== gate: authorized vs unauthorized =="
# authorize a uniquely-named reader via the dev allow-list (basename match).
READER="$WORK/okreader"; cp "$(command -v cat)" "$READER"
echo "okreader" > "$WORK/authz.txt"
if mount_fs --passdata --gate --authz "$WORK/authz.txt"; then
	MOUNTED=1
	if cmp -s <("$READER" "$MNT/secret.so") "$LOWER/plain.expected"; then
		ok "whitelisted reader (okreader) decrypts"
	else
		bad "authorized reader failed to decrypt"
	fi
	# plain cat/cp is NOT listed -> -EACCES
	if cat "$MNT/secret.so" >/dev/null 2>&1; then
		bad "unauthorized reader was allowed (expected EACCES)"
	else
		ok "unauthorized reader denied (-EACCES)"
	fi
else
	bad "mount (gate) failed"
fi

echo "== gate + passthrough-cipher: keyless container, no plaintext/key leak =="
if mount_fs --passdata --gate --authz "$WORK/authz.txt" --passthrough-cipher; then
	MOUNTED=1
	ENC_SIZE=$(stat -c %s "$LOWER/secret.so")
	EXPECT=$((ENC_SIZE - 40))          # container minus 32-byte key + 8-byte magic
	OUT="$WORK/copied.bin"; cat "$MNT/secret.so" > "$OUT" 2>/dev/null
	GOT=$(stat -c %s "$OUT")
	if [ "$GOT" = "$EXPECT" ]; then
		ok "unauthorized read yields container-minus-40 bytes ($GOT)"
	else
		bad "passthrough size wrong: got $GOT expected $EXPECT"
	fi
	if head -c8 "$OUT" | cmp -s - <(printf '\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f'); then
		ok "keyless copy still starts with FS_MAGIC (valid-looking container)"
	else
		bad "keyless copy missing magic"
	fi
	if cmp -s "$OUT" "$LOWER/plain.expected"; then
		bad "keyless copy leaked PLAINTEXT"
	else
		ok "keyless copy is not plaintext"
	fi
	# the embedded key (last 40 bytes of the lower file) must be absent
	tail -c 40 "$LOWER/secret.so" > "$WORK/keytrailer.bin"
	if grep -qF -f /dev/null "$OUT" 2>/dev/null; then :; fi
	if cmp -s <(tail -c 40 "$OUT") "$WORK/keytrailer.bin"; then
		bad "keyless copy still contains the key trailer"
	else
		ok "key trailer absent from unauthorized copy"
	fi
else
	bad "mount (gate+passthrough-cipher) failed"
fi

[ -n "$MOUNTED" ] && { fusermount3 -u "$MNT" 2>/dev/null; MOUNTED=""; }

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
