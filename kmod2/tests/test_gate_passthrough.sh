#!/bin/bash
# gate_passthrough_cipher test for vcachefs (key-in-.ko format): when an
# unauthorized process reads an encrypted file, instead of -EACCES it is served
# the WHOLE lower .enc/ file — the keyless container PLUS any appended signature
# footer — a valid-looking but undecryptable container (the AES key lives in the
# .ko, never in the file; a legacy embedded-key TRAILER, if any, stays withheld).
# Security is unchanged (no plaintext AND no key escapes); the difference is
# posture — the read "succeeds" with useless bytes rather than a permission error.
# Serving the WHOLE file (footer included) makes a backup taken THROUGH the mount
# byte-faithful, so a restored binary still verifies and runs.  Proves:
#   1. an authorized program still reads DECRYPTED content through the mount
#   2. cp (unlisted) SUCCEEDS but yields the whole keyless container; the embedded
#      key is NOT in the output
#   3. cat (unlisted) yields ciphertext (container magic, not the plaintext ELF)
#   4. an unauthorized objdump sees "not an ELF" — no symbols leak
#   5. flipping gate_passthrough_cipher=0 restores the -EACCES deny
#   6. the lower .enc file is (still) ciphertext
#   7. a SIGNED container copies through the mount WITH its footer intact (tar-safe)
#
# Requires root (insmod/mount).  Run:  sudo bash test_gate_passthrough.sh
set -uo pipefail

# Share one real session keyring across keyctl + mount (see test_antirevfs.sh).
if [[ -z "${ANTIREVFS_TEST_SESSION:-}" ]]; then
	if command -v keyctl >/dev/null 2>&1; then
		export ANTIREVFS_TEST_SESSION=1
		exec keyctl session - bash "$0" "$@"
	fi
	echo "warning: keyctl not found; cannot guarantee a shared session keyring" >&2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="$KMOD/module/vcachefs.ko"
PROTECT="$ROOT/shared/protect.py"
PASS_PARAM=/sys/module/vcachefs/parameters/gate_passthrough_cipher

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_passthru.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"; AUTHZ="$WORK/authorized_apps.txt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod vcachefs 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build test artifacts =="
cat > "$WORK/libtest.c" <<'EOF'
int antirevfs_answer(void) { return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
cp "$WORK/libtest.so" "$WORK/libtest.plain.so"   # reference plaintext

python3 "$PROTECT" encrypt-lib --fs --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

# A SIGNED container: the encrypted lib + a synthetic per-exe signature footer
# ([sig][sig_len:4 LE][SIG_MAGIC:8]).  The sig need not verify here — vcachefs
# detects it by the trailing SIG_MAGIC, so container_len < lower_size and the OLD
# passthrough would have truncated the footer off a copy.  §7 proves the new
# behavior serves the WHOLE file so the footer survives a backup through the mount.
cp "$ENC/libtest.so" "$ENC/libsigned.so"
python3 - "$ENC/libsigned.so" <<'PY'
import sys, struct
p = sys.argv[1]; d = open(p, "rb").read()
sig = b"\xA5" * 128
open(p, "wb").write(d + sig + struct.pack("<I", len(sig)) + bytes.fromhex("3d6af0128c55b427"))
PY

# An authorized loader (dlopen+dlsym+call).
cat > "$WORK/loader.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
	int (*f)(void) = dlsym(h, "antirevfs_answer");
	if (!f) { fprintf(stderr, "dlsym fail\n"); return 3; }
	printf("answer=%d\n", f());
	return f() == 42 ? 0 : 4;
}
EOF
gcc -o "$WORK/loader" "$WORK/loader.c" -ldl

cat > "$AUTHZ" <<EOF
# antirevfs passthrough test allow-list
$WORK/loader
EOF
chmod 0644 "$AUTHZ"

echo "== load module (gate_enforce=1, gate_passthrough_cipher=1) + key + mount =="
# NOTE: requires a dev-mode build (make AREV_DEV_MODE=1)
# key-in-.ko: build the module with the SAME key we packed with, then load
source "$KMOD/tests/keyhelper.sh"
arev_build_with_key "$WORK/key.hex" "$KMOD/module"
insmod "$MOD" gate_enforce=1 gate_passthrough_cipher=1 authz_path="$AUTHZ" \
	|| { echo "insmod failed"; exit 1; }
mount -t vcachefs -o ro "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted antirevfs (passthrough-cipher on)" || bad "mount missing"

echo "== 1. authorized program still reads decrypted content =="
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
echo "    loader: $OUT (rc=$RC)"
[[ $RC -eq 0 ]] && ok "authorized loader dlopen'd + called (answer=42)" \
	|| bad "authorized loader failed (rc=$RC)"

echo "== 2. cp (unlisted) succeeds but yields the whole keyless ciphertext (no key) =="
ENCSZ="$(stat -c%s "$ENC/libtest.so")"
if cp "$MP/libtest.so" "$WORK/out_cp" 2>"$WORK/cp.err"; then
	OUTSZ="$(stat -c%s "$WORK/out_cp")"
	if cmp -s "$WORK/out_cp" "$WORK/libtest.plain.so"; then
		bad "cp yielded PLAINTEXT (passthrough leaked decrypted content!)"
	elif cmp -s "$WORK/out_cp" "$ENC/libtest.so"; then
		# `cp FOO FOO_new` through the mount must be BYTE-IDENTICAL to the lower:
		# no header dropped (served from offset 0), no trailer dropped.
		ok "cp output is BYTE-IDENTICAL to the lower container ($OUTSZ bytes; nothing dropped — tar/backup-safe)"
	else
		bad "cp output differs from the lower container (OUTSZ=$OUTSZ ENCSZ=$ENCSZ; header/trailer dropped?)"
	fi
	# the embedded AES key (key.hex) must NOT appear anywhere in the stripped copy
	if python3 -c "import sys; d=open('$WORK/out_cp','rb').read(); k=bytes.fromhex(open('$WORK/key.hex').read().strip()); sys.exit(0 if k in d else 1)"; then
		bad "the embedded key LEAKED into the cp output"
	else
		ok "no key in the cp output (key lives in the .ko, never in the container)"
	fi
else
	bad "cp was denied (expected success with stripped ciphertext): $(cat "$WORK/cp.err")"
fi

echo "== 3. cat (unlisted) yields ciphertext (container magic, not the ELF) =="
MAGIC="$(head -c8 "$MP/libtest.so" 2>/dev/null | xxd -p)"
echo "    first 8 bytes (hex): '$MAGIC'"
[[ "$MAGIC" == "a74c2e91d63b085f" ]] && ok "cat sees the container magic header (ciphertext)" \
	|| bad "cat did not see ciphertext magic (got '$MAGIC')"

echo "== 4. objdump (unlisted) cannot parse it as an ELF =="
if command -v objdump >/dev/null 2>&1; then
	if objdump -d "$MP/libtest.so" >/dev/null 2>"$WORK/objdump.err"; then
		bad "objdump disassembled the mount (plaintext ELF leaked)"
	else
		ok "objdump refused it (not a recognized ELF): $(head -1 "$WORK/objdump.err")"
	fi
else
	echo "    (objdump not installed; skipping)"
fi

echo "== 5. flip gate_passthrough_cipher=0 -> deny returns to -EACCES =="
echo 0 > "$PASS_PARAM"
if cp "$MP/libtest.so" "$WORK/out_deny" 2>"$WORK/deny.err"; then
	bad "cp still succeeded after disabling passthrough"
else
	grep -qi "permission denied" "$WORK/deny.err" \
		&& ok "with passthrough off, cp is denied (-EACCES) again" \
		|| { ok "cp denied"; echo "    ($(cat "$WORK/deny.err"))"; }
fi
echo 1 > "$PASS_PARAM"

echo "== 6. lower .enc file is ciphertext =="
cmp -s "$ENC/libtest.so" "$WORK/libtest.plain.so" && bad "lower file is plaintext!" \
	|| ok "lower .enc file is ciphertext"

echo "== 7. a SIGNED container copies through the mount WITH its footer (tar-safe) =="
# Unlisted cp -> passthrough path.  The NEW behavior serves the WHOLE lower file
# (container + footer), so the copy is byte-identical to the lower and its
# signature footer survives — a backup taken through the mount still verifies.
# (The OLD behavior truncated at container_len, dropping the footer -> unsigned.)
SGN_SZ="$(stat -c%s "$ENC/libsigned.so")"
if cp "$MP/libsigned.so" "$WORK/out_signed" 2>"$WORK/cps.err"; then
	if cmp -s "$WORK/out_signed" "$ENC/libsigned.so"; then
		ok "passthrough copy of a signed container is byte-identical to the lower (footer preserved)"
	else
		bad "passthrough copy differs from lower (footer stripped? out=$(stat -c%s "$WORK/out_signed") lower=$SGN_SZ)"
	fi
	[[ "$(tail -c8 "$WORK/out_signed" | xxd -p)" == "3d6af0128c55b427" ]] \
		&& ok "signature footer present in the copy -> survives tar/backup through the mount" \
		|| bad "footer magic missing from the passthrough copy"
	# still no plaintext / no key leak on the signed path
	cmp -s "$WORK/out_signed" "$WORK/libtest.plain.so" && bad "signed passthrough copy is PLAINTEXT!" \
		|| ok "signed passthrough copy is still ciphertext (no plaintext leak)"
else
	bad "cp of signed container denied (expected passthrough success): $(cat "$WORK/cps.err")"
fi
# The OTHER direction: an AUTHORIZED read of the SIGNED container must decrypt to
# EXACTLY the original plaintext — the signature footer is NOT part of the
# plaintext (all crypto/size math uses container_len, which excludes it).  Flip
# the gate off so a plain read is authorized, then cmp against the pre-encryption
# file.  (libsigned's container == libtest's container, so the plaintext matches.)
GENF=/sys/module/vcachefs/parameters/gate_enforce
if [[ -w "$GENF" ]]; then
	echo 0 > "$GENF"
	if cmp -s "$MP/libsigned.so" "$WORK/libtest.plain.so"; then
		ok "authorized read of the signed container == original plaintext (footer excluded, byte-identical)"
	else
		bad "authorized read of signed container != original plaintext (footer bled into the plaintext?)"
	fi
	echo 1 > "$GENF"
else
	echo "    (gate_enforce param absent — release build; authorized-plaintext check skipped)"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
