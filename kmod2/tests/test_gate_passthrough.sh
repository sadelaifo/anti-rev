#!/bin/bash
# gate_passthrough_cipher test for antirevfs (embedded-key format): when an
# unauthorized process reads an encrypted file, instead of -EACCES it is served
# the lower .enc/ ciphertext WITH THE KEY TRAILER STRIPPED — a valid-looking but
# keyless, undecryptable ANTREV01 container.  Security is unchanged (no plaintext
# AND no key escapes); the difference is posture — the read "succeeds" with
# useless bytes rather than a permission error that advertises the gate.  Proves:
#   1. an authorized program still reads DECRYPTED content through the mount
#   2. cp (unlisted) SUCCEEDS but yields the container minus the 40-byte key
#      trailer (key + trailing magic), and the embedded key is NOT in the output
#   3. cat (unlisted) yields ciphertext (ANTREV01 magic, not the plaintext ELF)
#   4. an unauthorized objdump sees "not an ELF" — no symbols leak
#   5. flipping gate_passthrough_cipher=0 restores the -EACCES deny
#   6. the lower .enc file is (still) ciphertext
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
MOD="$KMOD/module/antirevfs.ko"
PROTECT="$ROOT/encryptor/protect.py"
KEYCTL="$KMOD/tools/antirev-keyctl"
PASS_PARAM=/sys/module/antirevfs/parameters/gate_passthrough_cipher

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_passthru.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"; AUTHZ="$WORK/authorized_apps.txt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod antirevfs 2>/dev/null
	"$KEYCTL" clear >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build test artifacts =="
cat > "$WORK/libtest.c" <<'EOF'
int antirevfs_answer(void) { return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
cp "$WORK/libtest.so" "$WORK/libtest.plain.so"   # reference plaintext

python3 "$PROTECT" encrypt-lib --embed-key --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

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
insmod "$MOD" gate_enforce=1 gate_passthrough_cipher=1 authz_path="$AUTHZ" \
	|| { echo "insmod failed"; exit 1; }
mount -t antirevfs -o ro "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted antirevfs (passthrough-cipher on)" || bad "mount missing"

echo "== 1. authorized program still reads decrypted content =="
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
echo "    loader: $OUT (rc=$RC)"
[[ $RC -eq 0 ]] && ok "authorized loader dlopen'd + called (answer=42)" \
	|| bad "authorized loader failed (rc=$RC)"

echo "== 2. cp (unlisted) succeeds but yields TRAILER-STRIPPED ciphertext (no key) =="
ENCSZ="$(stat -c%s "$ENC/libtest.so")"
if cp "$MP/libtest.so" "$WORK/out_cp" 2>"$WORK/cp.err"; then
	OUTSZ="$(stat -c%s "$WORK/out_cp")"
	if cmp -s "$WORK/out_cp" "$WORK/libtest.plain.so"; then
		bad "cp yielded PLAINTEXT (passthrough leaked decrypted content!)"
	elif [[ "$OUTSZ" -eq "$((ENCSZ - 40))" ]]; then
		ok "cp output is the .enc container minus the 40-byte key trailer ($OUTSZ = $ENCSZ-40)"
	else
		bad "cp output size $OUTSZ != enc-40 ($((ENCSZ - 40)))"
	fi
	# the embedded AES key (key.hex) must NOT appear anywhere in the stripped copy
	if python3 -c "import sys; d=open('$WORK/out_cp','rb').read(); k=bytes.fromhex(open('$WORK/key.hex').read().strip()); sys.exit(0 if k in d else 1)"; then
		bad "the embedded key LEAKED into the cp output"
	else
		ok "embedded key absent from the cp output (trailer withheld)"
	fi
else
	bad "cp was denied (expected success with stripped ciphertext): $(cat "$WORK/cp.err")"
fi

echo "== 3. cat (unlisted) yields ciphertext (ANTREV01 magic, not the ELF) =="
MAGIC="$(head -c 8 "$MP/libtest.so" 2>/dev/null)"
echo "    first 8 bytes: '$MAGIC'"
[[ "$MAGIC" == "ANTREV01" ]] && ok "cat sees the ANTREV01 container header (ciphertext)" \
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

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
