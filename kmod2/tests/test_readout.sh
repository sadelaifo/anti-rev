#!/bin/bash
# test_readout.sh — exercise kmod2/tools/vcache-readout against a LIVE vcachefs
# mount, proving it faithfully captures and labels exactly what the read gate
# serves THIS process.  This is the end-to-end test the tool's static-fixture
# self-test could not cover (EACCES deny, decrypted-plaintext, passthrough
# ciphertext, signature-footer survival).
#
# The gate keys on the READER's exe identity (current->mm->exe_file), so we use
# two copies of the tool: rd_auth (in the dev allow-list → authorized) and
# rd_unauth (unlisted → unauthorized).  Same bytes on disk, different verdict —
# which is the whole point of the gate.
#
# Proves:
#   1. mount comes up
#   2. authorized readout of an encrypted .so -> ELF magic, "DECRYPTED PLAINTEXT",
#      and the dumped bytes == the original plaintext lib (byte-faithful plaintext)
#   3. unauthorized readout, gate_passthrough_cipher=0 -> open() EACCES, tool exits
#      2, prints "read gate DENIED", and writes NO output file
#   4. unauthorized readout, gate_passthrough_cipher=1 -> container magic,
#      "CIPHERTEXT served", dumped bytes == the lower .enc container (byte-faithful)
#   5. unauthorized readout of a SIGNED container, passthrough=1 -> container magic
#      AND "SIGNATURE FOOTER present"; dump is byte-faithful incl. the footer
#   6. control: gate_enforce=0 -> the SAME unauthorized tool now gets plaintext,
#      proving the gate (not the tool) is the enforcer
#
# Requires root (insmod/mount) and a DEV-mode build (gate_enforce/authz_path).
# Run:  sudo bash test_readout.sh
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
TOOL="$KMOD/tools/vcache-readout"
ENFORCE=/sys/module/vcachefs/parameters/gate_enforce
PASS_PARAM=/sys/module/vcachefs/parameters/gate_passthrough_cipher

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }

WORK="$(mktemp -d /tmp/vcachefs_readout.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"; AUTHZ="$WORK/authorized_apps.txt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod vcachefs 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build the tool + test artifacts =="
make -C "$KMOD/tools" vcache-readout >/dev/null || { echo "tool build failed"; exit 1; }
# Two identical copies at different paths: only rd_auth is allow-listed.
cp "$TOOL" "$WORK/rd_auth"; cp "$TOOL" "$WORK/rd_unauth"
chmod +x "$WORK/rd_auth" "$WORK/rd_unauth"

cat > "$WORK/libtest.c" <<'EOF'
int vcachefs_answer(void) { return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
cp "$WORK/libtest.so" "$WORK/libtest.plain.so"   # reference plaintext

python3 "$PROTECT" encrypt-lib --fs --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

# A SIGNED container: encrypted lib + synthetic per-exe footer
# ([sig][sig_len:4 LE][SIG_MAGIC:8]).  The sig need not verify — the tool
# detects the footer by the trailing SIG_MAGIC.
cp "$ENC/libtest.so" "$ENC/libsigned.so"
python3 - "$ENC/libsigned.so" <<'PY'
import sys, struct
p = sys.argv[1]; d = open(p, "rb").read()
sig = b"\xA5" * 128
open(p, "wb").write(d + sig + struct.pack("<I", len(sig)) + bytes.fromhex("3d6af0128c55b427"))
PY

cat > "$AUTHZ" <<EOF
# readout test allow-list (authorized reader only)
$WORK/rd_auth
EOF
chmod 0644 "$AUTHZ"

echo "== load module (gate_enforce=1) + build with key + mount =="
# NOTE: requires a dev-mode build (make AREV_DEV_MODE=1); keyhelper defaults to it.
source "$KMOD/tests/keyhelper.sh"
arev_build_with_key "$WORK/key.hex" "$KMOD/module"
insmod "$MOD" gate_enforce=1 gate_passthrough_cipher=0 authz_path="$AUTHZ" \
	|| { echo "insmod failed"; exit 1; }
mount -t vcachefs -o ro "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted vcachefs" || bad "mount missing"

echo "== 2. authorized readout -> decrypted plaintext, byte-faithful =="
OUT="$("$WORK/rd_auth" "$MP/libtest.so" "$WORK/got_auth" 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "DECRYPTED PLAINTEXT" \
	&& cmp -s "$WORK/got_auth" "$WORK/libtest.plain.so"; then
	ok "authorized reader got the decrypted ELF, byte-identical to the plaintext lib"
else
	bad "authorized readout wrong (rc=$RC)"
fi

echo "== 3. unauthorized readout, passthrough=0 -> EACCES, no output file =="
rm -f "$WORK/got_deny"
OUT="$("$WORK/rd_unauth" "$MP/libtest.so" "$WORK/got_deny" 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -eq 2 ]] && echo "$OUT" | grep -q "read gate DENIED" && [[ ! -e "$WORK/got_deny" ]]; then
	ok "unauthorized reader denied at open() (EACCES), no bytes written"
else
	bad "expected EACCES deny with no output (rc=$RC, file exists? $([[ -e "$WORK/got_deny" ]] && echo yes || echo no))"
fi

echo "== 4. unauthorized readout, passthrough=1 -> keyless ciphertext, byte-faithful =="
echo 1 > "$PASS_PARAM"
OUT="$("$WORK/rd_unauth" "$MP/libtest.so" "$WORK/got_ct" 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "CIPHERTEXT served" \
	&& cmp -s "$WORK/got_ct" "$ENC/libtest.so"; then
	ok "unauthorized reader got the whole keyless container, byte-identical to the lower .enc"
else
	bad "passthrough ciphertext readout wrong (rc=$RC)"
fi
# and it is NOT the plaintext
cmp -s "$WORK/got_ct" "$WORK/libtest.plain.so" && bad "passthrough leaked plaintext!" \
	|| ok "passthrough output is NOT the plaintext ELF"

echo "== 5. unauthorized readout of a SIGNED container -> footer survives =="
OUT="$("$WORK/rd_unauth" "$MP/libsigned.so" "$WORK/got_signed" 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "SIGNATURE FOOTER present" \
	&& cmp -s "$WORK/got_signed" "$ENC/libsigned.so"; then
	ok "signed container copied through the mount with its footer intact (tar-safe)"
else
	bad "signed-container readout wrong (rc=$RC)"
fi
echo 0 > "$PASS_PARAM"

echo "== 6. control: gate_enforce=0 -> the SAME unlisted tool now gets plaintext =="
echo 0 > "$ENFORCE"
OUT="$("$WORK/rd_unauth" "$MP/libtest.so" "$WORK/got_off" 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "DECRYPTED PLAINTEXT" \
	&& cmp -s "$WORK/got_off" "$WORK/libtest.plain.so"; then
	ok "with gating off, the unlisted tool reads plaintext -> the GATE was the enforcer"
else
	bad "gate-off readout did not yield plaintext (rc=$RC)"
fi
echo 1 > "$ENFORCE"

echo "== 7. lower .enc file is ciphertext =="
cmp -s "$ENC/libtest.so" "$WORK/libtest.plain.so" && bad "lower file is plaintext!" \
	|| ok "lower .enc file is ciphertext"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
