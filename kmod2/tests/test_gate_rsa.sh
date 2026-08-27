#!/bin/bash
# Signed-allow-list gate test (gate_require_sig=1): the allow-list is only
# trusted if a detached PKCS#7 signature verifies against the vendor public key
# embedded in the module — so a client editing the plaintext list de-authorizes
# it and cannot forge a new one.  Proves end to end:
#   1. signed list + authorized program -> reads decrypted content      (allow)
#   2. EDIT the list without re-signing  -> same program now denied      (tamper)
#   3. restore the signed list           -> allowed again                (recover)
#   4. remove the .p7s signature         -> denied (no sig => reject)     (missing)
#   5. gate_require_sig=0 on the edited list -> honored again             (control)
#
# Builds a THROWAWAY copy of the module embedding a test vendor key (source tree
# untouched).  Requires root + gcc + openssl + kernel PKCS#7 support
# (CONFIG_ASYMMETRIC_KEY_TYPE + CONFIG_PKCS7_MESSAGE_PARSER + X509 parser).
#   sudo bash test_gate_rsa.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
PROTECT="$ROOT/encryptor/protect.py"
TOOLS="$KMOD/tools"
CC="${CC:-$(command -v gcc-12 || command -v gcc-4.8 || command -v gcc)}"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
skip(){ echo "  [SKIP] $*"; }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
[[ -n "$CC" ]] || { echo "no C compiler found (set CC=)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_gate_rsa.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"
AUTHZ="$WORK/authorized_apps.txt"; SIG="$AUTHZ.p7s"
mkdir -p "$ENC" "$MP"
cleanup() { mountpoint -q "$MP" && umount "$MP"; rmmod vcachefs 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 1) vendor key + throwaway module embedding it =="
bash "$TOOLS/authz-keygen.sh" "$WORK/keys" >/dev/null 2>&1 || { echo "keygen failed"; exit 1; }
cp -r "$KMOD/module" "$WORK/module"
bash "$TOOLS/authz-embed-pubkey.sh" "$WORK/keys/authz_cert.der" > "$WORK/module/gate_authz_pubkey.h"
if ! make -C "$WORK/module" CC="$CC" AREV_DEV_MODE=1 >/"$WORK/build.log" 2>&1; then
	echo "module build failed:"; tail -20 "$WORK/build.log"; exit 1
fi
MOD="$WORK/module/vcachefs.ko"
[[ -f "$MOD" ]] || { echo "no .ko built"; exit 1; }

echo "== 2) build + encrypt a test lib, build a loader =="
cat > "$WORK/libtest.c" <<'EOF'
int antirevfs_answer(void){ return 42; }
EOF
"$CC" -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
python3 "$PROTECT" encrypt-lib --embed-key --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null
cat > "$WORK/loader.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc,char**argv){ void*h=dlopen(argv[1],RTLD_NOW);
	if(!h){fprintf(stderr,"dlopen:%s\n",dlerror());return 2;}
	int(*f)(void)=dlsym(h,"antirevfs_answer"); if(!f)return 3;
	printf("answer=%d\n",f()); return f()==42?0:4; }
EOF
"$CC" -o "$WORK/loader" "$WORK/loader.c" -ldl

echo "== 3) signed allow-list =="
printf '# signed allow-list\n%s\n' "$WORK/loader" > "$AUTHZ"; chmod 0644 "$AUTHZ"
bash "$TOOLS/authz-sign.sh" "$WORK/keys/authz_priv.pem" "$WORK/keys/authz_cert.pem" "$AUTHZ" "$SIG" \
	|| { echo "signing failed"; exit 1; }

echo "== load module: gate_enforce=1 gate_require_sig=1 =="
insmod "$MOD" gate_enforce=1 gate_require_sig=1 \
	authz_path="$AUTHZ" authz_sig_path="$SIG" || { echo "insmod failed"; dmesg|tail -5; exit 1; }
dmesg | tail -3 | grep -qi 'authz vendor key loaded' && ok "module loaded the embedded vendor key" \
	|| skip "no 'vendor key loaded' log (check CONFIG_PKCS7_MESSAGE_PARSER)"
mount -t vcachefs -o ro "$ENC" "$MP" || { echo "mount failed"; dmesg|tail -5; exit 1; }

echo "== 1. signed list + authorized program decrypts =="
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
[[ $RC -eq 0 && "$OUT" == *answer=42* ]] && ok "authorized read under a SIGNED list" \
	|| bad "authorized read failed under signed list (rc=$RC: $OUT) — kernel PKCS#7 support?"

echo "== 2. tamper: edit the list without re-signing -> denied =="
printf '# signed allow-list\n%s\nEVIL\n' "$WORK/loader" > "$AUTHZ"   # sig no longer matches
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
[[ $RC -ne 0 ]] && ok "edited (unsigned) list rejected -> program denied" \
	|| bad "edited list still authorized (signature not enforced!)"

echo "== 3. restore the signed list -> allowed again =="
printf '# signed allow-list\n%s\n' "$WORK/loader" > "$AUTHZ"        # back to signed content
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
[[ $RC -eq 0 ]] && ok "restored list verifies again -> allowed" \
	|| bad "restored list not accepted (rc=$RC)"

echo "== 4. remove the signature -> denied =="
mv "$SIG" "$SIG.bak"
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
[[ $RC -ne 0 ]] && ok "missing signature -> denied (fails safe)" || bad "no-signature list still authorized"
mv "$SIG.bak" "$SIG"

echo "== 5. control: gate_require_sig=0 honors the plaintext (edited) list =="
echo 0 > /sys/module/vcachefs/parameters/gate_require_sig
printf '# plaintext\n%s\n' "$WORK/loader" > "$AUTHZ"   # unsigned, but require_sig off
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
[[ $RC -eq 0 ]] && ok "require_sig=0 -> plaintext list honored (proves the sig gate is the enforcer)" \
	|| bad "require_sig=0 still denied (rc=$RC)"
echo 1 > /sys/module/vcachefs/parameters/gate_require_sig

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
