#!/bin/bash
# Per-exe signature + hard-coded whitelist gate test.  A process passes if
# EITHER (1) its exe carries a valid appended per-exe signature, OR (2) its
# basename is in the compiled-in whitelist (gate_whitelist.h).  No allow-list
# file is involved.  Proves end to end:
#   1. a SIGNED loader on the mount runs and reads an encrypted lib      (auth)
#   2. an UNSIGNED copy of the same loader is denied                     (auth)
#   3. tampering a signed container (flip a byte) -> denied              (integrity)
#   4. a WHITELISTED basename passes even unsigned                       (whitelist)
#   5. gate_enforce=0 -> all allowed                                     (control)
#
# Builds a THROWAWAY module embedding a test key + a test whitelist entry
# (source tree untouched).  Requires root + gcc + openssl + kernel PKCS#7
# (CONFIG_SYSTEM_DATA_VERIFICATION).   sudo bash test_gate_perexe.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"; KMOD="$HERE/.."; ROOT="$KMOD/.."
PACK="$ROOT/kmod2/tools/vcache-pack.py"; TOOLS="$KMOD/tools"
CC="${CC:-$(command -v gcc-12 || command -v gcc-4.8 || command -v gcc)}"
PASS=0; FAIL=0; ok(){ echo "  [PASS] $*"; PASS=$((PASS+1)); }; bad(){ echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
[[ -n "$CC" ]] || { echo "no C compiler (set CC=)"; exit 1; }

W="$(mktemp -d /tmp/arev_perexe.XXXXXX)"
ENC="$W/enc"; MP="$W/mp"; mkdir -p "$W/install/bin" "$MP"
cleanup(){ mountpoint -q "$MP" && umount "$MP"; rmmod vcachefs 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

echo "== vendor key + throwaway module (embed key + whitelist 'wlloader') =="
bash "$TOOLS/authz-keygen.sh" "$W/keys" >/dev/null 2>&1 || { echo keygen failed; exit 1; }
cp -r "$KMOD/module" "$W/module"
bash "$TOOLS/authz-embed-pubkey.sh" "$W/keys/authz_cert.der" > "$W/module/gate_authz_pubkey.h"
# add a test whitelist entry
sed -i 's/^\tNULL$/\t"wlloader",\n\tNULL/' "$W/module/gate_whitelist.h"
make -C "$W/module" CC="$CC" AREV_DEV_MODE=1 >"$W/build.log" 2>&1 || { echo "build failed:"; tail -20 "$W/build.log"; exit 1; }
MOD="$W/module/vcachefs.ko"

echo "== build loader (dlopen+call) + a lib; pack+SIGN the tree =="
cat > "$W/libans.c" <<'EOF'
int arev_ans(void){ return 42; }
EOF
"$CC" -shared -fPIC -o "$W/install/bin/libans.so" "$W/libans.c"
cat > "$W/loader.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c,char**v){ void*h=dlopen(v[1],RTLD_NOW); if(!h){fprintf(stderr,"dlopen %s\n",dlerror());return 2;}
  int(*f)(void)=dlsym(h,"arev_ans"); if(!f)return 3; printf("ans=%d\n",f()); return f()==42?0:4; }
EOF
"$CC" -o "$W/install/bin/sloader" "$W/loader.c" -ldl     # signed (non-.so -> gets a sig)
cp "$W/install/bin/sloader" "$W/install/bin/uloader"     # will strip its sig -> unsigned
cp "$W/install/bin/sloader" "$W/install/bin/wlloader"    # whitelisted basename
cat > "$W/cfg.yaml" <<EOF
install_dir: $W/install
output_dir: $ENC
key: key.hex
sign_key: $W/keys/authz_priv.pem
sign_cert: $W/keys/authz_cert.pem
EOF
python3 "$PACK" "$W/cfg.yaml" >/dev/null 2>&1 || { echo pack failed; exit 1; }
# make uloader UNSIGNED: re-encrypt it without a sig (strip the appended section
# by re-packing just it via protect.py encrypt-lib, which never appends a sig)
python3 "$ROOT/encryptor/protect.py" encrypt-lib --embed-key --key "$W/uk.hex" \
        --libs "$W/install/bin/uloader" --output-dir "$ENC/bin" >/dev/null 2>&1
# ...but that uses a different key; simpler: truncate the sig off uloader so it
# ends in ANTREV01 (no ANTRSIG1) -> unsigned, still decrypts.
python3 - "$ENC/bin/uloader" <<'PY'
import sys,struct
p=sys.argv[1]; b=open(p,'rb').read()
if b[-8:]==bytes.fromhex("3d6af0128c55b427"):
    slen=struct.unpack('<I',b[-12:-8])[0]; open(p,'wb').write(b[:-12-slen])
PY

echo "== load module (gate_enforce=1, per-exe mode; no allow-list) + mount =="
insmod "$MOD" gate_enforce=1 || { echo insmod failed; dmesg|tail -5; exit 1; }
mount -t vcachefs -o ro,passdata "$ENC" "$MP" || { echo mount failed; dmesg|tail -5; exit 1; }
chmod +x "$MP/bin/sloader" "$MP/bin/uloader" "$MP/bin/wlloader" 2>/dev/null || true

echo "== 1. signed loader runs + reads the encrypted lib =="
OUT="$("$MP/bin/sloader" "$MP/bin/libans.so" 2>&1)"; RC=$?
[[ $RC -eq 0 && "$OUT" == *ans=42* ]] && ok "signed exe authorized (exec + lib read) -> 42" \
	|| bad "signed exe failed (rc=$RC: $OUT) — kernel PKCS#7?"

echo "== 2. unsigned loader is denied =="
OUT="$("$MP/bin/uloader" "$MP/bin/libans.so" 2>&1)"; RC=$?
[[ $RC -ne 0 ]] && ok "unsigned exe denied (rc=$RC)" || bad "unsigned exe ran (gate broken)"

echo "== 3. tampered signed loader is denied =="
# flip a byte inside sloader's container in the lower tree, then remount so the
# inode re-classifies (verdict is cached per inode).
umount "$MP"
python3 - "$ENC/bin/sloader" <<'PY'
import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[64]^=0xff; open(p,'wb').write(b)
PY
mount -t vcachefs -o ro,passdata "$ENC" "$MP"; chmod +x "$MP/bin/sloader" 2>/dev/null || true
OUT="$("$MP/bin/sloader" "$MP/bin/libans.so" 2>&1)"; RC=$?
[[ $RC -ne 0 ]] && ok "tampered signed exe denied (rc=$RC)" || bad "tampered exe ran (integrity broken)"

echo "== 4. whitelisted basename passes (even though we strip its sig) =="
umount "$MP"
python3 - "$ENC/bin/wlloader" <<'PY'
import sys,struct; p=sys.argv[1]; b=open(p,'rb').read()
if b[-8:]==bytes.fromhex("3d6af0128c55b427"):
    slen=struct.unpack('<I',b[-12:-8])[0]; open(p,'wb').write(b[:-12-slen])
PY
mount -t vcachefs -o ro,passdata "$ENC" "$MP"; chmod +x "$MP/bin/wlloader" 2>/dev/null || true
OUT="$("$MP/bin/wlloader" "$MP/bin/libans.so" 2>&1)"; RC=$?
[[ $RC -eq 0 && "$OUT" == *ans=42* ]] && ok "whitelisted basename authorized (no sig needed)" \
	|| bad "whitelisted exe denied (rc=$RC: $OUT)"

echo "== 5. control: gate_enforce=0 -> unsigned uloader runs =="
echo 0 > /sys/module/vcachefs/parameters/gate_enforce
OUT="$("$MP/bin/uloader" "$MP/bin/libans.so" 2>&1)"; RC=$?
[[ $RC -eq 0 ]] && ok "gate off -> unsigned runs (proves the gate was enforcing)" \
	|| bad "gate off still denied (rc=$RC)"

echo; echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
