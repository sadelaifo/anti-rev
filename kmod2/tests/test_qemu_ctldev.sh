#!/bin/bash
# test_qemu_ctldev.sh — exercise the /dev/vcachefs control device (ctldev.c) in
# ISOLATION, without building qemu.  A tiny C helper impersonates the emulator and
# drives the ioctls directly:
#   1. AUTHORIZE_FD on a SIGNED binary       -> 0 (authorized)
#   2. AUTHORIZE_FD on an UNSIGNED binary    -> denied
#   3. OPEN_CIPHER on an encrypted mount file-> keyless container (magic present,
#                                               size == container-40, no key)
#   4. caller gate: a NON-whitelisted helper -> every ioctl -EACCES
#
# Builds a THROWAWAY module embedding a test key + whitelisting the helper's
# basename (source tree untouched).  Requires root + gcc + openssl + kernel
# PKCS#7 (CONFIG_SYSTEM_DATA_VERIFICATION).   sudo bash test_qemu_ctldev.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"; KMOD="$HERE/.."; ROOT="$KMOD/.."
PACK="$ROOT/kmod2/tools/vcache-pack.py"; TOOLS="$KMOD/tools"
SIGNEXE="$TOOLS/authz-sign-exe.py"
CC="${CC:-$(command -v gcc-12 || command -v gcc-4.8 || command -v gcc)}"
MAGIC_HEX="a74c2e91d63b085f"      # container magic (antirevfs.h ANTREV_MAGIC)
PASS=0; FAIL=0; ok(){ echo "  [PASS] $*"; PASS=$((PASS+1)); }; bad(){ echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
[[ -n "$CC" ]] || { echo "no C compiler (set CC=)"; exit 1; }

W="$(mktemp -d /tmp/arev_ctl.XXXXXX)"
ENC="$W/enc"; MP="$W/mp"; mkdir -p "$W/install/bin" "$W/install/lib" "$MP"
cleanup(){ mountpoint -q "$MP" && umount "$MP"; rmmod vcachefs 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

echo "== vendor key + throwaway module (embed key + whitelist 'arevctl') =="
bash "$TOOLS/authz-keygen.sh" "$W/keys" >/dev/null 2>&1 || { echo keygen failed; exit 1; }
cp -r "$KMOD/module" "$W/module"
bash "$TOOLS/authz-embed-pubkey.sh" "$W/keys/authz_cert.der" "$W/module/gate_authz_pubkey.h" >/dev/null
sed -i 's/^\tNULL$/\t"arevctl",\n\tNULL/' "$W/module/gate_whitelist.h"
make -C "$W/module" CC="$CC" >"$W/build.log" 2>&1 || { echo "MODULE BUILD FAILED:"; tail -30 "$W/build.log"; exit 1; }
MOD="$W/module/vcachefs.ko"
ok "module (with ctldev.o) built"

echo "== build helper (drives the ioctls) =="
cp "$W/module/arev_uapi.h" "$W/arev_uapi.h"
cat > "$W/arevctl.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "arev_uapi.h"
int main(int argc, char **argv){
    if(argc<3){fprintf(stderr,"usage: %s authorize <file> | cipher <path> <out>\n",argv[0]);return 2;}
    int ctl=open(AREV_DEV_PATH,O_RDWR);
    if(ctl<0){perror("open /dev/vcachefs");return 3;}
    if(!strcmp(argv[1],"authorize")){
        int fd=open(argv[2],O_RDONLY); if(fd<0){perror("open target");return 4;}
        int r=ioctl(ctl,AREV_IOC_AUTHORIZE_FD,(unsigned long)fd); int e=errno;
        printf("authorize %s -> %d (%s)\n",argv[2],r,r?strerror(e):"ok");
        return r==0?0:1;
    } else if(!strcmp(argv[1],"cipher")){
        struct arev_cipher_arg a; memset(&a,0,sizeof a);
        a.path=(uint64_t)(uintptr_t)argv[2]; a.path_len=strlen(argv[2])+1; a.out_fd=-1;
        int r=ioctl(ctl,AREV_IOC_OPEN_CIPHER,&a); int e=errno;
        if(r!=0){printf("cipher %s -> err (%s)\n",argv[2],strerror(e));return 1;}
        int of=open(argv[3],O_WRONLY|O_CREAT|O_TRUNC,0644);
        char buf[4096]; ssize_t n; long tot=0;
        while((n=read(a.out_fd,buf,sizeof buf))>0){ if(write(of,buf,n)!=n){perror("write");break;} tot+=n; }
        close(of); close(a.out_fd);
        printf("cipher %s -> fd %d, %ld bytes -> %s\n",argv[2],a.out_fd,tot,argv[3]);
        return 0;
    }
    return 2;
}
EOF
"$CC" -O2 -I "$W" -o "$W/arevctl" "$W/arevctl.c" || { echo "helper build failed"; exit 1; }
cp "$W/arevctl" "$W/notallowed"          # same binary, non-whitelisted basename
ok "helper built"

echo "== build a signed exe + an unsigned exe + an encrypted lib; pack + mount =="
printf 'int main(void){return 0;}\n' > "$W/m.c"
"$CC" -o "$W/install/bin/signed_app" "$W/m.c"
"$CC" -o "$W/install/bin/plain_app"  "$W/m.c"
printf 'int answer(void){return 42;}\n' > "$W/t.c"
"$CC" -shared -fPIC -o "$W/install/lib/libsecret.so" "$W/t.c"
cat > "$W/cfg.yaml" <<EOF
install_dir: $W/install
output_dir: $ENC
key: key.hex
EOF
python3 "$PACK" "$W/cfg.yaml" >/dev/null 2>&1 || { echo pack failed; exit 1; }
# sign the "signed_app" plaintext binary (option-1 form) OUTSIDE the enc tree so
# we can AUTHORIZE it; the packer already encrypted the enc-tree copies.
cp "$W/install/bin/signed_app" "$W/signed_app"
cp "$W/install/bin/plain_app"  "$W/plain_app"
python3 "$SIGNEXE" "$W/keys/authz_priv.pem" "$W/keys/authz_cert.pem" "$W/signed_app" >/dev/null 2>&1 \
    || { echo "sign-exe failed (openssl?)"; exit 1; }

insmod "$MOD" || { echo insmod failed; dmesg|tail -5; exit 1; }
[[ -e /dev/vcachefs ]] && ok "/dev/vcachefs created" || bad "/dev/vcachefs missing"
mount -t vcachefs -o ro,passdata "$ENC" "$MP" || { echo mount failed; dmesg|tail -5; exit 1; }

echo "== 1. AUTHORIZE a signed binary -> authorized =="
"$W/arevctl" authorize "$W/signed_app" && ok "signed_app authorized" || bad "signed_app NOT authorized (PKCS#7?)"

echo "== 2. AUTHORIZE an unsigned binary -> denied =="
"$W/arevctl" authorize "$W/plain_app" && bad "plain_app wrongly authorized" || ok "plain_app denied"

echo "== 3. OPEN_CIPHER an encrypted mount file -> keyless container =="
ENCSZ=$(stat -c%s "$ENC/lib/libsecret.so")
"$W/arevctl" cipher "$MP/lib/libsecret.so" "$W/leak.bin" || bad "OPEN_CIPHER failed"
if [[ -f "$W/leak.bin" ]]; then
    LSZ=$(stat -c%s "$W/leak.bin"); HDR=$(head -c8 "$W/leak.bin" | xxd -p)
    [[ "$HDR" == "$MAGIC_HEX" ]] && ok "cipher output carries the container magic" \
        || bad "cipher output magic wrong ($HDR)"
    [[ "$LSZ" -eq $((ENCSZ-40)) ]] && ok "cipher output is trailer-stripped (enc-40 = $LSZ)" \
        || bad "cipher output size $LSZ != enc-40 $((ENCSZ-40)) (key may be exposed!)"
    # the last 8 bytes must NOT be the trailing magic (trailer stripped)
    TAIL=$(tail -c8 "$W/leak.bin" | xxd -p)
    [[ "$TAIL" != "$MAGIC_HEX" ]] && ok "no trailing key-magic (trailer removed)" \
        || bad "trailing magic present -> key trailer NOT stripped"
else bad "no cipher output produced"; fi

echo "== 4. caller gate: non-whitelisted helper is refused =="
"$W/notallowed" authorize "$W/signed_app"; RC=$?
[[ $RC -ne 0 ]] && ok "non-whitelisted caller denied (rc=$RC)" || bad "non-whitelisted caller allowed (gate broken)"

echo; echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
