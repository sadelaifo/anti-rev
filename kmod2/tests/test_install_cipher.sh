#!/bin/bash
# test_install_cipher.sh — exercise AREV_IOC_INSTALL_CIPHER (ctldev.c): drop an
# encrypted hot-patch into a LIVE vcachefs mount's lower (.enc) store at runtime,
# then read it back DECRYPTED through the mount.  This is the in-place-layover
# delivery path (no separate .enc dir visible to the client).
#
#   1. install a keyless FS_MAGIC container into MP/lib/patch_v1 via the ioctl
#   2. the on-disk lower file is CIPHERTEXT (carries the container magic)
#   3. an AUTHORIZED reader sees it DECRYPTED through the mount (== original)
#   4. re-installing the same leaf -> -EEXIST (never overwrites)
#   5. a non-FS_MAGIC blob -> -EINVAL (can't plant arbitrary files)
#   6. a NON-whitelisted caller -> -EACCES (gate)
#
# There is no standalone installer binary: the ioctl is meant to be called from
# your own (already-authorized) hot-patch tool.  This test builds a tiny inline
# helper `ic` (install + read modes) that makes the ioctl directly — the same
# ~15 lines you fold into your tool.
#
# Builds a THROWAWAY module embedding a test key + whitelisting `ic`'s basename
# (source tree untouched).  Requires root + gcc + python3 (+ shared/protect.py).
#   sudo bash test_install_cipher.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"; KMOD="$HERE/.."; ROOT="$KMOD/.."
PACK="$ROOT/shared/vcache-pack.py"; TOOLS="$KMOD/tools"
CC="${CC:-$(command -v gcc-12 || command -v gcc-4.8 || command -v gcc)}"
MAGIC_HEX="a74c2e91d63b085f"      # container magic (antirevfs.h ANTREV_MAGIC / FS_MAGIC)
PASS=0; FAIL=0; ok(){ echo "  [PASS] $*"; PASS=$((PASS+1)); }; bad(){ echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 1; }
[[ -n "$CC" ]] || { echo "no C compiler (set CC=)"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required (vendor key)"; exit 1; }

W="$(mktemp -d /tmp/arev_install.XXXXXX)"
ENC="$W/enc"; MP="$W/mp"; mkdir -p "$W/install/lib" "$MP"
cleanup(){ mountpoint -q "$MP" && umount "$MP"; rmmod vcachefs 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

echo "== throwaway module: embed key + whitelist the test helper 'ic' =="
bash "$TOOLS/authz-keygen.sh" "$W/keys" >/dev/null 2>&1 || { echo keygen failed; exit 1; }
cp -r "$KMOD/module" "$W/module"
bash "$TOOLS/authz-embed-pubkey.sh" "$W/keys/authz_cert.der" "$W/module/gate_authz_pubkey.h" >/dev/null
sed -i 's/^\tNULL$/\t"ic",\n\tNULL/' "$W/module/gate_whitelist.h"
python3 -c 'import os,sys;open(sys.argv[1],"w").write(os.urandom(32).hex())' "$W/key.hex"
python3 "$ROOT/shared/gen_key_blob.py" "$W/key.hex" "$W/module/key_blob.c" >/dev/null
make -C "$W/module" CC="$CC" >"$W/build.log" 2>&1 || { echo "MODULE BUILD FAILED:"; tail -40 "$W/build.log"; exit 1; }
MOD="$W/module/vcachefs.ko"; ok "module (with INSTALL_CIPHER) built"

echo "== build the inline helper (install + read via the ioctl) =="
cat > "$W/ic.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "arev_uapi.h"
int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s install <dest> <ctfile> | read <src> <out>\n", argv[0]); return 2; }
    if (!strcmp(argv[1], "install")) {
        int cf = open(argv[3], O_RDONLY); if (cf < 0) { perror("open ct"); return 3; }
        struct stat st; if (fstat(cf, &st)) { perror("fstat"); return 3; }
        size_t len = (size_t)st.st_size; void *d = malloc(len);
        if (!d || read(cf, d, len) != (ssize_t)len) { perror("read ct"); return 3; }
        close(cf);
        int ctl = open(AREV_DEV_PATH, O_RDWR); if (ctl < 0) { perror("open ctl"); return 4; }
        struct arev_install_arg a; memset(&a, 0, sizeof a);
        a.path = (uint64_t)(uintptr_t)argv[2]; a.path_len = (uint32_t)(strlen(argv[2]) + 1);
        a.mode = 0644; a.data = (uint64_t)(uintptr_t)d; a.data_len = (uint64_t)len;
        int r = ioctl(ctl, AREV_IOC_INSTALL_CIPHER, &a); int e = errno;
        if (r) { fprintf(stderr, "install %s: %s\n", argv[2], strerror(e)); return 1; }
        printf("installed %zu bytes -> %s\n", len, argv[2]); return 0;
    } else if (!strcmp(argv[1], "read")) {
        int fd = open(argv[2], O_RDONLY); if (fd < 0) { perror("open src"); return 1; }
        int o = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644); char b[65536]; ssize_t n;
        while ((n = read(fd, b, sizeof b)) > 0) if (write(o, b, n) != n) { perror("write"); return 1; }
        return 0;
    }
    return 2;
}
EOF
"$CC" -O2 -I "$W/module" -o "$W/ic" "$W/ic.c" || { echo "helper build failed"; exit 1; }
cp "$W/ic" "$W/notallowed"                 # same binary, NON-whitelisted basename
ok "inline helper built"

echo "== pack a tiny tree + mount =="
printf 'int answer(void){return 42;}\n' > "$W/t.c"
"$CC" -shared -fPIC -o "$W/install/lib/libsecret.so" "$W/t.c"
cat > "$W/cfg.yaml" <<EOF
install_dir: $W/install
output_dir: $ENC
key: key.hex
EOF
python3 "$PACK" --config "$W/cfg.yaml" >/dev/null 2>&1 || { echo pack failed; exit 1; }
insmod "$MOD" || { echo insmod failed; dmesg|tail -5; exit 1; }
[[ -e /dev/vcachefs ]] && ok "/dev/vcachefs present" || bad "/dev/vcachefs missing"
mount -t vcachefs "$ENC" "$MP" || { echo mount failed; dmesg|tail -5; exit 1; }

echo "== encrypt a hot-patch OFF-BOX with the project key (keyless FS_MAGIC) =="
PATCH_PLAIN="$W/patch_v1.plain"; PATCH_CT="$W/patch_v1.ct"
head -c 3000 /dev/urandom > "$PATCH_PLAIN"     # arbitrary (non-ELF) patch payload
python3 - "$ROOT" "$W/key.hex" "$PATCH_PLAIN" "$PATCH_CT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/shared")
from protect import make_container
key = bytes.fromhex(open(sys.argv[2]).read().strip())
data = open(sys.argv[3], "rb").read()
ct = make_container(data, key, embed_key=False, magic=bytes.fromhex("a74c2e91d63b085f"))
open(sys.argv[4], "wb").write(ct)
PY
[[ -s "$PATCH_CT" ]] && ok "patch encrypted to a keyless container" || bad "encrypt failed"

echo "== 1. INSTALL_CIPHER the patch into the LIVE mount =="
if "$W/ic" install "$MP/lib/patch_v1" "$PATCH_CT"; then ok "install reported success"; else bad "install failed"; fi

echo "== 2. the on-disk lower file is CIPHERTEXT =="
if [[ -f "$ENC/lib/patch_v1" ]]; then
    HDR=$(head -c8 "$ENC/lib/patch_v1" | xxd -p)
    [[ "$HDR" == "$MAGIC_HEX" ]] && ok "lower file carries the container magic (ciphertext at rest)" \
        || bad "lower file magic wrong ($HDR)"
    cmp -s "$ENC/lib/patch_v1" "$PATCH_PLAIN" && bad "lower file equals plaintext!" \
        || ok "lower file != plaintext"
else bad "lower file $ENC/lib/patch_v1 not created"; fi

echo "== 3. an AUTHORIZED reader sees it DECRYPTED through the mount =="
"$W/ic" read "$MP/lib/patch_v1" "$W/got.plain" 2>/dev/null
if [[ -f "$W/got.plain" ]] && cmp -s "$W/got.plain" "$PATCH_PLAIN"; then
    ok "mount served the patch decrypted (== original plaintext)"
else
    bad "decrypted read mismatch (got $(stat -c%s "$W/got.plain" 2>/dev/null || echo 0) bytes)"
fi

echo "== 4. re-install the same leaf -> refused (never overwrite) =="
if "$W/ic" install "$MP/lib/patch_v1" "$PATCH_CT" 2>/dev/null; then
    bad "re-install wrongly succeeded (overwrote)"
else
    ok "re-install refused (-EEXIST)"
fi

echo "== 5. a non-FS_MAGIC blob -> rejected =="
head -c 2000 /dev/urandom > "$W/garbage.bin"   # no container magic
if "$W/ic" install "$MP/lib/patch_bad" "$W/garbage.bin" 2>/dev/null; then
    bad "garbage blob wrongly installed"
else
    [[ ! -e "$ENC/lib/patch_bad" ]] && ok "garbage rejected and no partial file left" \
        || bad "garbage rejected but a partial file was left behind"
fi

echo "== 6. a NON-whitelisted caller is denied by the gate =="
if "$W/notallowed" install "$MP/lib/patch_v2" "$PATCH_CT" 2>/dev/null; then
    bad "non-whitelisted caller allowed (gate broken)"
else
    [[ ! -e "$ENC/lib/patch_v2" ]] && ok "non-whitelisted caller denied (-EACCES), nothing written" \
        || bad "denied but a file was written"
fi

echo; echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
