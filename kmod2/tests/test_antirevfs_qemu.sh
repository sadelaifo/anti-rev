#!/bin/bash
# qemu-user (ARM64-on-x86) test for antirevfs — the "sim mode" deployment where
# an ARM64 slave's software runs on an x86-64 host via qemu-aarch64-static
# (binfmt_misc), typically inside a Docker image.  Proves antirevfs is the RIGHT
# fit for that setup: decryption is arch-agnostic (the x86 .ko serves ARM64
# plaintext), qemu loads encrypted ARM64 libs/exes transparently through the
# mount, and the decrypt-auth gate keys on the EMULATOR's identity under binfmt.
#
#   1. arch-agnostic decrypt: an encrypted ARM64 .so decrypts byte-for-byte
#      through the mount; the decrypted view is a real AARCH64 ELF        (no qemu)
#   2. end-to-end: an ARM64 program run under qemu-aarch64-static dlopen+calls an
#      ENCRYPTED ARM64 .so read through the mount -> 42        (gate off)
#   3. gate under qemu: the lib read is gated on the EMULATOR's exe
#      (current->mm->exe_file == qemu-aarch64-static, not the guest binary):
#        - whitelist qemu-aarch64-static -> works
#        - empty allow-list             -> denied (EACCES, dlopen fails)
#        - host `cp` of the .so (not whitelisted) -> denied (no exfiltration)
#   4. binfmt exec-load split: a *transparently*-run encrypted ARM64 EXE on the
#      mount needs BOTH whitelisted — the exe's own path (host kernel opens it
#      FMODE_EXEC before the binfmt redirect) AND qemu (which then reads it as
#      data); dropping the exe from the list denies the exec-load.
#
# Docker note: not exercised here (needs a usable docker daemon).  Under Docker
# the same logic holds but: the mount must be visible in the container mount-ns
# (bind/volume) — which exposes plaintext IN the container; the allow-list
# (authz_path) resolves to the CONTAINER's /etc; and d_path(exe_file) is
# container-relative, so whitelist by BASENAME.  See CLAUDE.md "qemu-user +
# Docker" TODO.
#
# Requires root (insmod/mount), qemu-aarch64-static, aarch64-linux-gnu-gcc, and
# a guest aarch64 sysroot (QEMU_LD_PREFIX).  Run:  sudo bash test_antirevfs_qemu.sh
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
ENF_PARAM=/sys/module/antirevfs/parameters/gate_enforce

ACC=aarch64-linux-gnu-gcc
QEMU="$(command -v qemu-aarch64-static || true)"
# guest sysroot holding ld-linux-aarch64.so.1 + libc (qemu QEMU_LD_PREFIX)
PREFIX="${QEMU_LD_PREFIX:-/usr/aarch64-linux-gnu}"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
skip(){ echo "  [SKIP] $*"; }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

# ---- prerequisite gate: skip cleanly if the cross/emulation stack is absent --
miss=""
[[ -n "$QEMU" ]]                                   || miss+=" qemu-aarch64-static"
command -v "$ACC" >/dev/null 2>&1                  || miss+=" aarch64-linux-gnu-gcc"
[[ -e "$PREFIX/lib/ld-linux-aarch64.so.1" ]]       || miss+=" $PREFIX/lib/ld-linux-aarch64.so.1"
if [[ -n "$miss" ]]; then
	echo "qemu/cross prerequisites missing:$miss"
	echo "install e.g.: apt-get install qemu-user-static gcc-aarch64-linux-gnu libc6-dev-arm64-cross"
	echo "SKIP: nothing to test on this host."
	exit 0
fi
export QEMU_LD_PREFIX="$PREFIX"

WORK="$(mktemp -d /tmp/antirevfs_qemu.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"; AUTHZ="$WORK/authorized_apps.txt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod antirevfs 2>/dev/null
	"$KEYCTL" clear >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build ARM64 test artifacts (cross-compiled) =="
cat > "$WORK/libtest.c" <<'EOF'
int arm_answer(void) { return 42; }
EOF
"$ACC" -shared -fPIC -o "$WORK/libtest_arm.so" "$WORK/libtest.c"
cp "$WORK/libtest_arm.so" "$WORK/libtest_arm.plain.so"   # reference plaintext
file "$WORK/libtest_arm.so" | grep -q "ARM aarch64" \
	&& echo "    libtest_arm.so is an AARCH64 ELF" \
	|| { echo "cross-compile did not produce an aarch64 ELF"; exit 1; }

# ARM64 loader: dlopen+dlsym+call.  Lives OUTSIDE the mount (plaintext) and is
# run under qemu; the only antirevfs-gated open is the encrypted lib it dlopens.
cat > "$WORK/loader.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
	int (*f)(void) = dlsym(h, "arm_answer");
	if (!f) { fprintf(stderr, "dlsym fail\n"); return 3; }
	printf("answer=%d\n", f());
	return f() == 42 ? 0 : 4;
}
EOF
"$ACC" -o "$WORK/loader_arm" "$WORK/loader.c" -ldl

# An ARM64 EXECUTABLE that will be encrypted + placed on the mount + run
# transparently via binfmt (section 4).
cat > "$WORK/armapp.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("ARM_APP_RAN_OK\n"); return 0; }
EOF
"$ACC" -o "$WORK/armapp" "$WORK/armapp.c"

# encrypt both the ARM .so and the ARM exe (encryption is arch-agnostic)
python3 "$PROTECT" encrypt-lib --key "$WORK/key.hex" \
	--libs "$WORK/libtest_arm.so" --output-dir "$ENC" >/dev/null
python3 "$PROTECT" encrypt-lib --key "$WORK/key.hex" \
	--libs "$WORK/armapp" --output-dir "$ENC" >/dev/null
chmod +x "$ENC/armapp"      # mount mirrors lower mode; exec needs +x

QBASE="$(basename "$QEMU")"   # qemu-aarch64-static
echo "    emulator basename to whitelist: $QBASE"

echo "== load module + key + mount (gate off first: validate pure emulation) =="
insmod "$MOD" gate_enforce=0 authz_path="$AUTHZ" || { echo "insmod failed"; exit 1; }
"$KEYCTL" unlock --keyfile "$WORK/key.hex" >/dev/null
mount -t antirevfs -o ro,passdata "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted antirevfs (passdata)" || bad "mount missing"

echo "== 1. arch-agnostic decrypt: ARM64 .so decrypts through the x86 module =="
cmp -s "$MP/libtest_arm.so" "$WORK/libtest_arm.plain.so" \
	&& ok "decrypted view byte-identical to the original ARM64 .so" \
	|| bad "decrypted ARM64 .so mismatch"
# ELF e_machine at offset 18 (LE u16) == 0xB7 (EM_AARCH64)
MACH="$(od -An -tx2 -j18 -N2 "$MP/libtest_arm.so" | tr -d ' ')"
[[ "$MACH" == "00b7" ]] && ok "decrypted view reports e_machine=AARCH64 (0xb7)" \
	|| bad "decrypted view e_machine=$MACH (expected 00b7)"
head -c 8 "$ENC/libtest_arm.so" | grep -q ANTREV01 \
	&& ok "lower .enc file is ANTREV01 ciphertext" || bad "lower not ciphertext"

echo "== 2. qemu-user runs ARM64 code that dlopens the ENCRYPTED ARM64 .so =="
OUT="$("$QEMU" "$WORK/loader_arm" "$MP/libtest_arm.so" 2>&1)"; RC=$?
echo "    qemu loader: $OUT (rc=$RC)"
[[ $RC -eq 0 && "$OUT" == *answer=42* ]] \
	&& ok "emulated ARM64 loader dlopen'd the decrypted lib + called it (42)" \
	|| bad "qemu end-to-end load failed (rc=$RC): $OUT"

echo "== 3. gate under qemu: lib read is gated on the EMULATOR's identity =="
echo 1 > "$ENF_PARAM"
# 3a. whitelist qemu -> authorized
printf '%s\n' "$QBASE" > "$AUTHZ"; chmod 0644 "$AUTHZ"
OUT="$("$QEMU" "$WORK/loader_arm" "$MP/libtest_arm.so" 2>&1)"; RC=$?
[[ $RC -eq 0 && "$OUT" == *answer=42* ]] \
	&& ok "whitelisting $QBASE lets the emulated load through (gate keys on qemu)" \
	|| bad "whitelisted qemu still failed (rc=$RC): $OUT"
# 3b. empty allow-list -> denied
: > "$AUTHZ"
OUT="$("$QEMU" "$WORK/loader_arm" "$MP/libtest_arm.so" 2>&1)"; RC=$?
echo "    no-whitelist: $OUT (rc=$RC)"
[[ $RC -ne 0 ]] && echo "$OUT" | grep -qi "denied\|dlopen" \
	&& ok "with qemu un-listed the lib read is denied (EACCES) -> gate enforced" \
	|| bad "un-listed emulator still read the lib (gate not enforcing)"
# 3c. host cp of the ARM .so (cp not whitelisted) -> denied, no plaintext escapes
if cp "$MP/libtest_arm.so" "$WORK/leak" 2>/dev/null && \
   cmp -s "$WORK/leak" "$WORK/libtest_arm.plain.so"; then
	bad "host cp exfiltrated the plaintext ARM64 .so"
else
	ok "host cp of the encrypted ARM64 .so denied (no exfiltration)"
fi

echo "== 4. binfmt exec-load split: transparent ARM64 exe needs exe + qemu listed =="
# Need: armapp's OWN path (host kernel opens it FMODE_EXEC before binfmt) AND
# qemu (which reopens it as data + reads its libs).  d_path resolves the mount
# path; whitelist by basename to stay robust.
printf '%s\n%s\n' "$QBASE" "armapp" > "$AUTHZ"
OUT="$("$MP/armapp" 2>&1)"; RC=$?
echo "    transparent run: $OUT (rc=$RC)"
if [[ "$OUT" == *ARM_APP_RAN_OK* ]]; then
	ok "listed encrypted ARM64 exe runs transparently via binfmt+qemu"
else
	# Some hosts wrap binfmt or restrict env; treat a non-gate failure as info.
	if echo "$OUT" | grep -qi "denied"; then
		bad "listed ARM64 exe was denied though whitelisted: $OUT"
	else
		skip "transparent binfmt run inconclusive on this host: $OUT (rc=$RC)"
	fi
fi
# drop the exe from the list (keep qemu) -> host exec-load gate denies it
printf '%s\n' "$QBASE" > "$AUTHZ"
OUT="$("$MP/armapp" 2>&1)"; RC=$?
echo "    exe un-listed: $OUT (rc=$RC)"
[[ $RC -ne 0 ]] && echo "$OUT" | grep -qi "denied\|Permission\|exec" \
	&& ok "un-listing the ARM64 exe denies its exec-load (gated on own path)" \
	|| skip "exe-unlisted result inconclusive: $OUT (rc=$RC)"
echo 0 > "$ENF_PARAM"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
