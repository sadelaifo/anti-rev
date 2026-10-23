#!/bin/bash
# test_write_mode.sh — native writable passthrough (`-o writable`) for vcachefs.
#
# Proves the single-mount writable alternative to the overlay (kernel >= 4.9):
#   1. an AUTHORIZED process creates/writes/reads-back a PLAINTEXT file in-place
#      through the mount; the bytes land in the lower tree as plaintext    (write)
#   2. mkdir / append / rename(atomic replace) / truncate / unlink by the
#      authorized process all succeed                                     (ops)
#   3. an UNAUTHORIZED process (not in the allow-list) is DENIED -EACCES on
#      create AND on unlink — `cp` into the mount cannot land content      (gate)
#   4. an ENCRYPTED (ANTREV01) file is IMMUTABLE: a write open -> -EROFS, an
#      unlink -> -EPERM, a rename -> -EPERM, even for the authorized process
#      -> the shipped ciphertext payload can never be altered/removed      (immutable)
#   5. decrypt still works through the writable mount: the authorized reader sees
#      the encrypted lib's plaintext ELF; the lower file stays ciphertext  (decrypt)
#   6. plaintext scratch is NOT gated on read (the documented tradeoff: it is
#      served to anyone, and sits plaintext in the lower tree)             (plaintext)
#   7. control: with gate_enforce=0 the unauthorized writer succeeds -> proves the
#      gate is what denies in (3), not some unrelated failure              (control)
#
# Requires root + a kernel >= 4.9 (the write-op inode ABI the module shims span
# mnt_idmap >= 6.3, user_namespace 5.12-6.2, and none < 5.12 down to 4.9).  On an
# older kernel `-o writable` is rejected and the test SKIPS.  Field targets: 6.8
# mainline, SLES 12 SP5 4.12, BiSheng 5.10.  Run:  sudo bash test_write_mode.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="$KMOD/module/vcachefs.ko"
PROTECT="$ROOT/shared/protect.py"
MOUNT_RO="$KMOD/tools/vcache-mount-ro"
GPARAM=/sys/module/vcachefs/parameters/gate_enforce

# shellcheck source=keyhelper.sh
. "$HERE/keyhelper.sh"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $*"; SKIP=$((SKIP+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }

WORK="$(mktemp -d /tmp/vcachefs_wmode.XXXXXX)"
ENC="$WORK/.enc"; MP="$WORK/mnt"; AUTHZ="$WORK/authorized_apps.txt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP" 2>/dev/null
	rmmod vcachefs 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build test artifacts =="
# An encrypted lib in the lower tree (immutability + decrypt checks).
cat > "$WORK/libtest.c" <<'EOF'
int vcachefs_answer(void) { return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
python3 "$PROTECT" encrypt-lib --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

# fsop: a precise single-identity filesystem op tool.  Prints "OK[ <data>]" on
# success or "ERR <errno> <name>" and exits nonzero on failure, so the gate's
# errno (EACCES / EROFS / EPERM) is observable from the shell.
cat > "$WORK/fsop.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
static int fail(void){ printf("ERR %d %s\n", errno, strerror(errno)); return 1; }
int main(int argc, char **argv){
	if (argc < 3) { fprintf(stderr,"usage: fsop OP path [arg]\n"); return 2; }
	const char *op = argv[1], *p = argv[2];
	if (!strcmp(op,"create")) {
		int fd = open(p, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (fd < 0) return fail();
		const char *d = argc>3?argv[3]:"";
		if (write(fd, d, strlen(d)) < 0) { close(fd); return fail(); }
		close(fd); printf("OK\n"); return 0;
	} else if (!strcmp(op,"write")) {            /* O_WRONLY, no create/trunc */
		int fd = open(p, O_WRONLY);
		if (fd < 0) return fail();
		const char *d = argc>3?argv[3]:"";
		if (write(fd, d, strlen(d)) < 0) { close(fd); return fail(); }
		close(fd); printf("OK\n"); return 0;
	} else if (!strcmp(op,"append")) {
		int fd = open(p, O_WRONLY|O_APPEND);
		if (fd < 0) return fail();
		const char *d = argc>3?argv[3]:"";
		if (write(fd, d, strlen(d)) < 0) { close(fd); return fail(); }
		close(fd); printf("OK\n"); return 0;
	} else if (!strcmp(op,"read")) {
		int fd = open(p, O_RDONLY);
		if (fd < 0) return fail();
		char buf[4096]; ssize_t n = read(fd, buf, sizeof buf); close(fd);
		if (n < 0) return fail();
		printf("OK "); fwrite(buf,1,n,stdout); printf("\n"); return 0;
	} else if (!strcmp(op,"readelf")) {          /* print first 4 bytes as hex */
		int fd = open(p, O_RDONLY);
		if (fd < 0) return fail();
		unsigned char b[4]={0}; ssize_t n = read(fd,b,4); close(fd);
		if (n < 0) return fail();
		printf("OK %02x%02x%02x%02x\n", b[0],b[1],b[2],b[3]); return 0;
	} else if (!strcmp(op,"unlink")) {
		if (unlink(p) < 0) return fail();
		printf("OK\n"); return 0;
	} else if (!strcmp(op,"mkdir")) {
		if (mkdir(p, 0755) < 0) return fail();
		printf("OK\n"); return 0;
	} else if (!strcmp(op,"trunc")) {
		off_t len = argc>3?atol(argv[3]):0;
		if (truncate(p, len) < 0) return fail();
		printf("OK\n"); return 0;
	} else if (!strcmp(op,"rename")) {
		if (argc<4) return 2;
		if (rename(p, argv[3]) < 0) return fail();
		printf("OK\n"); return 0;
	}
	fprintf(stderr,"bad op %s\n", op); return 2;
}
EOF
gcc -O2 -o "$WORK/fsop" "$WORK/fsop.c"
cp "$WORK/fsop" "$WORK/fsop_evil"     # identical bytes, NOT in the allow-list

# Allow-list: only the authorized fsop by its full path.
printf '%s\n' "$WORK/fsop" > "$AUTHZ"

echo "== build module with the pack key + load (gate_enforce=1, writable) =="
arev_build_with_key "$WORK/key.hex" "$KMOD/module"
insmod "$MOD" gate_enforce=1 authz_path="$AUTHZ" || { echo "insmod failed"; exit 1; }

# Writable + passdata mount (plaintext scratch must read back; encrypted still
# decrypts + is gated).
if ! "$MOUNT_RO" --writable --passdata "$ENC" "$MP" 2>"$WORK/mnt.err"; then
	if grep -qi "invalid argument" "$WORK/mnt.err"; then
		skip "kernel lacks the -o writable ABI (<4.9): -o writable rejected"
		echo "---- mount error ----"; cat "$WORK/mnt.err"
		echo; echo "SKIP: writable passthrough needs kernel >= 4.9"
		exit 0
	fi
	echo "mount failed:"; cat "$WORK/mnt.err"; exit 1
fi

run()  { "$WORK/fsop" "$@" 2>/dev/null; }          # authorized identity
evil() { "$WORK/fsop_evil" "$@" 2>/dev/null; }     # unauthorized identity

echo "== 1. authorized create + read-back (write passthrough) =="
out=$(run create "$MP/app.lock" "LOCKED")
[[ "$out" == "OK" ]] && ok "authorized create app.lock" || bad "create: $out"
out=$(run read "$MP/app.lock")
[[ "$out" == "OK LOCKED" ]] && ok "read back plaintext scratch" || bad "read: $out"
# bytes landed in the lower tree as plaintext
if [[ -f "$ENC/app.lock" && "$(cat "$ENC/app.lock")" == "LOCKED" ]]; then
	ok "scratch is plaintext in the lower tree"
else
	bad "lower app.lock missing/not plaintext"
fi

echo "== 2. authorized mkdir / append / rename / trunc / unlink =="
out=$(run mkdir "$MP/logs");               [[ "$out" == "OK" ]] && ok "mkdir logs" || bad "mkdir: $out"
out=$(run create "$MP/logs/a.log" "x");    [[ "$out" == "OK" ]] && ok "create in subdir" || bad "subdir create: $out"
run append "$MP/app.lock" "+more" >/dev/null
out=$(run read "$MP/app.lock")
[[ "$out" == "OK LOCKED+more" ]] && ok "append grows the file" || bad "append: $out"
run create "$MP/app.new" "REPLACED" >/dev/null
out=$(run rename "$MP/app.new" "$MP/app.lock")
[[ "$out" == "OK" ]] && ok "rename (atomic replace)" || bad "rename: $out"
out=$(run read "$MP/app.lock")
[[ "$out" == "OK REPLACED" ]] && ok "renamed content visible" || bad "post-rename read: $out"
out=$(run trunc "$MP/app.lock" 0)
[[ "$out" == "OK" ]] && [[ ! -s "$ENC/app.lock" ]] && ok "truncate to 0" || bad "trunc: $out / size $(stat -c%s "$ENC/app.lock" 2>/dev/null)"
out=$(run unlink "$MP/logs/a.log")
[[ "$out" == "OK" && ! -e "$ENC/logs/a.log" ]] && ok "unlink scratch" || bad "unlink: $out"

echo "== 3. unauthorized writer is denied (the gate) =="
out=$(evil create "$MP/evil" "x")
[[ "$out" == ERR*EACCES* || "$out" == *"Permission denied"* ]] && ok "unauthorized create -> EACCES" || bad "evil create: $out"
[[ ! -e "$ENC/evil" ]] && ok "no evil file landed in the tree" || bad "evil file appeared!"
out=$(evil unlink "$MP/app.lock")
[[ "$out" == ERR*EACCES* || "$out" == *"Permission denied"* ]] && ok "unauthorized unlink -> EACCES" || bad "evil unlink: $out"
[[ -e "$ENC/app.lock" ]] && ok "app.lock survived the unauthorized unlink" || bad "app.lock was removed!"

echo "== 4. encrypted file is immutable (no encrypt-on-write) =="
out=$(run write "$MP/libtest.so" "x")
[[ "$out" == ERR*EROFS* || "$out" == *"Read-only"* ]] && ok "write encrypted -> EROFS" || bad "enc write: $out"
out=$(run unlink "$MP/libtest.so")
[[ "$out" == ERR*EPERM* || "$out" == *"Operation not permitted"* ]] && ok "unlink encrypted -> EPERM" || bad "enc unlink: $out"
run create "$MP/t.tmp" "y" >/dev/null
out=$(run rename "$MP/libtest.so" "$MP/elsewhere.so")
[[ "$out" == ERR*EPERM* || "$out" == *"Operation not permitted"* ]] && ok "rename encrypted -> EPERM" || bad "enc rename: $out"
run unlink "$MP/t.tmp" >/dev/null 2>&1

echo "== 5. decrypt still works through the writable mount =="
out=$(run readelf "$MP/libtest.so")
[[ "$out" == "OK 7f454c46" ]] && ok "authorized reader sees decrypted ELF" || bad "decrypt read: $out"
# lower stays ciphertext (container magic a74c2e91d63b085f)
lmag=$(head -c8 "$ENC/libtest.so" | xxd -p 2>/dev/null)
[[ "$lmag" == "a74c2e91d63b085f" ]] && ok "lower lib stays ciphertext at rest" || bad "lower magic: $lmag"

echo "== 6. plaintext scratch read is NOT gated (documented tradeoff) =="
run create "$MP/public.txt" "HELLO" >/dev/null
out=$(evil read "$MP/public.txt")
[[ "$out" == "OK HELLO" ]] && ok "unauthorized reader CAN read plaintext scratch" || bad "evil read plaintext: $out"

echo "== 7. control: gate_enforce=0 lets the unauthorized writer through =="
echo 0 > "$GPARAM" 2>/dev/null || true
out=$(evil create "$MP/ctrl" "z")
if [[ "$out" == "OK" ]]; then
	ok "gate_enforce=0 -> unauthorized write succeeds (gate was the enforcer)"
else
	bad "control gate_enforce=0: $out"
fi
echo 1 > "$GPARAM" 2>/dev/null || true

echo
echo "==== write-mode: $PASS passed, $FAIL failed, $SKIP skipped ===="
[[ $FAIL -eq 0 ]]
