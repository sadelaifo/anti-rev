#!/bin/bash
# test_write_mode.sh — native writable passthrough (`-o writable`) for vcachefs.
#
# Proves the single-mount writable alternative to the overlay (kernel >= 4.9).
# WRITES ARE UNGATED — the gate is ONLY on reading decrypted content — so an
# operator can stop a subsystem, replace its binary (or a lib it links to) with
# another container, and restart, all while the rest of the system runs:
#   1. a process creates/writes/reads-back a PLAINTEXT file in-place through the
#      mount; the bytes land in the lower tree as plaintext                (write)
#   2. mkdir / append / rename(atomic replace) / truncate / unlink succeed  (ops)
#   3. an UNAUTHORIZED process can ALSO write — create AND unlink succeed, the
#      file lands in the tree (writes are ungated; cp/scp/drag all work)   (ungated)
#   4. decrypt still works through the writable mount: the authorized reader sees
#      the encrypted lib's plaintext ELF; the lower file stays ciphertext  (decrypt)
#   5. the READ gate still holds — an UNAUTHORIZED reader NEVER gets decrypted
#      content (EACCES or the keyless container, never plaintext ELF)      (readgate)
#   6. plaintext scratch is NOT gated on read (it is served to anyone, and sits
#      plaintext in the lower tree)                                        (plaintext)
#   7. an ENCRYPTED file replaced through the mount (cp a NEW container over it)
#      is picked up LIVE — ->release re-classifies + drops the stale decrypt, so
#      the next read decrypts the NEW bytes (size tracks the new container), no
#      vcache-replace; it can also be unlinked (even unauthorized)         (live-swap)
#   8. control: with gate_enforce=0 the unauthorized READER decrypts -> proves the
#      gate is the READ enforcer                                           (control)
#   9. chattr +i through the mount forwards to the lower inode and locks the file
#      read-only live (writes -> -EPERM); chattr -i restores it; lsattr reads the
#      flag through the mount.  Best-effort (SKIPs if the lower fs lacks flag
#      support, e.g. tmpfs on an older kernel)                             (chattr)
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

# A SECOND, clearly bigger encrypted lib, used as a replacement container to
# prove live refresh-on-write-close (its decrypted size differs from libtest.so).
cat > "$WORK/libbig.c" <<'EOF'
char vcf_marker[65536] = "BIGVERSION";
int vcachefs_answer(void) { return 99; }
EOF
gcc -shared -fPIC -o "$WORK/libbig.so" "$WORK/libbig.c"
python3 "$PROTECT" encrypt-lib --key "$WORK/key.hex" \
	--libs "$WORK/libbig.so" --output-dir "$ENC" >/dev/null
BIG_PLAIN_SZ=$(stat -c%s "$WORK/libbig.so")

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

echo "== 3. ALL writes are ungated — the unauthorized writer also succeeds =="
out=$(evil create "$MP/dropped" "x")
[[ "$out" == "OK" ]] && ok "unauthorized create -> OK (writes ungated)" || bad "evil create: $out"
[[ -f "$ENC/dropped" && "$(cat "$ENC/dropped")" == "x" ]] && ok "dropped file landed plaintext in the tree" || bad "dropped file missing/not plaintext"
out=$(evil unlink "$MP/dropped")
[[ "$out" == "OK" && ! -e "$ENC/dropped" ]] && ok "unauthorized unlink -> OK" || bad "evil unlink: $out"

echo "== 4. decrypt still works through the writable mount (read path intact) =="
out=$(run readelf "$MP/libtest.so")
[[ "$out" == "OK 7f454c46" ]] && ok "authorized reader sees decrypted ELF" || bad "decrypt read: $out"
# lower stays ciphertext (container magic a74c2e91d63b085f)
lmag=$(head -c8 "$ENC/libtest.so" | xxd -p 2>/dev/null)
[[ "$lmag" == "a74c2e91d63b085f" ]] && ok "lower lib stays ciphertext at rest" || bad "lower magic: $lmag"

echo "== 5. the READ gate still protects decrypted content (the ONLY gate) =="
out=$(evil readelf "$MP/libtest.so")
# An unauthorized reader must NEVER see the decrypted ELF (7f454c46): depending
# on gate_passthrough_cipher it gets either EACCES or the keyless container's
# magic (a74c...), but never plaintext.
if [[ "$out" == "OK 7f454c46" ]]; then
	bad "unauthorized reader DECRYPTED the lib — read gate broken! ($out)"
else
	ok "unauthorized reader does NOT get decrypted content ($out)"
fi

echo "== 6. plaintext scratch read is NOT gated (documented tradeoff) =="
run create "$MP/public.txt" "HELLO" >/dev/null
out=$(evil read "$MP/public.txt")
[[ "$out" == "OK HELLO" ]] && ok "unauthorized reader CAN read plaintext scratch" || bad "evil read plaintext: $out"

echo "== 7. replace an encrypted file through the mount -> picked up LIVE =="
# libvictim starts as the small encrypted libtest.so (classifies encrypted on
# first lookup, ciphertext already in place).
cp "$ENC/libtest.so" "$ENC/libvictim.so"
out=$(run readelf "$MP/libvictim.so")
[[ "$out" == "OK 7f454c46" ]] && ok "fresh encrypted copy decrypts" || bad "victim decrypt: $out"
sz0=$(stat -c%s "$MP/libvictim.so")
# Operator drops a NEW (bigger) container over it, straight through the mount —
# no vcache-replace.  On close, ->release re-classifies + drops the stale decrypt.
cp "$ENC/libbig.so" "$MP/libvictim.so"
out=$(run readelf "$MP/libvictim.so")
[[ "$out" == "OK 7f454c46" ]] && ok "after replace: still a valid decrypted ELF (not raw ciphertext)" || bad "post-replace readelf: $out"
sz1=$(stat -c%s "$MP/libvictim.so")
if [[ "$sz1" == "$BIG_PLAIN_SZ" && "$sz1" != "$sz0" ]]; then
	ok "decrypted size tracks the NEW container ($sz0 -> $sz1) — refresh-on-close worked"
else
	bad "size not refreshed: $sz0 -> $sz1 (want $BIG_PLAIN_SZ)"
fi
# and an encrypted file can be removed (even by the unauthorized identity)
out=$(evil unlink "$MP/libvictim.so")
[[ "$out" == "OK" && ! -e "$ENC/libvictim.so" ]] && ok "unlink an encrypted file -> OK (even unauthorized)" || bad "enc unlink: $out"

echo "== 8. control: gate_enforce=0 lets the unauthorized reader decrypt =="
echo 0 > "$GPARAM" 2>/dev/null || true
out=$(evil readelf "$MP/libtest.so")
if [[ "$out" == "OK 7f454c46" ]]; then
	ok "gate_enforce=0 -> unauthorized reader decrypts (the gate is the READ enforcer)"
else
	bad "control gate_enforce=0 read: $out"
fi
echo 1 > "$GPARAM" 2>/dev/null || true

echo "== 9. chattr +i through the mount locks a file read-only (live) =="
# Forwarded to the lower inode (via fileattr ops on >=5.13, unlocked_ioctl below
# that).  Best-effort: SKIP if the lower fs can't store the flag (the test's
# lower is tmpfs, which supports chattr flags only on newer kernels; a real ext4
# lower always does).
if command -v chattr >/dev/null && command -v lsattr >/dev/null; then
	run create "$MP/locked.txt" "v1" >/dev/null
	if chattr +i "$MP/locked.txt" 2>"$WORK/chattr.err"; then
		out=$(run write "$MP/locked.txt" "v2")
		[[ "$out" == ERR* ]] && ok "write to a chattr +i file is denied ($out)" || bad "write succeeded despite +i: $out"
		lsattr "$MP/locked.txt" 2>/dev/null | grep -q 'i' && ok "lsattr shows the immutable flag through the mount" || bad "lsattr missing the i flag"
		chattr -i "$MP/locked.txt" 2>/dev/null
		out=$(run write "$MP/locked.txt" "v3")
		[[ "$out" == "OK" ]] && ok "chattr -i restores writability" || bad "still locked after -i: $out"
	else
		skip "lower fs ($(stat -f -c %T "$ENC" 2>/dev/null)) has no chattr-flag support: $(cat "$WORK/chattr.err")"
	fi
else
	skip "chattr/lsattr not installed"
fi

echo "== 10. lseek+read coherence on a writable plaintext read (regression) =="
# Regression for the writable-mount llseek bug: vcachefs_llseek used to seek the
# LOWER file while reads are driven by THIS file's position (iocb->ki_pos), so a
# seek left file->f_pos stale and the next read landed a whole buffer away.
# Sequential readers (cat/sha256sum) never seek and looked fine; bash, which
# parses a script by read()ing a buffer then lseek()ing back to the byte it
# consumed, skipped a buffer's worth and silently dropped variable assignments
# ("start_3rd=0" never ran -> `[ $start_3rd != 0 ]` -> "unary operator expected").
#
# (a) deterministic: a marker 5000 bytes in; dd skips to it via lseek then reads.
{ head -c5000 /dev/zero | tr '\0' 'A'; printf 'START3RD'; \
  head -c5000 /dev/zero | tr '\0' 'B'; } > "$ENC/seektest"
got=$(dd if="$MP/seektest" bs=1 skip=5000 count=8 2>/dev/null)
if [[ "$got" == "START3RD" ]]; then
	ok "lseek+read returns the sought bytes (got '$got')"
else
	bad "lseek+read incoherent: got '$got' (expected START3RD; buggy .ko reads from offset 0 -> AAAAAAAA)"
fi

# (b) end-to-end: the field symptom — a large script whose early assignment must
# survive bash's buffered-read + reposition.  External commands between the
# assignment and the test force the fd reposition that exposed the bug.
{
	echo '#!/bin/sh'
	echo 'start_3rd=0'
	for i in $(seq 1 3000); do echo "# filler $i — push past bash's read buffer"; done
	echo 'true; /bin/true'
	echo 'if [ $start_3rd != 0 ]; then echo NONZERO; else echo ZERO; fi'
	echo 'echo DONE'
} > "$ENC/bigscript.sh"
chmod +x "$ENC/bigscript.sh"
out=$(sh "$MP/bigscript.sh" 2>&1)
if [[ "$out" == *ZERO* && "$out" == *DONE* && "$out" != *unary* ]]; then
	ok "bash runs a large script through the writable mount (assignment survived)"
else
	bad "large-script read corrupted through the mount: $(printf '%s' "$out" | tr '\n' '|')"
fi

echo
echo "==== write-mode: $PASS passed, $FAIL failed, $SKIP skipped ===="
[[ $FAIL -eq 0 ]]
