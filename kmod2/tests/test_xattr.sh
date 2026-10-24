#!/bin/bash
# test_xattr.sh — extended-attribute passthrough for vcachefs (the overlayfs
# idiom: forward get/list/set/remove to the LOWER inode).
#
# WHY THIS MATTERS: vcachefs stores no xattrs of its own.  Without the
# passthrough the vcachefs inode reports NO xattrs, so:
#   * a setcap'd binary read through the mount loses its file capabilities on
#     exec (security.capability reads back empty), and
#   * an SELinux-enforcing host (e.g. RHEL7) sees an unlabeled inode and can
#     deny it outright.
# The headline check here is security.capability round-tripping through the
# mount (getcap), plus a generic user.* get/list/set and a check that xattrs are
# orthogonal to content encryption (an xattr on an ENCRYPTED file's lower inode
# still reads through while the content decrypts).
#
#   1. get:    a user.* xattr set on the lower file reads back through the mount
#   2. list:   listxattr through the mount enumerates it
#   3. caps:   security.capability (setcap) survives being read through the mount
#              -> getcap sees it (best-effort; SKIPs if the lower fs can't store
#              security.* xattrs)
#   4. enc:    an xattr on an ENCRYPTED file's lower inode reads through while the
#              content still decrypts (xattr is inode metadata, not content)
#   5. ro:     set/removexattr through a READ-ONLY mount is refused (-EROFS)
#   6. set:    on a WRITABLE mount, set/removexattr forward to the lower inode
#
# Requires root + kernel >= 4.9 (the xattr_handler ABI the module targets; below
# that vcachefs compiles WITHOUT the passthrough and this test SKIPs).  Run:
#   sudo bash test_xattr.sh      (build the .ko with AREV_CC=gcc-12 on the 6.8 box)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="$KMOD/module/vcachefs.ko"
PROTECT="$ROOT/shared/protect.py"
MOUNT_RO="$KMOD/tools/vcache-mount-ro"

# shellcheck source=keyhelper.sh
. "$HERE/keyhelper.sh"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $*"; SKIP=$((SKIP+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }

WORK="$(mktemp -d /tmp/vcachefs_xattr.XXXXXX)"
ENC="$WORK/.enc"; MP="$WORK/mnt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP" 2>/dev/null
	rmmod vcachefs 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build test artifacts =="
# A plaintext ELF served verbatim under passdata; the setcap target.
cat > "$WORK/tool.c" <<'EOF'
int main(void){ return 0; }
EOF
gcc -O2 -o "$WORK/tool" "$WORK/tool.c"
cp "$WORK/tool" "$ENC/tool"              # plaintext (non-magic) -> passdata serves it

# An encrypted lib (xattr-is-orthogonal-to-content check).
cat > "$WORK/libtest.c" <<'EOF'
int vcachefs_answer(void){ return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
python3 "$PROTECT" encrypt-lib --fs --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

# xattrop: a syscall-level xattr tool (getfattr/setfattr are not installed on
# every box).  Prints "OK[ <data>]" or "ERR <errno> <name>", exits nonzero on
# error, so the errno (EROFS/ENODATA/EPERM) is observable from the shell.
cat > "$WORK/xattrop.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/xattr.h>
static int fail(void){ printf("ERR %d %s\n", errno, strerror(errno)); return 1; }
int main(int argc, char **argv){
	if (argc < 3) { fprintf(stderr,"usage: xattrop OP path [name] [val]\n"); return 2; }
	const char *op = argv[1], *p = argv[2];
	if (!strcmp(op,"get")) {
		char buf[4096];
		ssize_t n = getxattr(p, argv[3], buf, sizeof buf);
		if (n < 0) return fail();
		printf("OK "); fwrite(buf,1,n,stdout); printf("\n"); return 0;
	} else if (!strcmp(op,"list")) {
		char buf[8192];
		ssize_t n = listxattr(p, buf, sizeof buf);
		if (n < 0) return fail();
		printf("OK ");
		for (ssize_t i=0;i<n;) { printf("%s,", buf+i); i += strlen(buf+i)+1; }
		printf("\n"); return 0;
	} else if (!strcmp(op,"set")) {
		if (setxattr(p, argv[3], argv[4], strlen(argv[4]), 0) < 0) return fail();
		printf("OK\n"); return 0;
	} else if (!strcmp(op,"rm")) {
		if (removexattr(p, argv[3]) < 0) return fail();
		printf("OK\n"); return 0;
	}
	fprintf(stderr,"bad op %s\n", op); return 2;
}
EOF
gcc -O2 -o "$WORK/xattrop" "$WORK/xattrop.c"

echo "== build module with the pack key + load =="
arev_build_with_key "$WORK/key.hex" "$KMOD/module"
# gate_enforce irrelevant here: xattr passthrough is a metadata path, not the
# content-read gate.  Load with the gate off so the decrypt check in §4 is simple.
insmod "$MOD" gate_enforce=0 || { echo "insmod failed"; exit 1; }

# Seed xattrs on the LOWER inodes BEFORE mounting.
if ! "$WORK/xattrop" set "$ENC/tool" user.flavor mango >/dev/null 2>"$WORK/seed.err"; then
	skip "lower fs ($(stat -f -c %T "$ENC")) rejects user.* xattrs: $(cat "$WORK/seed.err")"
	echo; echo "==== xattr: $PASS passed, $FAIL failed, $((SKIP+1)) skipped ===="
	echo "SKIP: the lower fs cannot store xattrs (use an ext4 lower)"; exit 0
fi
"$WORK/xattrop" set "$ENC/libtest.so" user.enc secret >/dev/null 2>&1 || true

echo "== mount read-only (passdata) =="
"$MOUNT_RO" --passdata "$ENC" "$MP" 2>"$WORK/mnt.err" || { echo "mount failed:"; cat "$WORK/mnt.err"; exit 1; }

echo "== 1. get: a lower user.* xattr reads back through the mount =="
out=$("$WORK/xattrop" get "$MP/tool" user.flavor 2>/dev/null)
[[ "$out" == "OK mango" ]] && ok "getxattr through the mount returns the lower value ($out)" \
	|| bad "getxattr mismatch: $out (want 'OK mango')"

echo "== 2. list: listxattr through the mount enumerates it =="
out=$("$WORK/xattrop" list "$MP/tool" 2>/dev/null)
[[ "$out" == *user.flavor* ]] && ok "listxattr through the mount shows user.flavor ($out)" \
	|| bad "listxattr missing user.flavor: $out"

echo "== 3. caps: security.capability survives being read through the mount =="
# The motivating case.  Set a file capability on the LOWER tool, then read it
# back through the mount with getcap.  Best-effort: SKIP if the lower fs can't
# store security.* (setcap fails) — a real ext4 lower always can.
if command -v setcap >/dev/null && command -v getcap >/dev/null; then
	if setcap cap_net_bind_service+ep "$ENC/tool" 2>"$WORK/setcap.err"; then
		cap=$(getcap "$MP/tool" 2>/dev/null)
		if [[ "$cap" == *cap_net_bind_service* ]]; then
			ok "getcap through the mount sees the file capability ($cap)"
		else
			bad "security.capability NOT visible through the mount (getcap: '$cap') — setcap'd binaries would lose caps"
		fi
	else
		skip "lower fs cannot store security.capability: $(cat "$WORK/setcap.err")"
	fi
else
	skip "setcap/getcap not installed"
fi

echo "== 4. enc: an xattr on an ENCRYPTED file reads through while content decrypts =="
out=$("$WORK/xattrop" get "$MP/libtest.so" user.enc 2>/dev/null)
[[ "$out" == "OK secret" ]] && ok "xattr on an encrypted file is readable through the mount ($out)" \
	|| bad "encrypted-file xattr not readable: $out"
# ...and the content still decrypts (ELF magic), proving xattr != content path
mag=$("$WORK/xattrop" get "$MP/libtest.so" user.enc >/dev/null 2>&1; head -c4 "$MP/libtest.so" | xxd -p)
[[ "$mag" == "7f454c46" ]] && ok "the encrypted file still decrypts to a valid ELF (xattr is orthogonal)" \
	|| bad "encrypted content did not decrypt through the mount: $mag"

echo "== 5. ro: set/removexattr through a READ-ONLY mount is refused =="
out=$("$WORK/xattrop" set "$MP/tool" user.nope x 2>/dev/null)
[[ "$out" == ERR*30* || "$out" == *"Read-only"* || "$out" == ERR* ]] \
	&& ok "setxattr on a read-only mount is refused ($out)" \
	|| bad "setxattr unexpectedly succeeded on a read-only mount: $out"
# the lower must be untouched
"$WORK/xattrop" get "$ENC/tool" user.nope >/dev/null 2>&1 \
	&& bad "user.nope leaked onto the lower despite RO mount" \
	|| ok "the lower inode was not modified"

echo "== 6. set: on a WRITABLE mount, set/removexattr forward to the lower =="
umount "$MP"
if "$MOUNT_RO" --writable --passdata "$ENC" "$MP" 2>"$WORK/mntw.err"; then
	out=$("$WORK/xattrop" set "$MP/tool" user.added hi 2>/dev/null)
	if [[ "$out" == "OK" ]]; then
		ok "setxattr through a writable mount succeeds"
		low=$("$WORK/xattrop" get "$ENC/tool" user.added 2>/dev/null)
		[[ "$low" == "OK hi" ]] && ok "the attr landed on the LOWER inode ($low)" \
			|| bad "attr did not forward to the lower: $low"
		out=$("$WORK/xattrop" rm "$MP/tool" user.added 2>/dev/null)
		[[ "$out" == "OK" ]] && ! "$WORK/xattrop" get "$ENC/tool" user.added >/dev/null 2>&1 \
			&& ok "removexattr through the mount clears it on the lower" \
			|| bad "removexattr did not forward: $out"
	else
		bad "setxattr through a writable mount failed: $out"
	fi
elif grep -qi "invalid argument" "$WORK/mntw.err"; then
	skip "kernel lacks the -o writable ABI (<4.9): writable xattr-set not tested"
else
	bad "writable mount failed: $(cat "$WORK/mntw.err")"
fi

echo
echo "==== xattr: $PASS passed, $FAIL failed, $SKIP skipped ===="
[[ $FAIL -eq 0 ]]
