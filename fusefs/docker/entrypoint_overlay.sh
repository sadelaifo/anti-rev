#!/usr/bin/env bash
# entrypoint_overlay.sh — in-container test of the WRITABLE view:
# overlayfs(rw upper) stacked over vcachefsd(ro, decrypt).  Proves the app can
# write lock/log/pid files INSIDE its tree (landing in the overlay upper) while
# the ciphertext lower stays untouched and decrypted reads still work.
set -u
LOWER=/opt/product.enc
MNT=/opt/product
EXPECT=/opt/expected
STATE=/run/fusefs
OPTS="--passdata"
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
wait_mounted() { i=0; while ! grep -q " $1 " /proc/self/mountinfo; do i=$((i+1)); [ $i -gt 50 ] && return 1; sleep 0.1; done; }

echo "== [container] build writable view: overlay(rw) over fusefs(ro) =="
mkdir -p "$MNT" "$STATE"
mount -t tmpfs tmpfs "$STATE"           # real fs for the overlay upper/work
DEC="$STATE/dec"; UPPER="$STATE/upper"; WORK="$STATE/work"
mkdir -p "$DEC" "$UPPER" "$WORK"
vcachefsd "$LOWER" "$DEC" $OPTS
wait_mounted "$DEC" || { echo "  FAIL: fusefs lower did not mount"; echo; echo "0 passed, 1 failed"; exit 1; }
ok "fusefs (decrypt, ro) lower mounted at $DEC"
if mount -t overlay fusefs_overlay -o "lowerdir=$DEC,upperdir=$UPPER,workdir=$WORK" "$MNT"; then
	wait_mounted "$MNT" && ok "overlayfs writable upper stacked over the fusefs lower" || bad "overlay mount not visible"
else
	bad "overlayfs REFUSED the fusefs lower (lowerdir=fuse unsupported on this kernel)"
	echo; echo "$PASS passed, $((FAIL)) failed"; exit 1
fi

# 1. decrypted read still works through the overlay
cmp -s "$MNT/secret.so" "$EXPECT" && ok "encrypted lib decrypts through the overlay" || bad "decrypt through overlay mismatch"

# 2. the app writes a lock file INSIDE its tree -> succeeds (bare RO mount would EROFS)
if echo "pid=1" > "$MNT/runtime.lock" 2>/dev/null; then
	ok "app wrote runtime.lock inside the tree (no EROFS)"
else
	bad "write into the tree failed (EROFS) — overlay upper not effective"
fi

# 3. the write landed in the overlay UPPER, not the ciphertext lower
[ -f "$UPPER/runtime.lock" ] && ok "runtime.lock is in the overlay upper" || bad "runtime.lock not in upper"
[ ! -e "$LOWER/runtime.lock" ] && ok "runtime.lock did NOT touch the .enc ciphertext tree" || bad "write leaked into the .enc tree"

# 4. ciphertext lower is unchanged (still the encrypted container)
if head -c8 "$LOWER/secret.so" | cmp -s - <(printf '\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f'); then
	ok "ciphertext secret.so on disk is untouched (still FS_MAGIC)"
else
	bad "ciphertext lower was modified"
fi

# 5. plaintext passthrough still served
[ "$(cat "$MNT/notes.txt")" = "third-party plaintext" ] && ok "plaintext data file still served through overlay" || bad "passthrough broke under overlay"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
