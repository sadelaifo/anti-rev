#!/bin/bash
# test_hot_swap.sh — live per-file upgrade of ONE encrypted file on an in-place
# vcachefs mount, with no remount (other subsystems keep running).
#
# Scenario (the field request): /root/proj/bin is an IN-PLACE vcachefs mount;
# a system monitor stops one subsystem binary FOO, an operator replaces it with
# an encrypted FOO_new, and the monitor re-invokes FOO — while every other
# subsystem keeps running.  The mechanism: `vcache-replace` drives the
# /dev/vcachefs control device (AREV_IOC_LOWER_DIRFD to reach the shadowed lower
# dir + AREV_IOC_REFRESH_PATH to drop that one path's cached dentry).
#
# Verifies:
#   1. in-place mount decrypts FOO (version A)                      (decrypt)
#   2. lower file is ciphertext at rest                            (at rest)
#   3. vcache-replace swaps FOO -> version B on the LIVE mount     (hot swap)
#   4. re-read returns version B with NO remount                   (refresh)
#   5. a sibling file BAR is byte-unchanged across the swap        (isolation)
#   6. --no-refresh leaves the cache STALE (re-read still B)       (failure mode
#      and a following refresh then picks up A                      without fix)
#   7. a non-container input is rejected without --force           (sanity gate)
#   8. after unmount, the lower file is the new ciphertext         (at rest 2)
#
# Requires root (insmod/mount) and a dev-mode build (default via keyhelper;
# gate_enforce defaults 0 so an ordinary reader sees the decrypted bytes, while
# the control device still gates on the caller — vcache-replace is whitelisted).
#
# NOTE: the module-side ioctls (LOWER_DIRFD / REFRESH_PATH) are NOT yet built or
# run on a real kernel — compile + run this on the target box.  Run:
#     sudo bash kmod2/tests/test_hot_swap.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="$KMOD/module/vcachefs.ko"
REPLACE="$KMOD/tools/vcache-replace"
NEUTRAL_MAGIC="a74c2e91d63b085f"   # module ANTREV_MAGIC / packer FS_MAGIC

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }

WORK="$(mktemp -d /tmp/vcachefs_hotswap.XXXXXX)"
BIN="$WORK/bin"          # the in-place mount (lower == mountpoint)
mkdir -p "$BIN"

cleanup() {
	mountpoint -q "$BIN" && umount "$BIN"
	rmmod vcachefs 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

# enc <src-plaintext> <dst-ciphertext> : wrap src into a neutral-magic
# (a74c...) keyless container with the SAME key the .ko is built with, so the
# module accepts + decrypts it.  (protect.py encrypt-lib defaults to the old
# ANTREV01 magic, which this module would reject, so call make_container directly.)
enc() {
	python3 - "$1" "$2" "$WORK/key.hex" "$ROOT/shared" "$NEUTRAL_MAGIC" <<'PY'
import sys
src, dst, keyf, shdir, magic_hex = sys.argv[1:6]
sys.path.insert(0, shdir)
from pathlib import Path
from protect import make_container, load_or_create_key
key = load_or_create_key(Path(keyf))
data = open(src, "rb").read()
open(dst, "wb").write(make_container(data, key, magic=bytes.fromhex(magic_hex)))
PY
}

echo "== build test artifacts =="
# Two versions of FOO with distinguishable behaviour, and an unrelated BAR.
printf 'int answer(void){return 42;}\n' > "$WORK/fooA.c"
printf 'int answer(void){return 99;}\n' > "$WORK/fooB.c"
printf 'int answer(void){return 7;}\n'  > "$WORK/bar.c"
gcc -shared -fPIC -o "$WORK/fooA.so" "$WORK/fooA.c"
gcc -shared -fPIC -o "$WORK/fooB.so" "$WORK/fooB.c"
gcc -shared -fPIC -o "$WORK/bar.so"  "$WORK/bar.c"

echo "== build module (with test key) + tool =="
source "$KMOD/tests/keyhelper.sh"
arev_build_with_key "$WORK/key.hex" "$KMOD/module"      # creates key.hex, builds .ko
make -C "$KMOD/tools" vcache-replace >/dev/null || { echo "tool build failed"; exit 1; }
[[ -x "$REPLACE" ]] || { echo "vcache-replace missing"; exit 1; }

# Encrypt version A + BAR into the (to-be-shadowed) lower dir; stage B + a
# second copy of A for the replace steps.
enc "$WORK/fooA.so" "$BIN/FOO"
enc "$WORK/bar.so"  "$BIN/BAR"
enc "$WORK/fooB.so" "$WORK/FOO_B.enc"
enc "$WORK/fooA.so" "$WORK/FOO_A.enc"

echo "== 2. ciphertext at rest (before mount) =="
cmp -s "$BIN/FOO" "$WORK/fooA.so" && bad "lower FOO is plaintext!" || ok "lower FOO is ciphertext"

echo "== load module + in-place mount =="
insmod "$MOD" || { echo "insmod failed"; dmesg | tail -5; exit 1; }
# In-place: lower == mountpoint.  The real $BIN dir is pinned then shadowed.
mount -t vcachefs "$BIN" "$BIN" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mountpoint -q "$BIN" && ok "in-place vcachefs mounted at $BIN" || bad "mount missing"

echo "== 1. decrypt (version A) =="
cmp -s "$BIN/FOO" "$WORK/fooA.so" && ok "FOO decrypts to version A" || bad "FOO != version A"
cmp -s "$BIN/BAR" "$WORK/bar.so"  && ok "BAR decrypts"              || bad "BAR decrypt failed"

echo "== 3/4. hot swap FOO -> version B on the LIVE mount =="
# --force: decouple from which magic the harness emits (we know it's neutral,
# but the tool's default check hardcodes neutral; --force keeps the test robust
# to any harness magic change).  This is the operator's one command.
if "$REPLACE" --force "$WORK/FOO_B.enc" "$BIN/FOO"; then
	ok "vcache-replace reported success"
else
	bad "vcache-replace failed (rc=$?)"
fi
if cmp -s "$BIN/FOO" "$WORK/fooB.so"; then
	ok "re-read FOO returns version B — live, no remount"
else
	bad "FOO still old after replace (refresh/ioctl not effective)"
fi

echo "== 5. sibling BAR untouched by the swap =="
cmp -s "$BIN/BAR" "$WORK/bar.so" && ok "BAR unchanged across FOO swap" || bad "BAR changed!"

echo "== 6. failure mode: --no-refresh leaves the cache STALE =="
# Replace the lower back to A but SKIP the refresh ioctl: the cached dentry/
# inode (version B) must persist — this is exactly the stale-cache bug that
# AREV_IOC_REFRESH_PATH exists to fix.
"$REPLACE" --no-refresh --force "$WORK/FOO_A.enc" "$BIN/FOO" >/dev/null 2>&1
if cmp -s "$BIN/FOO" "$WORK/fooB.so"; then
	ok "without refresh, re-read still returns B (stale cache — the bug)"
else
	bad "cache unexpectedly updated without a refresh"
fi
# Now a full replace (with refresh) must pick up A.
"$REPLACE" --force "$WORK/FOO_A.enc" "$BIN/FOO" >/dev/null 2>&1
if cmp -s "$BIN/FOO" "$WORK/fooA.so"; then
	ok "refresh makes the re-read return A"
else
	bad "refresh did not pick up A"
fi

echo "== 7. sanity gate: a non-container input is refused =="
printf 'not a container\n' > "$WORK/plain.txt"
if "$REPLACE" "$WORK/plain.txt" "$BIN/FOO" >/dev/null 2>&1; then
	bad "accepted a non-container input without --force"
else
	ok "non-container input rejected (bad magic)"
fi
# FOO must be untouched by the rejected attempt.
cmp -s "$BIN/FOO" "$WORK/fooA.so" && ok "FOO intact after rejected replace" || bad "FOO corrupted by rejected replace"

echo "== 8. ciphertext at rest after swap (post-unmount) =="
umount "$BIN"
cmp -s "$BIN/FOO" "$WORK/fooA.so" && bad "lower FOO is plaintext after swap!" || ok "lower FOO is ciphertext after swap"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
