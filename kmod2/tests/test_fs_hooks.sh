#!/bin/bash
# test_fs_hooks.sh — the remaining VFS hooks: advisory/record locking
# (flock + fcntl), fallocate, and d_revalidate.
#
# vcachefs forwards a writable-mount plaintext file's data ops to a per-open
# LOWER file, so locks and fallocate taken THROUGH the mount must land on the
# lower inode — coherent with anything touching the lower directly.  And a
# d_revalidate completes the stacking contract: an out-of-band rename of the
# lower file invalidates the cached vcachefs dentry.
#
#   1. flock:   an exclusive flock(2) held via the mount is seen on the LOWER
#               path (forwarded to the lower inode); released, it clears
#   2. fcntl:   an fcntl F_SETLKW write lock is coherent among MOUNT users — a
#               second process reading via the mount sees it with F_GETLK
#               (POSIX locks stay local to the shared vcachefs inode by design)
#   3. falloc:  fallocate(2) through the mount grows the plaintext file and the
#               bytes land in the lower tree
#   4. dreval:  an out-of-band unlink+recreate of a lower file (new inode, same
#               name) is picked up on next access — the cached vcachefs dentry
#               is invalidated by d_revalidate (open-time size/mtime revalidate
#               cannot see a same-size inode swap)
#   5. flock:   a blocking flock waits for the holder then acquires (exclusion)
#   6. flock:   shared locks coexist; an exclusive request still conflicts
#   7. flock:   a SIGKILLed holder's lock is released (lifetime on lower fput)
#   8. dreval:  a HELD fd keeps old content while a fresh lookup gets new (the
#               in-use-open boundary; in-place is covered by test_hot_swap §6)
#   9. falloc:  fallocate punch-hole (KEEP_SIZE) forwards to the lower
#  10. stress:  parallel flock contenders + concurrent decrypt reads, no
#               deadlock, and the kernel log stays clean (no oops/WARNING)
#
# Requires root + kernel >= 4.9 (writable passthrough).  SKIPs the write-mount
# sections on older kernels.  Run:  sudo bash test_fs_hooks.sh  (build with
# AREV_CC=gcc-12 on the 6.8 box).
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
command -v flock >/dev/null || { echo "flock(1) required"; exit 1; }

WORK="$(mktemp -d /tmp/vcachefs_hooks.XXXXXX)"
ENC="$WORK/.enc"; MP="$WORK/mnt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP" 2>/dev/null
	rmmod vcachefs 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build test artifacts =="
printf 'hello\n' > "$ENC/data.txt"            # plaintext passthrough file
printf 'v1' > "$ENC/victim.txt"               # for the d_revalidate rename test

cat > "$WORK/libtest.c" <<'EOF'
int vcachefs_answer(void){ return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
python3 "$PROTECT" encrypt-lib --fs --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

# locktool: hold / test an fcntl WRITE lock, so we can prove a record lock taken
# through the mount is visible on the LOWER inode.
cat > "$WORK/locktool.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>		/* flock(2) */
int main(int argc, char **argv){
	if (argc < 3) { fprintf(stderr,"usage: locktool hold|test|flock-hold path [secs]\n"); return 2; }
	const char *op = argv[1], *p = argv[2];
	int fd = open(p, O_RDWR);
	if (fd < 0) { perror("open"); return 3; }
	struct flock fl; memset(&fl,0,sizeof fl);
	fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET; fl.l_start = 0; fl.l_len = 0;
	if (!strcmp(op,"flock-hold")) {			/* hold flock(LOCK_EX) in-process */
		if (flock(fd, LOCK_EX) < 0) { perror("flock"); return 4; }
		printf("HELD\n"); fflush(stdout);
		sleep(argc>3?atoi(argv[3]):3);
		return 0;
	} else if (!strcmp(op,"hold")) {
		if (fcntl(fd, F_SETLKW, &fl) < 0) { perror("F_SETLKW"); return 4; }
		printf("HELD\n"); fflush(stdout);
		sleep(argc>3?atoi(argv[3]):3);
		return 0;
	} else if (!strcmp(op,"test")) {
		if (fcntl(fd, F_GETLK, &fl) < 0) { perror("F_GETLK"); return 4; }
		printf(fl.l_type==F_UNLCK ? "UNLOCKED\n" : "LOCKED\n");
		return 0;
	}
	return 2;
}
EOF
gcc -O2 -o "$WORK/locktool" "$WORK/locktool.c"

echo "== build module with the pack key + load =="
arev_build_with_key "$WORK/key.hex" "$KMOD/module"
insmod "$MOD" gate_enforce=0 || { echo "insmod failed"; exit 1; }

if ! "$MOUNT_RO" --writable --passdata "$ENC" "$MP" 2>"$WORK/mnt.err"; then
	if grep -qi "invalid argument" "$WORK/mnt.err"; then
		skip "kernel lacks the -o writable ABI (<4.9)"
		echo; echo "==== fs-hooks: $PASS passed, $FAIL failed, $((SKIP+1)) skipped ===="
		exit 0
	fi
	echo "mount failed:"; cat "$WORK/mnt.err"; exit 1
fi

echo "== 1. flock(2) taken via the mount is coherent on the LOWER path =="
# Hold an exclusive flock on the file THROUGH the mount, then try a non-blocking
# exclusive flock on the LOWER path: it must FAIL (busy) -> the lock forwarded to
# the shared lower inode.  Without ->flock forwarding the mount lock would sit on
# the vcachefs inode and the lower-path lock would wrongly succeed.
flock -x "$MP/data.txt" -c 'sleep 2' &
HOLDER=$!
sleep 0.4
if flock -x -n "$ENC/data.txt" -c true; then
	bad "lower-path flock succeeded while the mount held it — NOT forwarded"
else
	ok "lower-path flock is blocked while the mount holds it (forwarded to lower)"
fi
wait "$HOLDER" 2>/dev/null
flock -x -n "$ENC/data.txt" -c true && ok "flock clears after release" || bad "flock stuck after release"

echo "== 2. fcntl record lock is coherent among MOUNT users =="
# POSIX fcntl locks stay local to the shared vcachefs inode (not forwarded to
# the lower), so two processes BOTH going through the mount — the actual
# deployment — see each other's locks.  Holder locks MP/data.txt; a second
# process F_GETLKs MP/data.txt and must see it.
"$WORK/locktool" hold "$MP/data.txt" 2 >"$WORK/held" &
HOLDER=$!
sleep 0.4
out=$("$WORK/locktool" test "$MP/data.txt")
[[ "$out" == "LOCKED" ]] && ok "a second mount user sees the F_SETLKW write lock ($out)" \
	|| bad "mount user did NOT see the lock ($out) — inode-local locking broken"
wait "$HOLDER" 2>/dev/null
out=$("$WORK/locktool" test "$MP/data.txt")
[[ "$out" == "UNLOCKED" ]] && ok "lock released after holder exits ($out)" || bad "lock stuck ($out)"

echo "== 3. fallocate(2) via the mount grows the file + lands on the lower =="
if fallocate -l 65536 "$MP/data.txt" 2>"$WORK/fa.err"; then
	msz=$(stat -c%s "$MP/data.txt"); lsz=$(stat -c%s "$ENC/data.txt")
	[[ "$msz" -ge 65536 && "$lsz" -ge 65536 ]] \
		&& ok "fallocate grew the file through the mount (mnt=$msz lower=$lsz)" \
		|| bad "fallocate size wrong: mnt=$msz lower=$lsz (want >=65536)"
else
	# some lower fs lack fallocate; EOPNOTSUPP is an honest SKIP, not a fail
	if grep -qi "not supported\|operation not" "$WORK/fa.err"; then
		skip "lower fs ($(stat -f -c %T "$ENC")) has no fallocate: $(cat "$WORK/fa.err")"
	else
		bad "fallocate failed: $(cat "$WORK/fa.err")"
	fi
fi

echo "== 4. d_revalidate: an out-of-band inode swap under the same name is seen =="
# Cache the vcachefs dentry+inode for victim.txt (read it), then UNLINK the
# lower file and recreate it with the SAME name but NEW content/inode, out of
# band.  The cached lower dentry is now unhashed, so d_revalidate must invalidate
# OUR dentry; the next read re-resolves to the new lower inode and serves v2.
# (Open-time size/mtime revalidate can't catch this — it checks the stale cached
# inode, whose stamped size/mtime never changed.)
got=$(cat "$MP/victim.txt" 2>/dev/null)
[[ "$got" == "v1" ]] && ok "initial content served ($got)" || bad "initial read wrong: '$got'"
rm -f "$ENC/victim.txt"                          # out-of-band unlink on the lower
printf 'v2' > "$ENC/victim.txt"                  # recreate: same name, NEW inode
got=$(cat "$MP/victim.txt" 2>/dev/null)
if [[ "$got" == "v2" ]]; then
	ok "after an out-of-band inode swap the NEW content is served ($got) — dentry revalidated"
else
	bad "stale content after inode swap: '$got' (want v2 — d_revalidate not firing)"
fi

echo "== 5. flock blocking: a contender waits, then acquires after release =="
flock -x "$MP/data.txt" -c 'sleep 1.5' &
HOLDER=$!
sleep 0.3
t0=$(date +%s%N)
flock -x "$MP/data.txt" -c true          # blocking (no -n) -> waits for the holder
t1=$(date +%s%N)
wait "$HOLDER" 2>/dev/null
waited=$(( (t1 - t0) / 1000000 ))         # ms
[[ "$waited" -ge 700 ]] && ok "blocking flock waited ${waited}ms for the holder (mutual exclusion)" \
	|| bad "blocking flock did not wait (${waited}ms) — exclusion broken"

echo "== 6. flock shared locks coexist; exclusive still conflicts =="
flock -s "$MP/data.txt" -c 'sleep 1' &
S1=$!
sleep 0.3
flock -s -n "$MP/data.txt" -c true \
	&& ok "a second SHARED flock is granted concurrently" \
	|| bad "shared flock wrongly blocked another shared holder"
flock -x -n "$MP/data.txt" -c true \
	&& bad "exclusive flock granted while a shared lock is held" \
	|| ok "exclusive flock is correctly blocked by the shared lock"
wait "$S1" 2>/dev/null

echo "== 7. flock released when the holder is SIGKILLed (freed on lower fput) =="
# Hold the flock IN-PROCESS (locktool, no child fork) so SIGKILL truly closes the
# only fd.  (flock(1) -c forks the command, which inherits the lock fd and would
# keep the lock alive past the parent's death — a test artifact, not a leak.)
"$WORK/locktool" flock-hold "$MP/data.txt" 30 >"$WORK/fh" &
HOLDER=$!
for _ in $(seq 1 20); do grep -q HELD "$WORK/fh" 2>/dev/null && break; sleep 0.1; done
flock -x -n "$ENC/data.txt" -c true \
	&& bad "lower not locked while the mount holds it (pre-kill)" \
	|| ok "lower is locked while the mount holds it (pre-kill)"
kill -9 "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null
rel=0
for _ in $(seq 1 20); do
	if flock -x -n "$ENC/data.txt" -c true; then rel=1; break; fi
	sleep 0.1
done
[[ "$rel" -eq 1 ]] && ok "flock released after SIGKILL (retargeted lock freed on lower fput)" \
	|| bad "flock LEAKED after SIGKILL — the lower stays locked"

echo "== 8. d_revalidate boundary: a held fd keeps OLD content; a new lookup gets NEW =="
printf 'A1' > "$ENC/of.txt"
exec 7<"$MP/of.txt"                       # pin the old inode via an open fd
rm -f "$ENC/of.txt"; printf 'A2' > "$ENC/of.txt"   # out-of-band inode swap
held=$(cat <&7)                           # read via the held fd
exec 7<&-
fresh=$(cat "$MP/of.txt")                 # fresh lookup -> d_revalidate re-resolves
[[ "$held" == "A1" ]] && ok "the held fd still serves the OLD content ($held) — in-use open undisturbed" \
	|| bad "held fd changed unexpectedly: '$held'"
[[ "$fresh" == "A2" ]] && ok "a fresh lookup serves the NEW content ($fresh) — d_revalidate" \
	|| bad "fresh lookup stale: '$fresh' (want A2)"
# NOTE: d_revalidate on a true IN-PLACE mount (lower == mountpoint) is covered by
# test_hot_swap.sh §6 (vcache-replace --no-refresh picked up live).

echo "== 9. fallocate punch-hole forwards to the lower (best-effort) =="
# data.txt was grown to 65536 in §3; punch a hole with KEEP_SIZE (-p) and confirm
# the size is unchanged (the op forwarded, not emulated as a truncate).
szb=$(stat -c%s "$MP/data.txt")
if fallocate -p -o 0 -l 4096 "$MP/data.txt" 2>"$WORK/ph.err"; then
	sza=$(stat -c%s "$MP/data.txt")
	[[ "$sza" == "$szb" ]] && ok "punch-hole kept the size ($sza) — forwarded to the lower" \
		|| bad "punch-hole changed size: $szb -> $sza"
elif grep -qi "not supported\|operation not" "$WORK/ph.err"; then
	skip "lower fs ($(stat -f -c %T "$ENC")) has no punch-hole: $(cat "$WORK/ph.err")"
else
	bad "punch-hole failed: $(cat "$WORK/ph.err")"
fi

echo "== 10. concurrency smoke: parallel flock contenders + decrypt reads, no hang/oops =="
dmesg -c >/dev/null 2>&1 || true          # clear the ring so the scan below is fresh
: > "$WORK/ctr"
for _ in $(seq 1 12); do
	( flock -x "$MP/data.txt" -c "printf 'x\n' >> '$WORK/ctr'" ) &
done
wait
n=$(wc -l < "$WORK/ctr")
[[ "$n" -eq 12 ]] && ok "12 exclusive flock contenders all completed (serialized, no deadlock) — $n" \
	|| bad "flock contention lost work or hung: $n/12"
for _ in $(seq 1 8); do ( head -c4 "$MP/libtest.so" >/dev/null 2>&1 ) & done
wait
ok "concurrent decrypt reads of the shared page cache completed"
if dmesg 2>/dev/null | grep -qiE 'BUG:|Oops|general protection|NULL pointer|WARNING: CPU|call trace'; then
	bad "kernel log shows a fault after the concurrency run"; dmesg | tail -15
else
	ok "no kernel oops/WARNING after the concurrency run"
fi

echo
echo "==== fs-hooks: $PASS passed, $FAIL failed, $SKIP skipped ===="
[[ $FAIL -eq 0 ]]
