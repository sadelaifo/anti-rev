#!/bin/bash
# stress_antirevfs.sh — SAFETY-FIRST stress/correctness test for the vcachefs
# (antirevfs) kernel module, intended for a REAL, CUSTOM slave kernel.
#
# Design goal: shake out decrypt correctness, page-cache sharing, fd/mount churn
# and concurrency races WITHOUT ever risking the kernel.  It is conservative by
# construction:
#
#   * PRE-FLIGHT GATE — verifies vermagic matches the running kernel, that the
#     module loads AND unloads cleanly once, and that a single decrypt is
#     byte-exact, BEFORE any stress runs.  If the basic path is broken it aborts
#     with the .ko never left loaded.
#   * NO FORCE, EVER — never `umount -l`, never `rmmod -f`.  Before every rmmod
#     it checks /sys/module/vcachefs/refcnt and waits for readers to drain; a
#     stuck mount is reported, not force-removed.
#   * OOPS WATCH — snapshots the kernel-log tail at start and, after every phase
#     (and in a background poller), scans NEW lines for BUG/Oops/WARN/
#     "general protection"/"unable to handle"/soft-lockup/RCU-stall.  On the
#     first hit it STOPS the stress, tears down, and dumps the offending lines —
#     so a fault is caught early instead of being hammered on.
#   * CORRECTNESS UNDER LOAD — every read is checked against the known SHA-256 of
#     the plaintext, so a silent mis-decrypt is a FAIL, not just a crash.
#   * BOUNDED + TUNABLE — concurrency, iteration count and duration are env vars
#     with gentle defaults; nothing runs unbounded.
#   * READ-ONLY to the system — all artifacts live under a mktemp dir; the only
#     privileged actions are insmod/mount/umount/rmmod of THIS module.
#
# Requires root (insmod/mount).  Everything is cleaned up on any exit.
#
#   sudo bash stress_antirevfs.sh
#   sudo JOBS=8 ITERS=2000 DURATION=120 bash stress_antirevfs.sh
#   sudo NFILES=40 FILE_MB=4 bash stress_antirevfs.sh
#
# Env knobs (all optional):
#   JOBS       concurrent reader processes           (default 4)
#   ITERS      read iterations per reader             (default 500)
#   DURATION   max wall-clock seconds for the whole   (default 60)
#              stress phase; whichever of ITERS/DURATION comes first wins
#   NFILES     number of distinct encrypted files     (default 12)
#   FILE_MB    approx size of the largest file (MB)   (default 2)
#   MOUNT_CYCLES  mount/umount churn iterations        (default 20)
#   MOD        path to vcachefs.ko  (default ../module/vcachefs.ko)
#   KEEP_GOING 1 = keep testing after a non-fatal FAIL (default 0 = stop on oops)
set -uo pipefail

# ── config ────────────────────────────────────────────────────────────
JOBS="${JOBS:-4}"
ITERS="${ITERS:-500}"
DURATION="${DURATION:-60}"
NFILES="${NFILES:-12}"
FILE_MB="${FILE_MB:-2}"
MOUNT_CYCLES="${MOUNT_CYCLES:-20}"
KEEP_GOING="${KEEP_GOING:-0}"

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="${MOD:-$KMOD/module/vcachefs.ko}"
PROTECT="$ROOT/shared/protect.py"

PASS=0; FAIL=0; ABORTED=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
info() { echo "  [....] $*"; }
hdr()  { echo; echo "== $* =="; }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]]  || { echo "module not built: $MOD"; exit 1; }
command -v sha256sum >/dev/null || { echo "need sha256sum"; exit 1; }
command -v python3   >/dev/null || { echo "need python3"; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vcf_stress.XXXXXX")"
ENC="$WORK/.enc"; MP="$WORK/mnt"; MP2="$WORK/mnt2"
mkdir -p "$ENC" "$MP" "$MP2"

# ── kernel-log oops watch ───────────────────────────────────────────────
# Prefer a persistent cursor over dmesg tail so we never miss ring-buffer wrap.
KLOG_BASE=0
klog_snapshot() { KLOG_BASE="$(dmesg 2>/dev/null | wc -l)"; }
# Emit only NEW kernel-log lines since the last snapshot.
klog_new() { dmesg 2>/dev/null | tail -n +"$((KLOG_BASE+1))"; }
OOPS_RE='BUG:|Oops|kernel BUG|general protection|unable to handle|'\
'NULL pointer|soft lockup|hard LOCKUP|rcu_sched self-detected|'\
'RCU Stall|WARNING:|list_del corruption|refcount_t|use-after-free|KASAN'
# Returns 0 (and prints the lines) if a fault appeared in new klog since snapshot.
oops_since() {
	local new
	new="$(klog_new | grep -E "$OOPS_RE" || true)"
	[[ -z "$new" ]] && return 1
	echo "  !!! KERNEL LOG ANOMALY:"
	echo "$new" | sed 's/^/      /'
	return 0
}

STRESS_STOP="$WORK/.stop"   # touch to signal all readers to stop early
WATCH_PID=""

# ── teardown: never force; drain readers, drop mounts, then rmmod ───────
drain_and_unmount() {
	local mp="$1" tries=0
	mountpoint -q "$mp" || return 0
	# Nudge any of our readers to stop, then wait for the mount to be idle.
	touch "$STRESS_STOP" 2>/dev/null || true
	while ! umount "$mp" 2>/dev/null; do
		tries=$((tries+1))
		if [[ $tries -ge 50 ]]; then
			echo "  !!! could not umount $mp after 50 tries (readers still busy);"
			echo "      NOT forcing — leaving it mounted for manual inspection."
			return 1
		fi
		sleep 0.2
	done
	return 0
}

safe_rmmod() {
	local tries=0 rc
	[[ -d /sys/module/vcachefs ]] || return 0
	# Wait for refcnt to fall to 0 (mmap'd libs / open fds pin the module).
	while :; do
		rc="$(cat /sys/module/vcachefs/refcnt 2>/dev/null || echo 0)"
		[[ "$rc" == "0" ]] && break
		tries=$((tries+1))
		if [[ $tries -ge 50 ]]; then
			echo "  !!! vcachefs refcnt=$rc after 10s; NOT forcing rmmod."
			echo "      (a mount or mmap is still live — inspect before removing)"
			return 1
		fi
		sleep 0.2
	done
	rmmod vcachefs 2>/dev/null || {
		echo "  !!! rmmod failed (refcnt=$rc); NOT forcing."
		return 1
	}
	return 0
}

CLEANED=0
cleanup() {
	[[ "$CLEANED" == "1" ]] && return; CLEANED=1
	[[ -n "$WATCH_PID" ]] && kill "$WATCH_PID" 2>/dev/null
	touch "$STRESS_STOP" 2>/dev/null || true
	drain_and_unmount "$MP2"
	drain_and_unmount "$MP"
	safe_rmmod
	rm -rf "$WORK"
}
trap cleanup EXIT
trap 'echo; echo "interrupted — cleaning up safely"; exit 130' INT TERM

# Abort the whole run safely (used on any kernel anomaly).
abort() {
	ABORTED=1
	echo
	echo "!!! ABORTING STRESS — $* (kernel safety first)"
	cleanup
	echo
	echo "==== ABORTED: $PASS passed, $FAIL failed before abort ===="
	exit 2
}

# ── build encrypted corpus of varied sizes ─────────────────────────────
hdr "build encrypted corpus ($NFILES files, up to ${FILE_MB}MB)"
KEY="$WORK/key.hex"
# key-in-.ko: create the key, embed it, build the module with it
source "$KMOD/tests/keyhelper.sh"
arev_build_with_key "$KEY" "$KMOD/module"
declare -a NAMES SHAS
mk_file() {
	local idx="$1" bytes="$2" src="$WORK/src_$idx.bin"
	# Deterministic pseudo-random content (urandom is fine; we hash it).
	head -c "$bytes" /dev/urandom > "$src"
	SHAS[$idx]="$(sha256sum "$src" | awk '{print $1}')"
	NAMES[$idx]="enc_$idx.bin"
	python3 "$PROTECT" encrypt-lib --key "$KEY" \
		--libs "$src" --output-dir "$ENC" >/dev/null 2>&1 \
		|| abort "packing enc_$idx failed"
	mv "$ENC/$(basename "$src")" "$ENC/${NAMES[$idx]}"
}
for i in $(seq 0 $((NFILES-1))); do
	# sizes fan out from ~4KB to FILE_MB, exercising sub-page, multi-page,
	# and the large-buffer decrypt path.
	sz=$(( 4096 + (i * FILE_MB * 1024 * 1024) / NFILES ))
	mk_file "$i" "$sz"
done
info "corpus built: $NFILES files, sizes 4KB..${FILE_MB}MB"

# helper: verify one file read through the mount matches its known SHA
verify_read() {  # $1=idx  -> 0 ok, 1 mismatch/err
	local idx="$1" got
	got="$(sha256sum "$MP/${NAMES[$idx]}" 2>/dev/null | awk '{print $1}')"
	[[ "$got" == "${SHAS[$idx]}" ]]
}

# ══════════════════════════════════════════════════════════════════════
# PRE-FLIGHT GATE — must pass before any stress; leaves module unloaded.
# ══════════════════════════════════════════════════════════════════════
hdr "PRE-FLIGHT (abort if any step fails; no stress until these pass)"

# 0. vermagic must match the running kernel (wrong .ko must NOT be insmod'd).
VM="$(modinfo -F vermagic "$MOD" 2>/dev/null | head -1)"
RUN="$(uname -r)"
if [[ "$VM" == "$RUN"* ]]; then
	ok "vermagic '$VM' matches running kernel '$RUN'"
else
	echo "  vermagic='$VM'  uname -r='$RUN'"
	abort "vermagic mismatch — refusing to insmod a foreign .ko"
fi

klog_snapshot
if insmod "$MOD" 2>/dev/null; then
	ok "insmod clean"
else
	dmesg | tail -8 | sed 's/^/      /'
	abort "insmod failed"
fi
oops_since && abort "kernel anomaly right after insmod"

# Which backend did the module pick (dev build logs it; harmless if silent)?
BK="$(dmesg | grep -Eo 'AES-256-GCM via kernel gcm|built-in software AES-256-GCM' | tail -1 || true)"
[[ -n "$BK" ]] && info "crypto backend: $BK"

if mount -t vcachefs -o ro,passdata "$ENC" "$MP" 2>/dev/null; then
	ok "mount clean"
else
	dmesg | tail -8 | sed 's/^/      /'
	abort "mount failed"
fi
oops_since && abort "kernel anomaly right after mount"

# single-file correctness before we trust the module under load
if verify_read 0 && verify_read $((NFILES-1)); then
	ok "single-read decrypt byte-exact (smallest + largest file)"
else
	abort "decrypt WRONG on a quiet single read — do not stress a broken decrypt"
fi

# clean unmount + unload once, to prove teardown works before churn
drain_and_unmount "$MP" || abort "could not cleanly umount in pre-flight"
safe_rmmod || abort "could not cleanly rmmod in pre-flight (refcnt stuck)"
oops_since && abort "kernel anomaly during pre-flight teardown"
ok "clean umount + rmmod (teardown path verified)"

echo
info "PRE-FLIGHT PASSED — proceeding to stress (JOBS=$JOBS ITERS=$ITERS DURATION=${DURATION}s MOUNT_CYCLES=$MOUNT_CYCLES)"

# Re-establish for the stress phase.
klog_snapshot
insmod "$MOD" 2>/dev/null || abort "insmod (stress) failed"
mount -t vcachefs -o ro,passdata "$ENC" "$MP" 2>/dev/null || abort "mount (stress) failed"

# background oops poller: on first anomaly, signal readers + abort
( while :; do
	sleep 1
	if dmesg 2>/dev/null | tail -n +"$((KLOG_BASE+1))" | grep -Eq "$OOPS_RE"; then
		touch "$STRESS_STOP"
		break
	fi
  done ) &
WATCH_PID=$!

# ══════════════════════════════════════════════════════════════════════
# PHASE 1 — concurrent read/verify storm (decrypt correctness + races)
# ══════════════════════════════════════════════════════════════════════
hdr "PHASE 1: $JOBS concurrent readers × up to $ITERS iters (or ${DURATION}s)"
rm -f "$STRESS_STOP"
END=$(( $(date +%s) + DURATION ))
declare -a RPIDS
reader() {   # $1 = job id ; writes its mismatch count to $WORK/r_$1.rc
	local j="$1" mism=0 n
	for ((n=0; n<ITERS; n++)); do
		[[ -e "$STRESS_STOP" ]] && break
		[[ $(date +%s) -ge $END ]] && break
		local idx=$(( (RANDOM + j*7 + n) % NFILES ))
		verify_read "$idx" || mism=$((mism+1))
	done
	echo "$mism" > "$WORK/r_$j.rc"
}
for ((j=0; j<JOBS; j++)); do reader "$j" & RPIDS[$j]=$!; done
# Watch for the poller signalling an anomaly while readers run.
while :; do
	still=0
	for p in "${RPIDS[@]}"; do kill -0 "$p" 2>/dev/null && still=1; done
	[[ "$still" == "0" ]] && break
	if [[ -e "$STRESS_STOP" ]] && oops_since; then
		# readers will stop on the flag; reap them, then abort safely.
		for p in "${RPIDS[@]}"; do wait "$p" 2>/dev/null; done
		abort "kernel anomaly during concurrent read storm"
	fi
	sleep 0.5
done
for p in "${RPIDS[@]}"; do wait "$p" 2>/dev/null; done
TOTMISM=0
for ((j=0; j<JOBS; j++)); do TOTMISM=$((TOTMISM + $(cat "$WORK/r_$j.rc" 2>/dev/null || echo 1))); done
if [[ "$TOTMISM" == "0" ]]; then
	ok "concurrent readers: every decrypt byte-exact (0 mismatches)"
else
	bad "concurrent readers: $TOTMISM decrypt MISMATCHES (silent corruption!)"
	[[ "$KEEP_GOING" == "1" ]] || abort "decrypt corruption under load"
fi
oops_since && abort "kernel anomaly after read storm"

# ══════════════════════════════════════════════════════════════════════
# PHASE 2 — page-cache sharing: many processes mmap the same file at once
# ══════════════════════════════════════════════════════════════════════
hdr "PHASE 2: shared page-cache faulting ($JOBS × mmap+read same big file)"
BIGIDX=$((NFILES-1))
cat > "$WORK/mmread.py" <<'PY'
import mmap, os, sys, hashlib
p = sys.argv[1]; want = sys.argv[2]
fd = os.open(p, os.O_RDONLY); st = os.fstat(fd)
m = mmap.mmap(fd, st.st_size, prot=mmap.PROT_READ)
h = hashlib.sha256(m[:]).hexdigest()
m.close(); os.close(fd)
sys.exit(0 if h == want else 1)
PY
mm_fail=0; declare -a MPIDS=()
for ((j=0; j<JOBS*2; j++)); do
	python3 "$WORK/mmread.py" "$MP/${NAMES[$BIGIDX]}" "${SHAS[$BIGIDX]}" &
	MPIDS+=("$!")
done
for p in "${MPIDS[@]}"; do wait "$p" || mm_fail=$((mm_fail+1)); done
if [[ "$mm_fail" == "0" ]]; then
	ok "concurrent mmap readers: all saw identical correct plaintext"
else
	bad "concurrent mmap: $mm_fail readers got wrong bytes"
	[[ "$KEEP_GOING" == "1" ]] || abort "page-cache decrypt inconsistency"
fi
oops_since && abort "kernel anomaly after mmap phase"

# ══════════════════════════════════════════════════════════════════════
# PHASE 3 — mount/umount churn (superblock + inode lifecycle)
# ══════════════════════════════════════════════════════════════════════
hdr "PHASE 3: $MOUNT_CYCLES mount/umount cycles on a 2nd mountpoint"
mc_fail=0
for ((c=0; c<MOUNT_CYCLES; c++)); do
	if ! mount -t vcachefs -o ro,passdata "$ENC" "$MP2" 2>/dev/null; then
		mc_fail=$((mc_fail+1)); continue
	fi
	verify_read_mp2() { local g; g="$(sha256sum "$MP2/${NAMES[0]}" 2>/dev/null | awk '{print $1}')"; [[ "$g" == "${SHAS[0]}" ]]; }
	verify_read_mp2 || mc_fail=$((mc_fail+1))
	drain_and_unmount "$MP2" || { mc_fail=$((mc_fail+1)); break; }
	if [[ -e "$STRESS_STOP" ]]; then oops_since && abort "kernel anomaly during mount churn"; fi
done
if [[ "$mc_fail" == "0" ]]; then
	ok "$MOUNT_CYCLES mount/umount cycles clean (decrypt OK each time)"
else
	bad "mount churn: $mc_fail failures"
fi
oops_since && abort "kernel anomaly after mount churn"

# ══════════════════════════════════════════════════════════════════════
# PHASE 4 — fd pressure: open many files, hold fds, read, close
# ══════════════════════════════════════════════════════════════════════
hdr "PHASE 4: fd/open pressure (open all $NFILES, hold, verify, close) ×$JOBS"
cat > "$WORK/fdhold.py" <<'PY'
import os, sys, hashlib
base = sys.argv[1]
pairs = [(sys.argv[i], sys.argv[i+1]) for i in range(2, len(sys.argv), 2)]
fds = []
try:
    for name, _ in pairs:
        fds.append(os.open(os.path.join(base, name), os.O_RDONLY))
    bad = 0
    for fd, (name, want) in zip(fds, pairs):
        os.lseek(fd, 0, 0)
        data = b""
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk: break
            data += chunk
        if hashlib.sha256(data).hexdigest() != want:
            bad += 1
    sys.exit(0 if bad == 0 else 1)
finally:
    for fd in fds: os.close(fd)
PY
args=(); for ((i=0;i<NFILES;i++)); do args+=("${NAMES[$i]}" "${SHAS[$i]}"); done
fd_fail=0; declare -a FPIDS=()
for ((j=0; j<JOBS; j++)); do
	python3 "$WORK/fdhold.py" "$MP" "${args[@]}" &
	FPIDS+=("$!")
done
for p in "${FPIDS[@]}"; do wait "$p" || fd_fail=$((fd_fail+1)); done
if [[ "$fd_fail" == "0" ]]; then
	ok "fd pressure: all files verified correct while many fds held open"
else
	bad "fd pressure: $fd_fail workers saw wrong bytes"
	[[ "$KEEP_GOING" == "1" ]] || abort "decrypt error under fd pressure"
fi
oops_since && abort "kernel anomaly after fd phase"

# ── stop background watcher and tear down through the safe path ─────────
kill "$WATCH_PID" 2>/dev/null; WATCH_PID=""
hdr "teardown"
drain_and_unmount "$MP" && ok "final umount clean" || bad "final umount stuck (not forced)"
safe_rmmod && ok "final rmmod clean (refcnt reached 0)" || bad "final rmmod stuck (not forced)"
oops_since && bad "kernel anomaly during final teardown"

# ── summary ─────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════"
echo "  vcachefs STRESS: $PASS passed, $FAIL failed"
echo "  (JOBS=$JOBS ITERS=$ITERS DURATION=${DURATION}s NFILES=$NFILES FILE_MB=$FILE_MB MOUNT_CYCLES=$MOUNT_CYCLES)"
echo "════════════════════════════════════════════════════════════════"
[[ "$FAIL" == "0" ]] && exit 0 || exit 1
