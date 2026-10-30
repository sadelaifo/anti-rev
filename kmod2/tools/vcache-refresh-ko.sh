#!/bin/bash
# vcache-refresh-ko.sh — install a new vcachefs.ko on a deployed machine and make
# it active when (and only when) it is SAFE to do so.
#
# KERNEL REALITY (read this): vcachefs.ko is ONE kernel-global module shared by
# every user and every mount on the machine.  There is no per-user copy, and the
# running code CANNOT be swapped while ANY vcachefs mount is live — `rmmod` needs
# the module's refcount at 0, and every user's proj mount (plus any mmap'd file
# under it) adds to that count.  A user "re-running his proj" does NOT by itself
# pick up new module code: his mount re-uses the already-loaded (old) module.
# New CODE is active only after a real rmmod+insmod, which needs the WHOLE machine
# quiet (all users' proj down).  You cannot refresh one user's module while others
# keep running the old one.
#
# So this script:
#   1. installs the new .ko on disk atomically (always safe; the next load uses it);
#   2. if the module is NOT loaded, OR loaded with refcount 0 (nobody using it this
#      instant): rmmod + insmod the new one  -> active immediately;
#   3. if it is in use (other proj instances/users): it does NOT force anything
#      (never rmmod -f / umount -l) — it leaves the new .ko STAGED and tells you the
#      swap will happen at the next fully-idle moment or reboot.
#
# Usage:
#   sudo vcache-refresh-ko.sh <new-vcachefs.ko> [--target <path>] [--down-mine]
#     <new-vcachefs.ko>  the new module your fleet tooling pushed to this machine
#     --target <path>    the authoritative on-disk .ko the boot/mount tool loads
#                        (default: $VCACHE_KO_TARGET or the CFG_TARGET below)
#     --down-mine        first tear down THIS invocation's own idle proj mounts
#                        (vcache-mount-inplace down), then re-check refcount.  Only
#                        helps if YOUR proj is the sole user and is not actively
#                        mmap-pinning the module.  Never touches other users' mounts.
#   Env: VCACHE_INSMOD_PARAMS (default "gate_passthrough_cipher=1") — insmod args,
#        must match your deployment's load params.
#
# Every failure prints the REAL underlying error (from rmmod/insmod/modinfo/cp),
# what it means, and what to do — and always ends with a one-line verdict naming
# the exit code.  Exit codes (the only thing a fleet runner needs to branch on):
#   0  refreshed and ACTIVE now (or already current)
#   10 installed but STAGED — machine busy, reload deferred to next idle/reboot
#   1  error (bad/missing .ko, wrong kernel, install failed, reload raced to busy)
set -u

# ---- config (override via env / flags) -------------------------------------
CFG_TARGET="/root/vcache/kmod2/module/vcachefs.ko"   # where boot/mount tool loads from
TARGET="${VCACHE_KO_TARGET:-$CFG_TARGET}"
INSMOD_PARAMS="${VCACHE_INSMOD_PARAMS:-gate_passthrough_cipher=1}"
DOWN_MINE=0
NEW=""

log()  { printf '%s [%s]  %s\n' "$(date '+%F %T')" "$1" "${*:2}"; }
info() { log INFO  "$@"; }
warn() { log WARN  "$@"; }
err()  { log ERROR "$@"; }

# finish <code> — print the verdict line for <code> and exit with it.  Any
# explanatory ERROR/WARN lines are printed by the caller just before this.
finish() {
	case "$1" in
	0)  info "==> exit 0: the new module is ACTIVE now (or was already the running build)." ;;
	10) warn "==> exit 10: the new .ko is INSTALLED on disk but NOT yet active."
	    warn "            It loads at the next reboot, or next time this machine has NO proj running." ;;
	1)  err  "==> exit 1: refresh FAILED — nothing new was activated. See the error(s) above." ;;
	*)  err  "==> exit $1" ;;
	esac
	exit "$1"
}

while [ $# -gt 0 ]; do
	case "$1" in
		--target)     TARGET="$2"; shift 2 ;;
		--target=*)   TARGET="${1#*=}"; shift ;;
		--down-mine)  DOWN_MINE=1; shift ;;
		-h|--help)    sed -n '2,45p' "$0"; exit 0 ;;
		-*)           err "unknown option '$1'."; err "  run with -h for usage."; finish 1 ;;
		*)            NEW="$1"; shift ;;
	esac
done

if [ -z "$NEW" ]; then
	err "no new .ko file was given."
	err "  pass the new module as the first argument, e.g.:"
	err "    sudo $0 /path/to/new/vcachefs.ko --target $TARGET"
	finish 1
fi
if [ ! -r "$NEW" ]; then
	err "cannot read the new .ko at '$NEW'."
	err "  meaning: the file is missing, the path is wrong, or you lack read permission."
	err "  check where your fleet tooling copied it, and the exact path/spelling."
	finish 1
fi
if ! command -v modinfo >/dev/null; then
	err "'modinfo' is not installed (it ships in the 'kmod' package)."
	err "  meaning: this script cannot inspect the module without it."
	err "  fix: install kmod (apt/zypper/yum install kmod), then re-run."
	finish 1
fi

# ---- must be root (insmod/rmmod + replace a root-owned .ko) -----------------
if [ "$(id -u)" != 0 ]; then
	info "not root — re-executing under sudo (you may be prompted for a password)"
	exec sudo -E "$0" --target "$TARGET" $([ "$DOWN_MINE" = 1 ] && echo --down-mine) "$NEW"
fi

# ---- 1. validate the new .ko matches THIS kernel ---------------------------
if ! new_vermagic="$(modinfo -F vermagic "$NEW" 2>&1)" || [ -z "$new_vermagic" ]; then
	err "'$NEW' is not a usable kernel module."
	err "  modinfo said: ${new_vermagic:-<no vermagic>}"
	err "  meaning: the file is truncated, corrupted, not a .ko, or the wrong file."
	err "  fix: re-copy the new vcachefs.ko and check its size/sha against the source."
	finish 1
fi
new_rel="${new_vermagic%% *}"                 # first vermagic token = kernel release
if [ "$new_rel" != "$(uname -r)" ]; then
	err "kernel mismatch: this .ko was built for kernel '$new_rel',"
	err "  but this machine is running '$(uname -r)'."
	err "  meaning: loading it would fail ('Invalid module format') or be unsafe."
	err "  fix: build/push the vcachefs.ko for THIS kernel (match 'uname -r'),"
	err "       and the right CPU arch (e.g. arm64 BiSheng vs x86-64)."
	finish 1
fi
new_srcver="$(modinfo -F srcversion "$NEW" 2>/dev/null)"
info "new .ko looks valid: kernel='$new_rel' srcversion='${new_srcver:-?}'"

# ---- 2. is the running module already this exact build? --------------------
loaded=0; loaded_srcver=""; refcnt=0
if [ -d /sys/module/vcachefs ]; then
	loaded=1
	loaded_srcver="$(cat /sys/module/vcachefs/srcversion 2>/dev/null || true)"
	refcnt="$(cat /sys/module/vcachefs/refcnt 2>/dev/null || echo 0)"
	info "currently loaded: srcversion='${loaded_srcver:-?}' refcnt=$refcnt (users/mounts pinning it)"
else
	info "vcachefs is not currently loaded on this machine"
fi

# ---- 3. install the new .ko on disk (always safe) --------------------------
# Replacing the file never affects the loaded module; it only determines what the
# NEXT load (reboot / next idle reload) picks up.  Atomic: temp + rename.
dir="$(dirname "$TARGET")"
if ! mkdir -p "$dir" 2>/tmp/.vck.$$; then
	err "cannot create the target directory '$dir': $(cat /tmp/.vck.$$ 2>/dev/null); rm -f /tmp/.vck.$$"
	err "  meaning: --target points somewhere this box can't create, or the disk is read-only/full."
	err "  fix: pass a correct --target (where your boot/mount tool loads the .ko from)."
	rm -f /tmp/.vck.$$; finish 1
fi
rm -f /tmp/.vck.$$
tmp="$(mktemp "$dir/.vcachefs.ko.XXXXXX" 2>/dev/null)" || {
	err "cannot create a temp file in '$dir' (disk full, or read-only filesystem)."
	err "  fix: free space / remount rw, or choose a writable --target, then re-run."
	finish 1
}
if ! cp_err="$(cp -f "$NEW" "$tmp" 2>&1)"; then
	err "failed to copy the new .ko into place: $cp_err"
	err "  meaning: disk full, permission, or source disappeared mid-copy."
	rm -f "$tmp"; finish 1
fi
chmod 0644 "$tmp"; chown root:root "$tmp" 2>/dev/null || true
if ! mv_err="$(mv -f "$tmp" "$TARGET" 2>&1)"; then
	err "failed to install the .ko to '$TARGET': $mv_err"
	err "  meaning: the target path is on a different/read-only fs, or is in use."
	rm -f "$tmp"; finish 1
fi
info "installed the new .ko -> $TARGET (on-disk copy updated; the next load uses it)"
case "$TARGET" in /lib/modules/*) depmod -a 2>/dev/null || true ;; esac

if [ "$loaded" = 1 ] && [ -n "$new_srcver" ] && [ "$loaded_srcver" = "$new_srcver" ]; then
	info "the RUNNING module is already this exact build (srcversion=$new_srcver) — no reload needed."
	finish 0
fi

# ---- 4. reload now, only if the machine is quiet ---------------------------
# Terminal: this function always calls finish() and exits.
reload_now() {
	if [ "$loaded" = 1 ]; then
		info "unloading the old module (srcversion=${loaded_srcver:-?})"
		if ! rm_err="$(rmmod vcachefs 2>&1)"; then
			err "could not unload the old module: $rm_err"
			if printf '%s' "$rm_err" | grep -qi "busy\|temporarily"; then
				err "  meaning: it became BUSY between the check and now — a proj mount/process"
				err "           started using it.  Nothing was changed; the new .ko stays staged."
				err "  fix: ensure NO user is running proj, then re-run (or just reboot)."
				finish 10
			fi
			err "  meaning: unexpected unload failure (see the message above)."
			finish 1
		fi
	fi
	info "loading the new module (insmod params: $INSMOD_PARAMS)"
	if ! in_err="$(insmod "$TARGET" $INSMOD_PARAMS 2>&1)"; then
		err "the new .ko FAILED to load: $in_err"
		err "  !! this machine now has NO vcachefs module loaded — proj will NOT run until fixed."
		case "$in_err" in
		*"Invalid module format"*)
			err "  meaning: the .ko does not match this kernel/toolchain (vermagic/CONFIG)." ;;
		*"Required key"*|*"key was rejected"*)
			err "  meaning: Secure Boot/lockdown is rejecting an unsigned module." ;;
		*"Unknown symbol"*)
			err "  meaning: it was built against a different kernel config (missing symbol)." ;;
		*"Operation not permitted"*)
			err "  meaning: not permitted (not root, or kernel lockdown)." ;;
		*"File exists"*)
			err "  meaning: a vcachefs module is still loaded (unload did not take effect)." ;;
		*)  err "  meaning: see the loader message above and 'dmesg | tail'." ;;
		esac
		err "  recover: load your previous known-good vcachefs.ko to restore service,"
		err "           then investigate this build before retrying."
		finish 1
	fi
	now="$(cat /sys/module/vcachefs/srcversion 2>/dev/null || true)"
	if [ -n "$new_srcver" ] && [ "$now" != "$new_srcver" ]; then
		err "loaded, but srcversion ('$now') != the new .ko ('$new_srcver')."
		err "  meaning: a DIFFERENT/stale .ko got loaded — check that --target ('$TARGET')"
		err "           is really the path the loader used."
		finish 1
	fi
	info "SUCCESS: vcachefs reloaded and ACTIVE (srcversion=$now)."
	finish 0
}

if [ "$loaded" = 0 ]; then
	info "module not loaded — loading the new one now"
	reload_now
fi

# Optionally tear down THIS user's own idle proj mounts first (never others').
if [ "$refcnt" != 0 ] && [ "$DOWN_MINE" = 1 ] && command -v vcache-mount-inplace >/dev/null; then
	info "--down-mine: tearing down this invocation's own proj mounts, then re-checking"
	vcache-mount-inplace --mode real down >/dev/null 2>&1 || true
	refcnt="$(cat /sys/module/vcachefs/refcnt 2>/dev/null || echo 0)"
	info "refcount after --down-mine: $refcnt"
fi

if [ "$refcnt" = 0 ]; then
	reload_now
fi

# ---- 5. busy: do NOT force.  Stage + report exactly what is pinning it. -----
warn "the module is IN USE (refcnt=$refcnt) — NOT reloading, because forcing it would"
warn "  break every proj currently running on this machine (yours AND other users')."
warn "the new .ko is safely installed on disk; it becomes active at the next reboot, or"
warn "  the next time this machine has NO proj running."
warn "to activate NOW: stop ALL of the following (every user's proj), then re-run this"
warn "  script — or simply reboot the machine:"
if grep -qw vcachefs /proc/mounts 2>/dev/null; then
	grep -w vcachefs /proc/mounts 2>/dev/null | awk '{print "    mount:  " $2}'
	if command -v fuser >/dev/null; then
		grep -w vcachefs /proc/mounts 2>/dev/null | awk '{print $2}' | while read -r mp; do
			pids="$(fuser -m "$mp" 2>/dev/null | tr -s ' ')"
			[ -n "$pids" ] && echo "    procs on $mp:$pids"
		done
	fi
else
	warn "    (no vcachefs mount is visible, yet refcnt=$refcnt — a process still has an"
	warn "     mmap'd file from a since-unmounted proj; find it with: lsof | grep vcachefs)"
fi
finish 10
