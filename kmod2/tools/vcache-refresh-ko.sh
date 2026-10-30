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
# Exit codes (also the only thing a fleet runner needs to branch on):
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

while [ $# -gt 0 ]; do
	case "$1" in
		--target)     TARGET="$2"; shift 2 ;;
		--target=*)   TARGET="${1#*=}"; shift ;;
		--down-mine)  DOWN_MINE=1; shift ;;
		-h|--help)    sed -n '2,30p' "$0"; exit 0 ;;
		-*)           err "unknown option: $1"; exit 1 ;;
		*)            NEW="$1"; shift ;;
	esac
done

[ -n "$NEW" ]   || { err "no new .ko given (usage: $0 <new-vcachefs.ko>)"; exit 1; }
[ -r "$NEW" ]   || { err "cannot read new .ko: $NEW"; exit 1; }

# ---- must be root (insmod/rmmod + replace a root-owned .ko) -----------------
if [ "$(id -u)" != 0 ]; then
	info "re-executing under sudo"
	exec sudo -E "$0" ${TARGET:+--target "$TARGET"} ${DOWN_MINE:+--down-mine} "$NEW"
fi

command -v modinfo >/dev/null || { err "modinfo not found (install kmod)"; exit 1; }

# ---- 1. validate the new .ko matches THIS kernel ---------------------------
new_vermagic="$(modinfo -F vermagic "$NEW" 2>/dev/null)"
[ -n "$new_vermagic" ] || { err "not a valid module: $NEW"; exit 1; }
new_rel="${new_vermagic%% *}"                 # first vermagic token = kernel release
if [ "$new_rel" != "$(uname -r)" ]; then
	err "kernel mismatch: new .ko is for '$new_rel', this box is '$(uname -r)' — refusing"
	exit 1
fi
new_srcver="$(modinfo -F srcversion "$NEW" 2>/dev/null)"
info "new .ko: vermagic='$new_vermagic' srcversion='$new_srcver'"

# ---- 2. is the running module already this exact build? --------------------
loaded=0; loaded_srcver=""; refcnt=0
if [ -d /sys/module/vcachefs ]; then
	loaded=1
	loaded_srcver="$(cat /sys/module/vcachefs/srcversion 2>/dev/null || true)"
	refcnt="$(cat /sys/module/vcachefs/refcnt 2>/dev/null || echo 0)"
fi

# ---- 3. install the new .ko on disk (always safe) --------------------------
# Replacing the file never affects the loaded module; it only determines what the
# NEXT load (reboot / next idle reload) picks up.  Atomic: temp + rename.
install_file() {
	local dir tmp
	dir="$(dirname "$TARGET")"
	mkdir -p "$dir" || { err "cannot create $dir"; exit 1; }
	tmp="$(mktemp "$dir/.vcachefs.ko.XXXXXX")" || { err "mktemp failed in $dir"; exit 1; }
	if ! cp -f "$NEW" "$tmp"; then err "copy to $tmp failed"; rm -f "$tmp"; exit 1; fi
	chmod 0644 "$tmp"; chown root:root "$tmp" 2>/dev/null || true
	mv -f "$tmp" "$TARGET" || { err "atomic install to $TARGET failed"; rm -f "$tmp"; exit 1; }
	info "installed new .ko -> $TARGET"
	# If it lives under /lib/modules, refresh modules.dep so modprobe sees it.
	case "$TARGET" in /lib/modules/*) depmod -a 2>/dev/null || true ;; esac
}
install_file

if [ "$loaded" = 1 ] && [ -n "$new_srcver" ] && [ "$loaded_srcver" = "$new_srcver" ]; then
	info "running module is ALREADY this build (srcversion=$new_srcver) — nothing to reload"
	exit 0
fi

# ---- 4. reload now, only if the machine is quiet ---------------------------
reload_now() {
	if [ "$loaded" = 1 ]; then
		info "unloading old module (srcversion=${loaded_srcver:-?})"
		if ! rmmod vcachefs 2>/dev/null; then
			# raced: someone mounted/started proj between the refcnt check and now
			err "rmmod failed (module became busy) — leaving new .ko STAGED"
			return 10
		fi
	fi
	info "loading new module ($INSMOD_PARAMS)"
	if ! insmod "$TARGET" $INSMOD_PARAMS 2>/dev/null; then
		err "insmod of the new .ko FAILED — box now has NO vcachefs module loaded"
		err "   check: 'dmesg | tail' ; the new .ko may be broken or need AREV_* build flags"
		return 1
	fi
	local now; now="$(cat /sys/module/vcachefs/srcversion 2>/dev/null || true)"
	if [ -n "$new_srcver" ] && [ "$now" != "$new_srcver" ]; then
		err "loaded srcversion ('$now') != new ('$new_srcver') — wrong file loaded?"
		return 1
	fi
	info "ACTIVE: vcachefs reloaded, srcversion=$now"
	return 0
}

if [ "$loaded" = 0 ]; then
	info "module not currently loaded — loading the new one"
	reload_now; exit $?
fi

# Optionally tear down THIS user's own idle proj mounts first (never others').
if [ "$refcnt" != 0 ] && [ "$DOWN_MINE" = 1 ] && command -v vcache-mount-inplace >/dev/null; then
	info "--down-mine: tearing down this invocation's proj mounts"
	vcache-mount-inplace --mode real down >/dev/null 2>&1 || true
	refcnt="$(cat /sys/module/vcachefs/refcnt 2>/dev/null || echo 0)"
fi

if [ "$refcnt" = 0 ]; then
	reload_now; exit $?
fi

# ---- 5. busy: do NOT force.  Stage + report. -------------------------------
warn "module is IN USE (refcnt=$refcnt) — NOT reloading (would break running proj)"
warn "the new .ko is installed on disk and will take effect at the next full-idle reload / reboot"
info "what is pinning it (stop ALL of these — every user's proj — then re-run, or reboot):"
grep -w vcachefs /proc/mounts 2>/dev/null | awk '{print "    mount: " $2}' || true
if command -v fuser >/dev/null; then
	# processes with files open/mapped under each vcachefs mountpoint
	grep -w vcachefs /proc/mounts 2>/dev/null | awk '{print $2}' | while read -r mp; do
		fuser -m "$mp" 2>/dev/null | tr -s ' ' | sed "s|^|    procs on $mp:|"
	done
fi
exit 10
