#!/usr/bin/env bash
#
# vcache-remount.sh — tear down and re-establish the vcachefs mounts
# for the business stack, reloading the module with the decrypt-auth gate.
#
#   /root/proj_protect/lib  (ciphertext) -> /root/proj/lib  (WRITABLE view: overlay over vcachefs)
#   /root/proj_protect/bin  (ciphertext) -> /root/proj/bin  (WRITABLE view: overlay over vcachefs)
#
# Both trees are mounted as WRITABLE overlay views: decrypted .so/.elf reads
# fall through to the vcachefs lower, while any runtime write (GUI pid/lock/log
# files next to the binaries) lands in the overlay's writable upper and NEVER
# touches the ciphertext tree.
#
# No key handling: each encrypted file embeds its own AES key in a trailer, read
# by the module at decrypt time — there is no unlock step and no session-keyring
# dance.  An unauthorized read is served the container with the key trailer
# stripped (gate_passthrough_cipher=1 below).  Run as root; re-execs with sudo.
#
set -euo pipefail

##### ---- configuration: EDIT to match your deployment -------------------------
KMOD_DIR=/root/vcache/kmod2/module      # dir containing vcachefs.ko
TOOLS_DIR=/root/vcache/kmod2/tools      # dir with vcache-mount-ro / -mount-rw

LIB_LOWER=/root/proj_protect/lib
LIB_MOUNT=/root/proj/lib
BIN_LOWER=/root/proj_protect/bin
BIN_MOUNT=/root/proj/bin

GATE_ENFORCE=1                           # 1 = enforce /etc/authorized_apps.txt, 0 = allow all
GATE_PASSTHROUGH=1                       # 1 = unauthorized read gets trailer-stripped ciphertext; 0 = -EACCES
AUTHZ_PATH=/etc/authorized_apps.txt
MOUNT_FLAG=--passdata                    # or:  --passthrough so:py:pyc   (see vcache-mount-ro -h)
LIB_WRITABLE=1                           # 1 = lib is a writable overlay view too (set 0 for read-only lib)
##### ---------------------------------------------------------------------------

KO="$KMOD_DIR/vcachefs.ko"
MOUNT_BIN="$TOOLS_DIR/vcache-mount-ro"
MOUNTRW_BIN="$TOOLS_DIR/vcache-mount-rw"

log() { printf '[remount] %s\n' "$*"; }
die() { printf '[remount] ERROR: %s\n' "$*" >&2; exit 1; }

# 1) must be root (no keyring needed — keys are embedded per-file)
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -E "$0" "$@"
fi

# ---- sanity ------------------------------------------------------------------
[ -f "$KO" ]        || die "module not found: $KO"
[ -x "$MOUNT_BIN" ] || die "vcache-mount-ro not found/executable: $MOUNT_BIN"
[ -x "$MOUNTRW_BIN" ] || die "vcache-mount-rw not found/executable: $MOUNTRW_BIN"

# ---- teardown ----------------------------------------------------------------
force_down() {
    local mp="$1"
    mountpoint -q "$mp" 2>/dev/null || return 0
    log "unmounting $mp"
    umount "$mp"    2>/dev/null && return 0
    umount -R "$mp" 2>/dev/null && return 0
    sleep 1
    umount "$mp"    2>/dev/null && return 0
    log "$mp busy — lazy unmount"
    umount -l "$mp"
}

# unmount every vcachefs/overlay mount under the proj trees, deepest first,
# so a leftover overlay 'dec' lower (under .vcache-rw) can't pin the module.
sweep_proj_mounts() {
    local mps mp
    mps=$(grep -E 'vcachefs|overlay' /proc/mounts \
          | awk '$2 ~ /\/root\/proj/ {print $2}' | sort -r) || true
    for mp in $mps; do force_down "$mp"; done
}

log "tearing down existing mounts"
# Always try to collapse a writable overlay on BOTH mountpoints, regardless of
# this run's mode — a leftover overlay from a previous run (possibly the other
# mode) must be torn down (overlay then its vcachefs 'dec' lower) before the
# sweep, or the 'dec' mount stays pinned and rmmod fails. Harmless if absent.
"$MOUNTRW_BIN" --down "$BIN_MOUNT" 2>/dev/null || true
"$MOUNTRW_BIN" --down "$LIB_MOUNT" 2>/dev/null || true
sweep_proj_mounts

# ---- reload module -----------------------------------------------------------
# /sys/module/vcachefs is authoritative (independent of lsmod / PATH).
if [ -d /sys/module/vcachefs ]; then
    log "removing vcachefs module"
    if ! rmmod vcachefs 2>/dev/null; then
        log "rmmod failed — module in use (refcnt=$(cat /sys/module/vcachefs/refcnt 2>/dev/null))"
        log "vcachefs mounts still present in this namespace:"
        grep vcachefs /proc/mounts || log "  (none — likely a lazy-unmounted mount still held by a"
        log "   running process, or an vcachefs mount inside a container namespace)"
        log "processes whose mount namespace still references vcachefs:"
        grep -l vcachefs /proc/*/mountinfo 2>/dev/null || true
        die "stop the business stack (mmap'd .so files pin the module), then re-run"
    fi
fi
[ -d /sys/module/vcachefs ] && die "vcachefs still loaded after rmmod"
log "loading vcachefs (gate_enforce=$GATE_ENFORCE gate_passthrough_cipher=$GATE_PASSTHROUGH authz_path=$AUTHZ_PATH)"
insmod "$KO" gate_enforce="$GATE_ENFORCE" \
	gate_passthrough_cipher="$GATE_PASSTHROUGH" \
	authz_path="$AUTHZ_PATH" || die "insmod failed"

# (no key step — each encrypted file carries its own key in a trailer)

# ---- mount -------------------------------------------------------------------
log "mounting lib: $LIB_LOWER -> $LIB_MOUNT"
if [ "$LIB_WRITABLE" = 1 ]; then
    "$MOUNTRW_BIN" $MOUNT_FLAG "$LIB_LOWER" "$LIB_MOUNT" || die "lib (rw) mount failed"
else
    "$MOUNT_BIN"   $MOUNT_FLAG "$LIB_LOWER" "$LIB_MOUNT" || die "lib (ro) mount failed"
fi

log "mounting bin (writable view): $BIN_LOWER -> $BIN_MOUNT"
"$MOUNTRW_BIN" $MOUNT_FLAG "$BIN_LOWER" "$BIN_MOUNT" || die "bin (rw) mount failed"

# ---- verify ------------------------------------------------------------------
log "active proj mounts:"
grep -E 'vcachefs|overlay' /proc/mounts | grep -E '/root/proj' || true
log "done — gate_enforce=$(cat /sys/module/vcachefs/parameters/gate_enforce 2>/dev/null)"
