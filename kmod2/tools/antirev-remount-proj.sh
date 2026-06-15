#!/usr/bin/env bash
#
# antirev-remount-proj.sh — tear down and re-establish the antirevfs mounts
# for the business stack, reloading the module with the decrypt-auth gate.
#
#   /root/proj_protect/lib  (ciphertext) -> /root/proj/lib  (read-only, decrypt-on-read)
#   /root/proj_protect/bin  (ciphertext) -> /root/proj/bin  (WRITABLE view: overlay over antirevfs,
#                                                            so GUI/pid/lock/log writes succeed)
#
# Everything that needs the AES key (unlock + mount) runs inside ONE session
# keyring, so the module's request_key() finds it (see CLAUDE.md
# "session-keyring gotcha"). Run as root; it re-execs itself with sudo + keyctl.
#
set -euo pipefail

##### ---- configuration: EDIT to match your deployment -------------------------
KMOD_DIR=/root/antirev/kmod2/module      # dir containing antirevfs.ko
TOOLS_DIR=/root/antirev/kmod2/tools      # dir with antirev-keyctl / -mount / -mount-rw
KEYFILE=/root/antirev/key.hex            # 64-hex AES key (same one used to encrypt)

LIB_LOWER=/root/proj_protect/lib
LIB_MOUNT=/root/proj/lib
BIN_LOWER=/root/proj_protect/bin
BIN_MOUNT=/root/proj/bin

GATE_ENFORCE=1                           # 1 = enforce /etc/authorized_apps.txt, 0 = allow all
AUTHZ_PATH=/etc/authorized_apps.txt
MOUNT_FLAG=--passdata                    # or:  --passthrough so:py:pyc   (see antirev-mount -h)
LIB_WRITABLE=0                           # set 1 if lib also needs runtime writes (overlay)
##### ---------------------------------------------------------------------------

KO="$KMOD_DIR/antirevfs.ko"
KEYCTL_BIN="$TOOLS_DIR/antirev-keyctl"
MOUNT_BIN="$TOOLS_DIR/antirev-mount"
MOUNTRW_BIN="$TOOLS_DIR/antirev-mount-rw"

log() { printf '[remount] %s\n' "$*"; }
die() { printf '[remount] ERROR: %s\n' "$*" >&2; exit 1; }

# 1) must be root
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -E "$0" "$@"
fi

# 2) re-exec under a fresh session keyring so antirev-keyctl + mount share one _ses
if [ "${AREV_IN_SESSION:-}" != 1 ]; then
    export AREV_IN_SESSION=1
    exec keyctl session - "$0" "$@"
fi

# ---- sanity ------------------------------------------------------------------
[ -f "$KO" ]        || die "module not found: $KO"
[ -x "$MOUNT_BIN" ] || die "antirev-mount not found/executable: $MOUNT_BIN"
[ -x "$MOUNTRW_BIN" ] || die "antirev-mount-rw not found/executable: $MOUNTRW_BIN"
[ -r "$KEYFILE" ]   || die "keyfile not readable: $KEYFILE"

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

# unmount every antirevfs/overlay mount under the proj trees, deepest first,
# so a leftover overlay 'dec' lower (under .antirev-rw) can't pin the module.
sweep_proj_mounts() {
    local mps mp
    mps=$(grep -E 'antirevfs|overlay' /proc/mounts \
          | awk '$2 ~ /\/root\/proj/ {print $2}' | sort -r) || true
    for mp in $mps; do force_down "$mp"; done
}

log "tearing down existing mounts"
# Always try to collapse a writable overlay on BOTH mountpoints, regardless of
# this run's mode — a leftover overlay from a previous run (possibly the other
# mode) must be torn down (overlay then its antirevfs 'dec' lower) before the
# sweep, or the 'dec' mount stays pinned and rmmod fails. Harmless if absent.
"$MOUNTRW_BIN" --down "$BIN_MOUNT" 2>/dev/null || true
"$MOUNTRW_BIN" --down "$LIB_MOUNT" 2>/dev/null || true
sweep_proj_mounts

# ---- reload module -----------------------------------------------------------
# /sys/module/antirevfs is authoritative (independent of lsmod / PATH).
if [ -d /sys/module/antirevfs ]; then
    log "removing antirevfs module"
    if ! rmmod antirevfs 2>/dev/null; then
        log "rmmod failed — module in use (refcnt=$(cat /sys/module/antirevfs/refcnt 2>/dev/null))"
        log "antirevfs mounts still present in this namespace:"
        grep antirevfs /proc/mounts || log "  (none — likely a lazy-unmounted mount still held by a"
        log "   running process, or an antirevfs mount inside a container namespace)"
        log "processes whose mount namespace still references antirevfs:"
        grep -l antirevfs /proc/*/mountinfo 2>/dev/null || true
        die "stop the business stack (mmap'd .so files pin the module), then re-run"
    fi
fi
[ -d /sys/module/antirevfs ] && die "antirevfs still loaded after rmmod"
log "loading antirevfs (gate_enforce=$GATE_ENFORCE authz_path=$AUTHZ_PATH)"
insmod "$KO" gate_enforce="$GATE_ENFORCE" authz_path="$AUTHZ_PATH" || die "insmod failed"

# ---- unlock key (this session) -----------------------------------------------
log "unlocking AES key into session keyring"
"$KEYCTL_BIN" unlock --keyfile "$KEYFILE" || die "key unlock failed"

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
grep -E 'antirevfs|overlay' /proc/mounts | grep -E '/root/proj' || true
log "done — gate_enforce=$(cat /sys/module/antirevfs/parameters/gate_enforce 2>/dev/null)"
