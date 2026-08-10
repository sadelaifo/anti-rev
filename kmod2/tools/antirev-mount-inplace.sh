#!/usr/bin/env bash
#
# antirev-mount-inplace.sh — IN-PLACE antirevfs mounts + tmpfs write layers.
#
# Presents the business stack's bin/ and lib/ as DECRYPTED views at the SAME
# paths where the ciphertext lives.  No separate .enc/ tree, no .antirev-rw
# overlay, no 'dec' directory — nothing extra on disk to find.  Layout:
#
#     ext4  /root/proj/bin                  <- ciphertext at rest (hidden under mount)
#       '- antirevfs (ro)  /root/proj/bin   <- decrypted read-only view, IN PLACE
#            |- tmpfs /root/proj/bin/<dir>   <- app writes here (one per known write dir)
#            '- bind  /root/proj/bin/<file>  <- app writes here (one per stray file)
#
# Reads of encrypted .so/.elf decrypt through antirevfs; the app's runtime writes
# (lock/log/pid) land in ANONYMOUS tmpfs and NEVER touch the ciphertext.  Because
# the write layers are tmpfs (not an overlayfs upper), there is NO copy-up
# plaintext hazard and NO backing directory left on disk.
#
# antirevfs pins its lower tree by reference at mount time, which is what makes
# overmounting a directory onto itself safe (lookups are dentry-relative, never
# re-resolved by name, so there is no loop).  NOTE: in-place overmount (lower ==
# mountpoint) is not yet covered by a test in this repo — verify on your kernel
# (test_antirevfs_inplace_rw.sh) before relying on it in production.
#
# The set of writable paths is deployment-specific.  Bring the stack up with the
# WRITE_DIRS / WRITE_FILES arrays EMPTY, exercise the app, and watch for EROFS /
# "Read-only file system" (Error 30) — every such path is a write location.  Add
# it to the right array (dir vs stray file) and re-run 'up'.
#
# No key handling: each encrypted file embeds its own AES key in a trailer, read
# by the module at decrypt time.  Run as root; re-execs with sudo.
#
# Usage:
#   antirev-mount-inplace.sh up       # (default) reload module + mount everything
#   antirev-mount-inplace.sh down     # unmount everything (module left loaded)
#   antirev-mount-inplace.sh status   # show active mounts
#
# STEALTH (do this once the write paths are locked): run the WHOLE thing inside a
# persistent private mount namespace so the mounts are invisible in /proc/mounts
# of any normal shell, then launch the app inside that namespace:
#     touch /run/antirev.ns
#     unshare --mount=/run/antirev.ns --propagation private \
#         /path/to/antirev-mount-inplace.sh up      # module load is global; mounts land in the ns
#     nsenter --mount=/run/antirev.ns  /root/proj/bin/<launcher>
#     # teardown: nsenter --mount=/run/antirev.ns .../antirev-mount-inplace.sh down ; umount /run/antirev.ns
#
set -euo pipefail

##### ---- configuration: EDIT to match your deployment -------------------------
KMOD_DIR=/root/antirev/kmod2/module          # dir containing antirevfs.ko
KO="$KMOD_DIR/antirevfs.ko"

# In-place mounts: the ciphertext lives AT these paths; antirevfs mounts over
# them so the same paths show plaintext.  Add/remove trees as needed.
MOUNTS=(
    /root/proj/bin
    /root/proj/lib
)

GATE_ENFORCE=1                               # 1 = enforce allow-list, 0 = allow all
GATE_PASSTHROUGH=1                           # 1 = unauth read -> trailer-stripped cipher; 0 = -EACCES
AUTHZ_PATH=/etc/authorized_apps.txt
ANTIREVFS_OPTS="ro,passdata"                 # antirevfs mount options

# ---- writable locations (PLACEHOLDERS — fill in after testing) ----------------
# Directories the app writes into.  An anonymous tmpfs is stacked over each; the
# app then creates files/subdirs freely inside it.  The mountpoint dir is created
# in the lower (on-disk) tree first, so it exists in the antirevfs view.
# Format:  "<mount-root>|<relative-subdir>".  Leave commented until known.
WRITE_DIRS=(
    # "/root/proj/bin|logs"
    # "/root/proj/bin|some/module/run"
    # "/root/proj/lib|cache"
)

# Individual files the app writes DIRECTLY next to binaries (can't tmpfs a whole
# dir without hiding the binaries).  Each is bind-mounted from a tmpfs-backed
# source over a seeded placeholder.  PREFER redirecting these via the app's own
# config; use this only when you can't.
# Format:  "<mount-root>|<relative-file>".
WRITE_FILES=(
    # "/root/proj/bin|QtApplication.pid"
)

WRITE_BACKING=/run/antirev-write             # tmpfs source for per-file binds (NEVER /tmp)
TMPFS_OPTS="mode=0755,nosuid,nodev"
RELOAD_MODULE=1                              # 1 = rmmod+insmod on 'up'; 0 = use already-loaded module
##### ---------------------------------------------------------------------------

log() { printf '[inplace] %s\n' "$*"; }
die() { printf '[inplace] ERROR: %s\n' "$*" >&2; exit 1; }

# root: no keyring needed — keys are embedded per-file
if [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$@"; fi

ACTION="${1:-up}"

# ---- helpers -----------------------------------------------------------------

# print every mountpoint at or under $1, deepest first (for teardown ordering)
tree_mounts_desc() {
    awk -v r="$1" '$2==r || index($2, r"/")==1 {print $2}' /proc/mounts \
        | sort -r || true
}

# unmount everything under a tree (tmpfs/binds first, then the antirevfs base)
sweep_tree() {
    local mp
    for mp in $(tree_mounts_desc "$1"); do
        if mountpoint -q "$mp" 2>/dev/null; then
            log "umount $mp"
            umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null \
                || log "  (busy: $mp)"
        fi
    done
}

do_down() {
    local m
    for m in "${MOUNTS[@]}"; do sweep_tree "$m"; done
    if mountpoint -q "$WRITE_BACKING" 2>/dev/null; then
        log "umount $WRITE_BACKING"
        umount "$WRITE_BACKING" 2>/dev/null || umount -l "$WRITE_BACKING" 2>/dev/null || true
    fi
}

reload_module() {
    if [ -d /sys/module/antirevfs ]; then
        log "rmmod antirevfs"
        if ! rmmod antirevfs 2>/dev/null; then
            die "rmmod failed (refcnt=$(cat /sys/module/antirevfs/refcnt 2>/dev/null)); stop the app first (mmap'd .so pin the module)"
        fi
    fi
    log "insmod antirevfs (gate_enforce=$GATE_ENFORCE gate_passthrough_cipher=$GATE_PASSTHROUGH authz_path=$AUTHZ_PATH)"
    insmod "$KO" gate_enforce="$GATE_ENFORCE" \
        gate_passthrough_cipher="$GATE_PASSTHROUGH" \
        authz_path="$AUTHZ_PATH" \
        || die "insmod failed"
}

# ---- mount up ----------------------------------------------------------------
do_up() {
    local spec root rel tag

    # 1) Seed write-dir + write-file anchors in the LOWER (on-disk) tree BEFORE
    #    mounting antirevfs, so antirevfs presents them as mountpoints once it
    #    shadows the dir.  In-place => the lower dir IS the mount path and is
    #    still writable at this point (antirevfs not yet mounted).
    if [ ${#WRITE_DIRS[@]} -gt 0 ]; then
        for spec in "${WRITE_DIRS[@]}"; do
            root="${spec%%|*}"; rel="${spec#*|}"
            mkdir -p "$root/$rel"
        done
    fi
    if [ ${#WRITE_FILES[@]} -gt 0 ]; then
        for spec in "${WRITE_FILES[@]}"; do
            root="${spec%%|*}"; rel="${spec#*|}"
            mkdir -p "$(dirname "$root/$rel")"
            [ -e "$root/$rel" ] || : > "$root/$rel"
        done
    fi

    # 2) antirevfs, in place, over each tree
    modprobe antirevfs 2>/dev/null || true
    for root in "${MOUNTS[@]}"; do
        [ -d "$root" ] || die "mount point not a directory: $root"
        if mountpoint -q "$root" 2>/dev/null; then
            die "already mounted: $root (run '$0 down' first)"
        fi
        log "antirevfs $root -> $root  ($ANTIREVFS_OPTS)"
        mount -t antirevfs -o "$ANTIREVFS_OPTS" "$root" "$root" \
            || die "antirevfs mount failed: $root"
    done

    # 3) anonymous tmpfs over each known write directory
    if [ ${#WRITE_DIRS[@]} -gt 0 ]; then
        for spec in "${WRITE_DIRS[@]}"; do
            root="${spec%%|*}"; rel="${spec#*|}"
            log "tmpfs  $root/$rel"
            mount -t tmpfs -o "$TMPFS_OPTS" tmpfs "$root/$rel" \
                || die "tmpfs mount failed: $root/$rel"
        done
    fi

    # 4) per-file writable binds (tmpfs-backed source, capped placeholders)
    if [ ${#WRITE_FILES[@]} -gt 0 ]; then
        mkdir -p "$WRITE_BACKING"
        if ! mountpoint -q "$WRITE_BACKING" 2>/dev/null; then
            mount -t tmpfs -o "$TMPFS_OPTS" tmpfs "$WRITE_BACKING" \
                || die "write-backing tmpfs failed: $WRITE_BACKING"
        fi
        for spec in "${WRITE_FILES[@]}"; do
            root="${spec%%|*}"; rel="${spec#*|}"
            tag=$(printf '%s' "${root#/}/$rel" | tr '/' '_')
            : > "$WRITE_BACKING/$tag"
            log "bind   $WRITE_BACKING/$tag -> $root/$rel"
            mount --bind "$WRITE_BACKING/$tag" "$root/$rel" \
                || die "file bind failed: $root/$rel"
        done
    fi
}

show_status() {
    local m
    for m in "${MOUNTS[@]}"; do
        if mountpoint -q "$m" 2>/dev/null; then
            printf '[inplace] %-24s mounted\n' "$m"
            tree_mounts_desc "$m" | sort | sed 's/^/[inplace]     /'
        else
            printf '[inplace] %-24s not-mounted\n' "$m"
        fi
    done
}

# ---- dispatch ----------------------------------------------------------------
case "$ACTION" in
    up)
        [ -f "$KO" ] || die "module not found: $KO"
        log "tearing down any existing mounts"
        do_down
        if [ "$RELOAD_MODULE" = 1 ]; then reload_module; fi
        do_up
        log "up complete:"
        show_status
        ;;
    down)
        do_down
        log "down complete (module left loaded; 'rmmod antirevfs' to fully unload)"
        ;;
    status)
        show_status
        ;;
    *)
        die "usage: $0 {up|down|status}"
        ;;
esac
