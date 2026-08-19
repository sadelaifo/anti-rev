#!/usr/bin/env bash
#
# antirev-mount-inplace.sh — IN-PLACE antirevfs mounts + tmpfs write layers,
# in either of two deployment modes:
#
#   --mode real   (default)  mount directly on THIS host  -> real-mode host
#                            protection (the actual appliance / native box)
#   --mode sim               drive the mount INTO a running qemu-user "sim mode"
#                            slave container via `docker exec`  (ARM64-on-x86)
#
# Both modes present the business stack's bin/ and lib/ as DECRYPTED views at the
# SAME paths where the ciphertext lives.  No separate .enc/ tree, no .antirev-rw
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
# --- The two modes share ALL logic; only the EXECUTOR differs ------------------
# The antirevfs FS type is registered kernel-globally as soon as the .ko is
# insmod'd on the HOST, so the module is always loaded on the host (kernel is
# shared with every container).  In `sim` mode the mount/tmpfs/allow-list
# commands are then run inside the container's mount namespace via `docker exec`
# (legal because the sim container is --privileged => CAP_SYS_ADMIN); the
# decrypted plaintext exists ONLY inside that namespace.  In `real` mode the very
# same commands run locally.  This is what lets sim mode stay decoupled: flip
# --mode and nothing above the mount layer changes.
#
# ---------------------------------------------------------------------------
# sim mode context (why it can't be a host-side mount)
# ---------------------------------------------------------------------------
# The ARM64 slave software is baked into slave_img at /root/proj/{bin,lib} as
# ANTREV01 ciphertext and run on x86 via qemu-user-static (binfmt).  The business
# launcher does, UNCHANGED:
#     docker run --rm --privileged .../qemu-user-static /register --reset -p yes
#     docker run -d --privileged=true ... slave_img /usr/sbin/sshd -D
# There is NO -v volume, so there is no host path to mount over — the seam is
# `docker exec` into the running container.  Symptom if you skip this: SSH in,
# exec an encrypted binary -> the kernel reads raw ANTREV01 bytes -> no binfmt
# matches non-ELF magic -> "Exec format error" (ENOEXEC).  (A gate denial is
# -EACCES / "Permission denied" instead — different failure.)
#
# The set of writable paths is deployment-specific.  Bring the stack up with the
# WRITE_DIRS / WRITE_FILES arrays EMPTY, exercise the app, and watch for EROFS /
# "Read-only file system" (Error 30) — every such path is a write location.  Add
# it to the right array (dir vs stray file) and re-run 'up'.
#
# No key handling: each encrypted file embeds its own AES key in a trailer, read
# by the module at decrypt time.  Run as root; re-execs with sudo.
#
# The slave container name is a CONSTANT in the config block (CONTAINER=), not a
# CLI argument — set it once for your deployment.
#
# Usage:
#   antirev-mount-inplace.sh [--mode real|sim] up       # (default) ensure module + mount now (fails fast if the sim container is down)
#   antirev-mount-inplace.sh [--mode real|sim] watch    # DAEMON: idle-poll; mount when the container appears, re-mount on restart
#   antirev-mount-inplace.sh [--mode real|sim] down     # unmount everything (module left loaded)
#   antirev-mount-inplace.sh [--mode real|sim] status   # show active mounts
#
#   real: antirev-mount-inplace.sh up
#   sim : antirev-mount-inplace.sh --mode sim up        # (container must already be running)
#         AREV_MODE=sim ./antirev-mount-inplace.sh up
#
# --- Two deployment lifecycles, both supported --------------------------------
#   SHIP: OS + antirevfs pre-installed, machine shipped WITHOUT the container/
#         image; the client installs & boots the sim stack at an UNKNOWN LATER
#         TIME (days/weeks, across reboots).  The install script must NOT block:
#         it installs the unit and `systemctl enable --now`s it, then RETURNS.
#         The 'watch' DAEMON (systemd, backgrounded) does the waiting — it
#         idle-polls every WATCH_INTERVAL s, tolerates docker/the container being
#         absent indefinitely, and mounts the instant the container appears
#         (re-mounting on every restart).  real mode has no container, so its
#         ship service is a `oneshot` 'up' at boot, ordered before the app.
#   DEV : the container is already booted.  Run 'up' directly (one-shot), or
#         'watch' (mounts within one poll since it is already running).
#
#   The installer is non-blocking; only the daemon blocks — and that is fine, a
#   daemon is supposed to.  NEVER call 'watch' inline from the install script.
#
# systemd (sim ship — antirev-sim.service, see this dir):
#   [Unit]     After=docker.service   Wants=docker.service
#   [Service]  ExecStart=<path>/antirev-mount-inplace.sh --mode sim watch
#              Restart=always  RestartSec=5
#   [Install]  WantedBy=multi-user.target
# install script (returns immediately):
#   install -m0755 antirev-mount-inplace.sh /opt/antirev/ ; install -m0644 antirev-sim.service /etc/systemd/system/
#   systemctl daemon-reload ; systemctl enable --now antirev-sim.service   # <- non-blocking; the unit backgrounds
#
# systemd (real ship — antirev-real.service):
#   [Service]  Type=oneshot  RemainAfterExit=yes
#              ExecStart=<path>/antirev-mount-inplace.sh --mode real up
#   [Install]  WantedBy=multi-user.target   (+ Before=<business-app>.service)
#
# Bring-up order (sim, first time): GATE_ENFORCE=0 to prove decrypt+qemu, then
# discover write paths via EROFS, then GATE_ENFORCE=1 with basenames
# (qemu-aarch64-static + every slave exe).
#
# STEALTH (real mode; do this once the write paths are locked): run the WHOLE
# thing inside a persistent private mount namespace so the mounts are invisible in
# /proc/mounts of any normal shell, then launch the app inside that namespace:
#     touch /run/antirev.ns
#     unshare --mount=/run/antirev.ns --propagation private \
#         /path/to/antirev-mount-inplace.sh up      # module load is global; mounts land in the ns
#     nsenter --mount=/run/antirev.ns  /root/proj/bin/<launcher>
#     # teardown: nsenter --mount=/run/antirev.ns .../antirev-mount-inplace.sh down ; umount /run/antirev.ns
# (sim mode gets this isolation for free: the container already has its own ns.)
#
set -euo pipefail

# root first (insmod + docker both need it); -E keeps AREV_* overrides.
if [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$@"; fi

##### ---- configuration: EDIT to match your deployment -------------------------
KMOD_DIR=/root/antirev/kmod2/module          # dir containing antirevfs.ko
KO="${AREV_KO:-$KMOD_DIR/antirevfs.ko}"

# sim mode only: the FIXED name of the slave container (business `docker run
# --name <this>`).  A constant so no per-invocation input is needed; the
# AREV_CONTAINER env var can still override it for ad-hoc dev use.
CONTAINER="${AREV_CONTAINER:-slave}"         # <-- SET this to your container name
WATCH_INTERVAL="${AREV_WATCH_INTERVAL:-5}"   # 'watch' poll period (s); daemon idles here until the container appears

# In-place mounts: the ciphertext lives AT these paths; antirevfs mounts over
# them so the same paths show plaintext.  Add/remove trees as needed.
MOUNTS=(
    /root/proj/bin
    /root/proj/lib
)

GATE_ENFORCE="${AREV_GATE_ENFORCE:-1}"       # 1 = enforce allow-list, 0 = allow all
GATE_PASSTHROUGH=1                           # 1 = unauth read -> trailer-stripped cipher; 0 = -EACCES
AUTHZ_PATH=/etc/authorized_apps.txt          # resolved in the TARGET's mount ns (container's /etc in sim)
ANTIREVFS_OPTS="ro,passdata"                 # antirevfs mount options

# Overlay-lower staging (sim / Docker).  FIELD FACT: on SLES 12 SP5 (4.12.14)
# antirevfs cannot positioned-read an *overlayfs* lower — the offset-0 magic read
# sneaks through (plaintext files work) but the offset-(size-8) trailer read and
# the decrypt reads return -EIO, so every ENCRYPTED file fails with EIO through a
# mount whose lower is the Docker image layer (overlay2).  Workaround: copy the
# CIPHERTEXT (still encrypted — safe) onto a real fs (tmpfs) and mount antirevfs
# from THERE instead of in-place over the overlay.  On a real-fs lower (ext4,
# native appliance) staging is unnecessary, so 'auto' only stages when the lower
# is actually overlayfs.  Costs RAM = ciphertext size (fits the container's
# --shm-size tmpfs); point STAGE_DIR at a disk-backed dir if the tree is large.
STAGE_LOWER="${AREV_STAGE_LOWER:-auto}"      # auto = stage only when lower is overlayfs | always | never
STAGE_DIR="${AREV_STAGE_DIR:-/dev/shm/arev}" # real-fs (tmpfs) staging root IN THE TARGET

# Allow-list basenames written to the TARGET's $AUTHZ_PATH when GATE_ENFORCE=1.
# Match by BASENAME (paths differ under stacked/overlay mounts and per namespace).
# sim mode: include qemu-aarch64-static (lib/data reads gate on the EMULATOR's
# identity) plus every slave exe run transparently (its own exec-load is gated).
ALLOW=(
    # your_slave_exe
    # python3
    # qemu-aarch64-static      # sim mode only
)

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
RELOAD_MODULE="${AREV_RELOAD_MODULE:-0}"     # 1 = rmmod+insmod on 'up'; 0 = use already-loaded module
##### ---------------------------------------------------------------------------
# RELOAD_MODULE defaults to 0: on a shipped machine antirevfs is loaded once at
# boot and must NOT be churned on every container (re)start.  Set
# AREV_RELOAD_MODULE=1 while iterating on the .ko during development.

# ---- CLI parse (flag may precede or follow the action) -----------------------
MODE="${AREV_MODE:-real}"
ACTION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)               MODE="${2:-}"; shift 2 ;;
        --mode=*)             MODE="${1#*=}"; shift ;;
        up|down|status|watch) ACTION="$1"; shift ;;
        -h|--help)            grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                    echo "[inplace] ERROR: unknown arg: $1" >&2; exit 2 ;;
    esac
done
ACTION="${ACTION:-up}"

log() { printf '[inplace:%s] %s\n' "$MODE" "$*"; }
die() { printf '[inplace:%s] ERROR: %s\n' "$MODE" "$*" >&2; exit 1; }

case "$MODE" in
    real) ;;
    sim)
        [ -n "$CONTAINER" ] || die "sim mode needs a container name (set CONTAINER= in config or AREV_CONTAINER=)"
        # docker is REQUIRED for the one-shot actions, but 'watch' must tolerate
        # docker being installed later (client installs the sim stack whenever),
        # so it only warns and keeps polling.
        if [ "$ACTION" != watch ]; then
            command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
        fi
        ;;
    *) die "unknown --mode '$MODE' (use real|sim)" ;;
esac

# sim: is the slave container up right now?  real mode: always "yes" (it's local).
container_running() {
    [ "$MODE" = real ] && return 0
    docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx true
}

# ---- executor abstraction ----------------------------------------------------
# run_in_target CMD...      : run one command in the target (local | container)
# target_bash < script      : run a bash script in the target, forwarding the
#                             config env vars below (exported before each call).
FWD_VARS=(A_OPTS WRITE_BACKING TMPFS_OPTS MOUNTS_NL WDIRS_NL WFILES_NL STAGE_MODE STAGE_ROOT)

run_in_target() {
    if [ "$MODE" = sim ]; then docker exec -i "$CONTAINER" "$@"; else "$@"; fi
}
target_bash() {
    if [ "$MODE" = sim ]; then
        local eargs=() v
        for v in "${FWD_VARS[@]}"; do eargs+=(-e "$v"); done
        docker exec -i "${eargs[@]}" "$CONTAINER" bash -s
    else
        bash -s          # inherits exported FWD_VARS from this shell
    fi
}

# newline-join a (possibly empty) array without a stray trailing blank line
nl_join() { local a; for a in "$@"; do printf '%s\n' "$a"; done; }

# ---- host-side module management — IDENTICAL in both modes --------------------
# The module is loaded on the kernel that backs the mounts.  In sim mode the
# --privileged container SHARES the host kernel, so "load on the host" is the
# same kernel that serves the container's in-place mounts; in real mode this
# script runs on the slave machine and loads that machine's kernel.  Either way
# this is a local operation with no mode branch — real vs sim differs ONLY in
# where do_up/do_down/write_allowlist land (the executor), never here.
ensure_module() {
    if [ ! -d /sys/module/antirevfs ]; then
        [ -f "$KO" ] || die "module not loaded and .ko not found: $KO (set AREV_KO=)"
        log "insmod antirevfs (gate_enforce=$GATE_ENFORCE gate_passthrough_cipher=$GATE_PASSTHROUGH authz_path=$AUTHZ_PATH)"
        insmod "$KO" gate_enforce="$GATE_ENFORCE" \
            gate_passthrough_cipher="$GATE_PASSTHROUGH" \
            authz_path="$AUTHZ_PATH" || die "insmod failed"
        return
    fi
    if [ "$RELOAD_MODULE" = 1 ]; then
        log "rmmod antirevfs (reload)"
        if ! rmmod antirevfs 2>/dev/null; then
            die "rmmod failed (refcnt=$(cat /sys/module/antirevfs/refcnt 2>/dev/null)); run 'down' + stop the app first (mmap'd .so / live mounts pin the module)"
        fi
        [ -f "$KO" ] || die ".ko not found for reload: $KO"
        log "insmod antirevfs"
        insmod "$KO" gate_enforce="$GATE_ENFORCE" \
            gate_passthrough_cipher="$GATE_PASSTHROUGH" \
            authz_path="$AUTHZ_PATH" || die "insmod failed"
        return
    fi
    # keep loaded module; sync runtime-writable gate params
    log "antirevfs already loaded; syncing runtime-writable gate params"
    echo "$GATE_ENFORCE"     > /sys/module/antirevfs/parameters/gate_enforce 2>/dev/null || true
    echo "$GATE_PASSTHROUGH" > /sys/module/antirevfs/parameters/gate_passthrough_cipher 2>/dev/null || true
    local cur; cur="$(cat /sys/module/antirevfs/parameters/authz_path 2>/dev/null || echo '?')"
    [ "$cur" = "$AUTHZ_PATH" ] || log "note: loaded authz_path='$cur' (not runtime-writable); rmmod+reload to change"
}

# ---- target: gate allow-list -------------------------------------------------
write_allowlist() {
    [ "$GATE_ENFORCE" = 1 ] || { log "gate off; skipping allow-list"; return 0; }
    if [ "${#ALLOW[@]}" -eq 0 ]; then
        log "WARNING: GATE_ENFORCE=1 but ALLOW[] is empty -> everything will be denied"
    fi
    log "writing $AUTHZ_PATH ($( (IFS=,; echo "${ALLOW[*]:-}") ))"
    nl_join "${ALLOW[@]:-}" | run_in_target sh -c "cat > '$AUTHZ_PATH' && chmod 0644 '$AUTHZ_PATH'" \
        || die "could not write allow-list"
}

# ---- target: mount up --------------------------------------------------------
do_up() {
    export A_OPTS="$ANTIREVFS_OPTS" WRITE_BACKING TMPFS_OPTS
    export STAGE_MODE="$STAGE_LOWER" STAGE_ROOT="$STAGE_DIR"
    export MOUNTS_NL="$(nl_join "${MOUNTS[@]}")"
    export WDIRS_NL="$(nl_join "${WRITE_DIRS[@]:-}")"
    export WFILES_NL="$(nl_join "${WRITE_FILES[@]:-}")"
    target_bash <<'TARGET_UP'
set -euo pipefail
cerr() { printf '  [target] %s\n' "$*" >&2; }
readarray -t MOUNTS < <(printf '%s\n' "$MOUNTS_NL" | sed '/^$/d')
readarray -t WDIRS  < <(printf '%s\n' "$WDIRS_NL"  | sed '/^$/d')
readarray -t WFILES < <(printf '%s\n' "$WFILES_NL" | sed '/^$/d')

modprobe antirevfs 2>/dev/null || true   # no-op if already loaded on host

# 0) decide the LOWER for each mount.  Normally in-place (lower == mountpoint),
#    but if the mountpoint's fs is overlayfs (Docker image layer) antirevfs
#    cannot positioned-read it on SLES 4.12 -> stage the CIPHERTEXT onto a
#    real-fs (tmpfs) and mount from there.  Staging reads the raw ciphertext, so
#    it MUST happen before antirevfs is mounted over the path (guaranteed here:
#    'up' runs after 'down').  LOWERS[] is index-matched to MOUNTS[].
LOWERS=()
for root in "${MOUNTS[@]}"; do
    [ -d "$root" ] || { cerr "not a directory: $root"; exit 1; }
    if mountpoint -q "$root"; then cerr "already mounted: $root (run 'down' first)"; exit 1; fi
    stage=no
    case "$STAGE_MODE" in
        always) stage=yes ;;
        never)  stage=no ;;
        *)      [ "$(stat -f -c %T "$root" 2>/dev/null)" = overlayfs ] && stage=yes ;;
    esac
    if [ "$stage" = yes ]; then
        tag="$(printf '%s' "${root#/}" | tr '/' '_')"
        lower="$STAGE_ROOT/$tag"
        rm -rf "$lower"; mkdir -p "$lower"
        cerr "stage (overlay lower) $root -> $lower  [$(du -sh "$root" 2>/dev/null | cut -f1)]"
        cp -a "$root/." "$lower/" || { cerr "stage copy failed: $root"; exit 1; }
    else
        lower="$root"
    fi
    LOWERS+=("$lower")
done
# lower_for <root>: echo the LOWER chosen for a mount root (in-place or staged)
lower_for() { local i=0 r; for r in "${MOUNTS[@]}"; do
    [ "$r" = "$1" ] && { printf '%s' "${LOWERS[$i]}"; return; }; i=$((i+1)); done
    printf '%s' "$1"; }

# 1) seed write anchors in the LOWER (staged copy or in-place dir) before mount.
for spec in "${WDIRS[@]:-}"; do
    [ -n "$spec" ] || continue
    root="${spec%%|*}"; rel="${spec#*|}"; mkdir -p "$(lower_for "$root")/$rel"
done
for spec in "${WFILES[@]:-}"; do
    [ -n "$spec" ] || continue
    root="${spec%%|*}"; rel="${spec#*|}"; L="$(lower_for "$root")"
    mkdir -p "$(dirname "$L/$rel")"; [ -e "$L/$rel" ] || : > "$L/$rel"
done

# 2) antirevfs: lower (staged or in-place) -> mountpoint
i=0
for root in "${MOUNTS[@]}"; do
    lower="${LOWERS[$i]}"; i=$((i+1))
    cerr "antirevfs $lower -> $root ($A_OPTS)"
    mount -t antirevfs -o "$A_OPTS" "$lower" "$root" || { cerr "mount failed: $root"; exit 1; }
done

# 3) anonymous tmpfs over each known write directory
for spec in "${WDIRS[@]:-}"; do
    [ -n "$spec" ] || continue
    root="${spec%%|*}"; rel="${spec#*|}"
    cerr "tmpfs  $root/$rel"
    mount -t tmpfs -o "$TMPFS_OPTS" tmpfs "$root/$rel" || { cerr "tmpfs failed: $root/$rel"; exit 1; }
done

# 4) per-file writable binds (tmpfs-backed source, capped placeholders)
if [ "${#WFILES[@]}" -gt 0 ] && [ -n "${WFILES[0]:-}" ]; then
    mkdir -p "$WRITE_BACKING"
    mountpoint -q "$WRITE_BACKING" || mount -t tmpfs -o "$TMPFS_OPTS" tmpfs "$WRITE_BACKING"
    for spec in "${WFILES[@]}"; do
        [ -n "$spec" ] || continue
        root="${spec%%|*}"; rel="${spec#*|}"
        tag="$(printf '%s' "${root#/}/$rel" | tr '/' '_')"
        : > "$WRITE_BACKING/$tag"
        cerr "bind   $WRITE_BACKING/$tag -> $root/$rel"
        mount --bind "$WRITE_BACKING/$tag" "$root/$rel" || { cerr "bind failed: $root/$rel"; exit 1; }
    done
fi
cerr "up complete"
TARGET_UP
}

# ---- target: tear down (deepest-first: tmpfs/binds, then antirevfs base) ------
do_down() {
    export WRITE_BACKING STAGE_ROOT="$STAGE_DIR"
    export MOUNTS_NL="$(nl_join "${MOUNTS[@]}")"
    target_bash <<'TARGET_DOWN'
set -uo pipefail
readarray -t MOUNTS < <(printf '%s\n' "$MOUNTS_NL" | sed '/^$/d')
for r in "${MOUNTS[@]}"; do
    for mp in $(awk -v r="$r" '$2==r || index($2, r"/")==1 {print $2}' /proc/mounts | sort -r); do
        if mountpoint -q "$mp"; then
            # umount -l is expected here: a global LD_PRELOAD lib served from the
            # mount is mmap'd into every process, so a plain umount is always busy.
            umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || printf '  [target] busy: %s\n' "$mp" >&2
        fi
    done
done
if [ -d "$WRITE_BACKING" ] && mountpoint -q "$WRITE_BACKING"; then
    umount "$WRITE_BACKING" 2>/dev/null || umount -l "$WRITE_BACKING" 2>/dev/null || true
fi
# reclaim staged ciphertext copies (tmpfs RAM) once their mounts are gone
[ -n "${STAGE_ROOT:-}" ] && [ -d "$STAGE_ROOT" ] && rm -rf "$STAGE_ROOT"/* 2>/dev/null || true
printf '  [target] down complete\n' >&2
TARGET_DOWN
}

# ---- target: status ----------------------------------------------------------
do_status() {
    export MOUNTS_NL="$(nl_join "${MOUNTS[@]}")"
    target_bash <<'TARGET_STATUS'
set -uo pipefail
readarray -t MOUNTS < <(printf '%s\n' "$MOUNTS_NL" | sed '/^$/d')
for m in "${MOUNTS[@]}"; do
    if mountpoint -q "$m"; then
        printf '  %-22s mounted\n' "$m"
        awk -v r="$m" '$2==r || index($2, r"/")==1 {printf "      %s (%s)\n",$2,$3}' /proc/mounts | sort
    else
        printf '  %-22s not-mounted\n' "$m"
    fi
done
TARGET_STATUS
}

# ---- the full up sequence (shared by 'up' and 'watch') -----------------------
run_up_sequence() {
    log "tearing down any existing mounts"
    do_down                 # before reload: live mounts pin the module
    ensure_module           # host-side, identical in both modes
    write_allowlist
    do_up
    log "up complete."
    [ "$MODE" = sim ] && log "SSH into '$CONTAINER' and run the target binary from ${MOUNTS[0]}."
    log "watch for EROFS/'Read-only file system' -> add those paths to WRITE_DIRS/WRITE_FILES and re-run 'up'."
    do_status
}

# ---- watch: SHIP case — container boots AFTER us (or restarts) ----------------
# A long-lived DAEMON, meant to run as a backgrounded systemd service — NOT to be
# called inline from an install script (which must never block).  It idle-polls
# (edge-triggered on the down->up transition) and mounts when the container
# appears, re-mounting on every restart.  Deliberately race-free and
# docker-optional: it tolerates docker/the daemon/the container all being absent
# for an arbitrarily long time (the client may install the sim stack weeks after
# the OS ships) and simply keeps polling until they exist.  In real mode there is
# no container, so it degrades to a single 'up'.
do_watch() {
    if [ "$MODE" = real ]; then
        log "real mode: nothing to watch; running 'up' once"
        run_up_sequence
        return
    fi
    log "watch: polling for container '$CONTAINER' every ${WATCH_INTERVAL}s (backgrounded daemon; idle until it appears)"
    command -v docker >/dev/null 2>&1 || log "docker not present yet; will keep polling until it (and the container) are installed"
    local prev=down
    while :; do
        if container_running; then
            if [ "$prev" = down ]; then
                log "container '$CONTAINER' is up -> mounting"
                if run_up_sequence; then prev=up; else log "up failed; retrying next tick"; fi
            fi
        else
            prev=down
        fi
        sleep "$WATCH_INTERVAL"
    done
}

# ---- dispatch ----------------------------------------------------------------
case "$ACTION" in
    up)
        container_running || die "container '$CONTAINER' not running. Boot it (business launcher) then re-run 'up', or use 'watch' to auto-mount on start."
        run_up_sequence
        ;;
    watch)
        do_watch
        ;;
    down)
        if ! container_running; then
            log "container '$CONTAINER' not running; its mounts vanished with it — nothing to do"
            exit 0
        fi
        do_down
        log "down complete (module left loaded; 'rmmod antirevfs' to fully unload)"
        ;;
    status)
        if ! container_running; then log "container '$CONTAINER' not running"; exit 0; fi
        do_status
        ;;
    *)
        die "usage: $0 [--mode real|sim] {up|down|status|watch}"
        ;;
esac
