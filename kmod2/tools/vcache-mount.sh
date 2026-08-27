#!/usr/bin/env bash
#
# vcache-mount.sh — IN-PLACE vcachefs mounts + tmpfs write layers.
#
# A mode expands to a LIST of mount targets (the host is always one of them):
#
#   --mode real   (default)  HOST only.  Mounts the host's own /root/SW in place.
#                            (The real deployment's ARM64 slave is a separate
#                            machine — handled separately, later.)
#   --mode sim               HOST + CONTAINER.  Mounts the host's /root/SW AND,
#                            via `docker exec`, the slave software inside the
#                            qemu-user "sim mode" Docker container — the whole
#                            simulation box in one command.  (Run this ON THE
#                            HOST; it reaches into the container for you.)
#
# So one invocation can bring up both installs; the container half is skipped
# with a note if the container isn't running.
#
# Both modes present the business stack's bin/ and lib/ as DECRYPTED views at the
# SAME paths where the ciphertext lives.  No separate .enc/ tree, no .vcache-rw
# overlay, no 'dec' directory — nothing extra on disk to find.  Layout:
#
#     ext4  /root/proj/bin                  <- ciphertext at rest (hidden under mount)
#       '- vcachefs (ro)  /root/proj/bin   <- decrypted read-only view, IN PLACE
#            |- tmpfs /root/proj/bin/<dir>   <- app writes here (one per known write dir)
#            '- bind  /root/proj/bin/<file>  <- app writes here (one per stray file)
#
# Reads of encrypted .so/.elf decrypt through vcachefs; the app's runtime writes
# (lock/log/pid) land in ANONYMOUS tmpfs and NEVER touch the ciphertext.  Because
# the write layers are tmpfs (not an overlayfs upper), there is NO copy-up
# plaintext hazard and NO backing directory left on disk.
#
# vcachefs pins its lower tree by reference at mount time, which is what makes
# overmounting a directory onto itself safe (lookups are dentry-relative, never
# re-resolved by name, so there is no loop).  NOTE: in-place overmount (lower ==
# mountpoint) is not yet covered by a test in this repo — verify on your kernel
# (test_vcachefs_inplace_rw.sh) before relying on it in production.
#
# --- The two modes share ALL logic; only the EXECUTOR differs ------------------
# The vcachefs FS type is registered kernel-globally as soon as the .ko is
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
# Usage (run ON THE HOST in every case):
#   vcache-mount.sh [--mode real|sim] up       # (default) mount all targets now
#   vcache-mount.sh [--mode real|sim] watch    # DAEMON: mount host now; (sim) poll + mount the container when it appears
#   vcache-mount.sh [--mode real|sim] down     # unmount all targets (module left loaded)
#   vcache-mount.sh [--mode real|sim] status   # show active mounts per target
#
#   real: vcache-mount.sh up                   # host only
#   sim : vcache-mount.sh --mode sim up        # host + container (container skipped if not running)
#         AREV_MODE=sim ./vcache-mount.sh up
#
# --- Two deployment lifecycles, both supported --------------------------------
#   SHIP: OS + vcachefs pre-installed, machine shipped WITHOUT the container/
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
# systemd (sim ship — vcache-watch.service, see this dir):
#   [Unit]     After=docker.service   Wants=docker.service
#   [Service]  ExecStart=<path>/vcache-mount.sh --mode sim watch
#              Restart=always  RestartSec=5
#   [Install]  WantedBy=multi-user.target
# install script (returns immediately):
#   install -m0755 vcache-mount.sh /opt/vcache/ ; install -m0644 vcache-watch.service /etc/systemd/system/
#   systemctl daemon-reload ; systemctl enable --now vcache-watch.service   # <- non-blocking; the unit backgrounds
#
# systemd (real ship — vcache-mount.service):
#   [Service]  Type=oneshot  RemainAfterExit=yes
#              ExecStart=<path>/vcache-mount.sh --mode real up
#   [Install]  WantedBy=multi-user.target   (+ Before=<business-app>.service)
#
# Bring-up order (sim, first time): GATE_ENFORCE=0 to prove decrypt+qemu, then
# discover write paths via EROFS, then GATE_ENFORCE=1 with basenames
# (qemu-aarch64-static + every slave exe).
#
# STEALTH (real mode; do this once the write paths are locked): run the WHOLE
# thing inside a persistent private mount namespace so the mounts are invisible in
# /proc/mounts of any normal shell, then launch the app inside that namespace:
#     touch /run/vcache.ns
#     unshare --mount=/run/vcache.ns --propagation private \
#         /path/to/vcache-mount.sh up      # module load is global; mounts land in the ns
#     nsenter --mount=/run/vcache.ns  /root/proj/bin/<launcher>
#     # teardown: nsenter --mount=/run/vcache.ns .../vcache-mount.sh down ; umount /run/vcache.ns
# (sim mode gets this isolation for free: the container already has its own ns.)
#
set -euo pipefail

# root first (insmod + docker both need it); -E keeps AREV_* overrides.
if [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$@"; fi

##### ---- configuration: EDIT to match your deployment -------------------------
KMOD_DIR=/root/vcache/kmod2/module          # dir containing vcachefs.ko
KO="${AREV_KO:-$KMOD_DIR/vcachefs.ko}"

# sim mode only: the FIXED name of the slave container (business `docker run
# --name <this>`).  A constant so no per-invocation input is needed; the
# AREV_CONTAINER env var can still override it for ad-hoc dev use.
CONTAINER="${AREV_CONTAINER:-slave}"         # <-- SET this to your container name
WATCH_INTERVAL="${AREV_WATCH_INTERVAL:-5}"   # 'watch' poll period (s); daemon idles here until the container appears
# Readiness gate: an in-place mount is read-only and SHADOWS its directory, so
# all ciphertext must be present BEFORE we mount — otherwise the mount freezes an
# empty/partial tree and the installer's copy into bin/ lib/ gets EROFS.  We
# therefore refuse to mount a target until its mount roots are non-empty, and
# (if set) until READY_MARKER exists in the target.  Set AREV_READY_MARKER to a
# path the installer `touch`es as the LAST step after copying SW in — that makes
# the gate exact (a marker can't appear mid-copy the way a non-empty dir can).
READY_MARKER="${AREV_READY_MARKER:-}"        # e.g. /root/SW/.arev-ready (empty = non-empty-dir heuristic only)

# In-place mounts: the ciphertext lives AT these paths; vcachefs mounts over
# them so the same paths show plaintext.  Add/remove trees as needed.
MOUNTS=(
    /root/proj/bin
    /root/proj/lib
)

GATE_ENFORCE="${AREV_GATE_ENFORCE:-1}"       # 1 = enforce allow-list, 0 = allow all
GATE_PASSTHROUGH=1                           # 1 = unauth read -> trailer-stripped cipher; 0 = -EACCES
# DEV_MODE: does the .ko you load expose the dev-only params (gate_enforce toggle,
# authz_path allow-list)?  A PRODUCTION vcachefs.ko (built without AREV_DEV_MODE)
# gates unconditionally and has NO such params — passing them to insmod would
# fail.  0 (default) = production: insmod only gate_passthrough_cipher, no
# allow-list.  1 = dev .ko (built AREV_DEV_MODE=1): full param set + allow-list.
DEV_MODE="${AREV_DEV:-0}"
AUTHZ_PATH=/etc/authorized_apps.txt          # resolved in the TARGET's mount ns (container's /etc in sim)
# Signed allow-list (tamper-proof).  1 => the list is trusted only if its detached
# PKCS#7 signature (AUTHZ_SIG_PATH) verifies against the vendor key embedded in
# the .ko (module/gate_authz_pubkey.h).  In signed mode the tool does NOT write
# the list — you ship a pre-signed list + .p7s (produced by tools/authz-sign.sh
# at CI/vendor); the tool only checks they are present and flips the module param.
GATE_REQUIRE_SIG="${AREV_GATE_REQUIRE_SIG:-0}"   # 1 = require a valid signature on the list
AUTHZ_SIG_PATH="${AREV_AUTHZ_SIG_PATH:-$AUTHZ_PATH.p7s}"  # detached PKCS#7 (DER)
VCACHEFS_OPTS="ro,passdata"                 # vcachefs mount options

# Overlay-lower staging (sim / Docker).  FIELD FACT: on SLES 12 SP5 (4.12.14)
# vcachefs cannot positioned-read an *overlayfs* lower — the offset-0 magic read
# sneaks through (plaintext files work) but the offset-(size-8) trailer read and
# the decrypt reads return -EIO, so every ENCRYPTED file fails with EIO through a
# mount whose lower is the Docker image layer (overlay2).  Workaround: copy the
# CIPHERTEXT (still encrypted — safe) onto a real fs (tmpfs) and mount vcachefs
# from THERE instead of in-place over the overlay.  On a real-fs lower (ext4,
# native appliance) staging is unnecessary, so 'auto' only stages when the lower
# is actually overlayfs.  Costs RAM = ciphertext size (fits the container's
# --shm-size tmpfs); point STAGE_DIR at a disk-backed dir if the tree is large.
STAGE_LOWER="${AREV_STAGE_LOWER:-auto}"      # auto = stage only when lower is overlayfs | always | never
STAGE_DIR="${AREV_STAGE_DIR:-/dev/shm/arev}" # real-fs (tmpfs) staging root IN THE TARGET

# Legacy allow-list basenames, written to the TARGET's $AUTHZ_PATH when
# GATE_ENFORCE=1 and this array is NON-empty.  Match by BASENAME (paths differ
# under stacked/overlay mounts and per namespace).
#
# PER-EXE / WHITELIST MODEL (recommended): LEAVE THIS EMPTY.  Authorization then
# comes from per-exe signatures (signed by the vendor, verified against the key
# embedded in the .ko) + the .ko's compiled whitelist (module/gate_whitelist.h,
# e.g. qemu-aarch64-static / python3 / java).  With ALLOW[] empty the tool
# REMOVES any stale $AUTHZ_PATH on every `up`, so a leftover list can't silently
# re-authorize readers (busybox applets, cp, objdump).  Do NOT list interpreters
# here in this model — put them in gate_whitelist.h and rebuild the .ko instead.
#
# Only populate this array for the LEGACY plaintext-list model (no signatures).
ALLOW=(
    # your_slave_exe          # legacy model only — prefer per-exe signatures
)

# ---- writable locations (PLACEHOLDERS — fill in after testing) ----------------
# Directories the app writes into.  An anonymous tmpfs is stacked over each; the
# app then creates files/subdirs freely inside it.  The mountpoint dir is created
# in the lower (on-disk) tree first, so it exists in the vcachefs view.
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

WRITE_BACKING=/run/vcache-write             # tmpfs source for per-file binds (NEVER /tmp)
TMPFS_OPTS="mode=0755,nosuid,nodev"
RELOAD_MODULE="${AREV_RELOAD_MODULE:-0}"     # 1 = rmmod+insmod on 'up'; 0 = use already-loaded module
##### ---------------------------------------------------------------------------
# RELOAD_MODULE defaults to 0: on a shipped machine vcachefs is loaded once at
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

# Modes expand to a list of mount targets:
#   real -> host only            (native appliance; the real ARM64 slave is a
#                                 separate machine, handled separately later)
#   sim  -> host AND container   (the whole simulation box: the host's own
#                                 software + the slave software in the Docker
#                                 container on the same host)
case "$MODE" in
    real) TARGETS=(host) ;;
    sim)
        TARGETS=(host container)
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

# Is the slave container up right now?  (Only meaningful for the container target.)
container_running() {
    docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx true
}

# Is the current $TARGET available to operate on?  host: always; container: only
# when it is running.
target_present() {
    [ "$TARGET" = container ] || return 0
    container_running
}

# Is the target's ciphertext fully in place, so it is safe to mount over it?
# Every mount root must exist and be non-empty; if READY_MARKER is set it must
# also exist.  Runs in the current TARGET (host = local, container = docker exec).
target_ready() {
    local m
    for m in "${MOUNTS[@]}"; do
        run_in_target sh -c "[ -d '$m' ] && [ -n \"\$(ls -A '$m' 2>/dev/null)\" ]" \
            || return 1
    done
    if [ -n "$READY_MARKER" ]; then
        run_in_target sh -c "[ -e '$READY_MARKER' ]" || return 1
    fi
    return 0
}

# ---- executor abstraction ----------------------------------------------------
# run_in_target CMD...      : run one command in the target (local | container)
# target_bash < script      : run a bash script in the target, forwarding the
#                             config env vars below (exported before each call).
FWD_VARS=(A_OPTS WRITE_BACKING TMPFS_OPTS MOUNTS_NL WDIRS_NL WFILES_NL STAGE_MODE STAGE_ROOT)

# The current mount target — "host" (run locally) or "container" (via docker
# exec).  Set by the target loop in run_up_sequence/do_down_all/etc.  --mode real
# operates on the host only; --mode sim operates on BOTH host and container.
TARGET=host

run_in_target() {
    if [ "$TARGET" = container ]; then docker exec -i "$CONTAINER" "$@"; else "$@"; fi
}
target_bash() {
    if [ "$TARGET" = container ]; then
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
# insmod parameters differ by build: a PRODUCTION vcachefs.ko exposes only
# gate_passthrough_cipher (it always enforces and has no allow-list); a DEV .ko
# also takes the gate_enforce toggle + allow-list paths.  Word-split on purpose.
gate_insmod_params() {
    if [ "$DEV_MODE" = 1 ]; then
        printf '%s' "gate_enforce=$GATE_ENFORCE gate_require_sig=$GATE_REQUIRE_SIG gate_passthrough_cipher=$GATE_PASSTHROUGH authz_path=$AUTHZ_PATH authz_sig_path=$AUTHZ_SIG_PATH"
    else
        printf '%s' "gate_passthrough_cipher=$GATE_PASSTHROUGH"
    fi
}
gate_mode_label() { [ "$DEV_MODE" = 1 ] && echo "DEV" || echo "production"; }

ensure_module() {
    if [ ! -d /sys/module/vcachefs ]; then
        [ -f "$KO" ] || die "module not loaded and .ko not found: $KO (set AREV_KO=)"
        log "insmod vcachefs [$(gate_mode_label)] ($(gate_insmod_params))"
        insmod "$KO" $(gate_insmod_params) || die "insmod failed"
        return
    fi
    if [ "$RELOAD_MODULE" = 1 ]; then
        log "rmmod vcachefs (reload)"
        if ! rmmod vcachefs 2>/dev/null; then
            die "rmmod failed (refcnt=$(cat /sys/module/vcachefs/refcnt 2>/dev/null)); run 'down' + stop the app first (mmap'd .so / live mounts pin the module)"
        fi
        [ -f "$KO" ] || die ".ko not found for reload: $KO"
        log "insmod vcachefs [$(gate_mode_label)]"
        insmod "$KO" $(gate_insmod_params) || die "insmod failed"
        return
    fi
    # keep loaded module; sync runtime-writable gate params (dev .ko only —
    # production has no gate_enforce/authz_path params, so skip those writes).
    log "vcachefs already loaded; syncing runtime-writable gate params [$(gate_mode_label)]"
    echo "$GATE_PASSTHROUGH" > /sys/module/vcachefs/parameters/gate_passthrough_cipher 2>/dev/null || true
    if [ "$DEV_MODE" = 1 ]; then
        echo "$GATE_ENFORCE"     > /sys/module/vcachefs/parameters/gate_enforce 2>/dev/null || true
        echo "$GATE_REQUIRE_SIG" > /sys/module/vcachefs/parameters/gate_require_sig 2>/dev/null || true
        local cur; cur="$(cat /sys/module/vcachefs/parameters/authz_path 2>/dev/null || echo '?')"
        [ "$cur" = "$AUTHZ_PATH" ] || log "note: loaded authz_path='$cur' (not runtime-writable); rmmod+reload to change"
    fi
}

# ---- target: gate allow-list -------------------------------------------------
write_allowlist() {
    # Production .ko has no allow-list mechanism at all — authorization is purely
    # per-exe signature + compiled whitelist.  Nothing to write; make sure no
    # stale list lingers (a dev .ko would honor it) and return.
    if [ "$DEV_MODE" != 1 ]; then
        run_in_target sh -c "rm -f '$AUTHZ_PATH' '$AUTHZ_PATH.p7s'" 2>/dev/null || true
        return 0
    fi
    [ "$GATE_ENFORCE" = 1 ] || { log "gate off; skipping allow-list"; return 0; }
    # Signed mode: the list + its .p7s are produced at CI/vendor (with the private
    # key) and shipped; the tool must NOT overwrite them (that would invalidate
    # the signature).  Just confirm both are present in the target.
    if [ "$GATE_REQUIRE_SIG" = 1 ]; then
        if run_in_target sh -c "[ -r '$AUTHZ_PATH' ] && [ -r '$AUTHZ_SIG_PATH' ]"; then
            log "signed mode: using pre-signed $AUTHZ_PATH (+ $AUTHZ_SIG_PATH) — not overwriting"
        else
            log "WARNING: signed mode but $AUTHZ_PATH and/or $AUTHZ_SIG_PATH missing/unreadable in target -> gate will DENY. Deploy the signed list + .p7s (tools/authz-sign.sh)."
        fi
        return 0
    fi
    if [ "${#ALLOW[@]}" -eq 0 ]; then
        # Per-exe signature + compiled-whitelist model: the legacy allow-list is
        # unused.  REMOVE any stale list in the target rather than leaving one
        # around — a present, content-ful /etc/authorized_apps.txt authorizes its
        # entries via the fallback and would silently re-grant plaintext access
        # (the exact "delete it before mounting" gotcha).  Authorization then
        # comes only from per-exe signatures + the .ko's compiled whitelist.
        log "ALLOW[] empty -> per-exe/whitelist gating; removing any stale $AUTHZ_PATH"
        run_in_target sh -c "rm -f '$AUTHZ_PATH' '$AUTHZ_PATH.p7s'" || true
        return 0
    fi
    log "writing $AUTHZ_PATH ($( (IFS=,; echo "${ALLOW[*]:-}") ))"
    nl_join "${ALLOW[@]:-}" | run_in_target sh -c "cat > '$AUTHZ_PATH' && chmod 0644 '$AUTHZ_PATH'" \
        || die "could not write allow-list"
}

# ---- target: mount up --------------------------------------------------------
do_up() {
    export A_OPTS="$VCACHEFS_OPTS" WRITE_BACKING TMPFS_OPTS
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

modprobe vcachefs 2>/dev/null || true   # no-op if already loaded on host

# 0) decide the LOWER for each mount.  Normally in-place (lower == mountpoint),
#    but if the mountpoint's fs is overlayfs (Docker image layer) vcachefs
#    cannot positioned-read it on SLES 4.12 -> stage the CIPHERTEXT onto a
#    real-fs (tmpfs) and mount from there.  Staging reads the raw ciphertext, so
#    it MUST happen before vcachefs is mounted over the path (guaranteed here:
#    'up' runs after 'down').  LOWERS[] is index-matched to MOUNTS[].
LOWERS=()
for root in "${MOUNTS[@]}"; do
    [ -d "$root" ] || { cerr "not a directory: $root"; exit 1; }
    if mountpoint -q "$root"; then cerr "already mounted: $root (run 'down' first)"; exit 1; fi
    stage=no
    case "$STAGE_MODE" in
        always) stage=yes ;;
        never)  stage=no ;;
        *)      # auto: stage iff the fs backing $root is overlay.  Detect via
                # /proc/self/mountinfo (kernel-reported fstype after the " - "
                # separator, longest-prefix mount) — robust where `stat -f -c %T`
                # returns "UNKNOWN" (busybox / qemu-emulated coreutils in the
                # container don't know the overlay magic).  stat is a fallback.
                ft="$(awk -v p="$root" '
                    { mp=$5; sep=0; ftype=""
                      for (i=6;i<=NF;i++) if ($i=="-") { sep=i; ftype=$(i+1); break }
                      if (sep && (mp==p || substr(p,1,length(mp)+1)==mp"/" || mp=="/"))
                          if (length(mp) >= best) { best=length(mp); res=ftype } }
                    END { print res }' /proc/self/mountinfo 2>/dev/null)"
                case "$ft" in
                    overlay|overlayfs) stage=yes ;;
                    "") [ "$(stat -f -c %T "$root" 2>/dev/null)" = overlayfs ] && stage=yes ;;
                esac ;;
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

# 2) vcachefs: lower (staged or in-place) -> mountpoint
i=0
for root in "${MOUNTS[@]}"; do
    lower="${LOWERS[$i]}"; i=$((i+1))
    cerr "vcachefs $lower -> $root ($A_OPTS)"
    mount -t vcachefs -o "$A_OPTS" "$lower" "$root" || { cerr "mount failed: $root"; exit 1; }
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

# ---- target: tear down (deepest-first: tmpfs/binds, then vcachefs base) ------
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
# Bring up every target for this mode.  Host is always mounted; the container is
# mounted too under --mode sim (skipped with a note if it isn't running).
run_up_sequence() {
    # 1) tear every present target down first (live mounts pin the module).
    for TARGET in "${TARGETS[@]}"; do
        target_present || continue
        log "[$TARGET] tearing down any existing mounts"
        do_down
    done
    # 2) module load/reload — host-side, once, after teardown.
    ensure_module
    # 3) mount every present target.
    for TARGET in "${TARGETS[@]}"; do
        if ! target_present; then
            log "[$TARGET] container '$CONTAINER' not running -> skipped (start it, or use 'watch')"
            continue
        fi
        if ! target_ready; then
            log "[$TARGET] ciphertext NOT ready (a mount root in [${MOUNTS[*]}] is empty${READY_MARKER:+ or $READY_MARKER missing}) -> NOT mounting (an in-place mount would shadow the dir and block the copy). Finish placing the files, then re-run 'up'."
            continue
        fi
        log "[$TARGET] mounting"
        write_allowlist
        do_up
        do_status
    done
    log "up complete."
    log "watch for EROFS/'Read-only file system' -> add those paths to WRITE_DIRS/WRITE_FILES and re-run 'up'."
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
# Mount the host now (always available), then — for sim — poll for the container
# and mount it whenever it (re)appears.  In real mode there is no container, so
# it degrades to a single host 'up'.
do_watch() {
    # host first: mount it immediately and load the module.
    TARGET=host
    log "[host] mounting"
    do_down; ensure_module; write_allowlist; do_up; do_status

    if [ "$MODE" = real ]; then
        log "real mode: no container to watch; done"
        return
    fi

    log "watch: polling for container '$CONTAINER' every ${WATCH_INTERVAL}s (backgrounded daemon; idle until it appears)"
    command -v docker >/dev/null 2>&1 || log "docker not present yet; will keep polling until it (and the container) are installed"
    TARGET=container
    # State machine: down (no container) -> waiting (up but ciphertext not yet
    # in place) -> up (mounted).  We do NOT mount until target_ready, so a
    # container that comes up BEFORE its bin/ lib/ are copied in is left alone —
    # the mount can't shadow the dir and block the install copy.
    local prev=down
    while :; do
        if container_running; then
            if target_ready; then
                if [ "$prev" != up ]; then
                    log "container '$CONTAINER' up + ciphertext ready -> mounting"
                    if (do_down; write_allowlist; do_up; do_status); then prev=up
                    else log "container mount failed; retrying next tick"; prev=waiting; fi
                fi
            else
                if [ "$prev" != waiting ]; then
                    log "container '$CONTAINER' up but ciphertext NOT ready (empty ${MOUNTS[*]}${READY_MARKER:+ / no $READY_MARKER}); waiting for the install copy to finish before mounting"
                    prev=waiting
                fi
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
        # mounts the host always, and the container too under --mode sim
        # (skipped with a note if the container isn't running).
        run_up_sequence
        ;;
    watch)
        do_watch
        ;;
    down)
        for TARGET in "${TARGETS[@]}"; do
            if ! target_present; then
                log "[$TARGET] container '$CONTAINER' not running; its mounts vanished with it — nothing to do"
                continue
            fi
            log "[$TARGET] tearing down"
            do_down
        done
        log "down complete (module left loaded; 'rmmod vcachefs' to fully unload)"
        ;;
    status)
        for TARGET in "${TARGETS[@]}"; do
            if ! target_present; then log "[$TARGET] container '$CONTAINER' not running"; continue; fi
            log "[$TARGET] status:"
            do_status
        done
        ;;
    *)
        die "usage: $0 [--mode real|sim] {up|down|status|watch}"
        ;;
esac
