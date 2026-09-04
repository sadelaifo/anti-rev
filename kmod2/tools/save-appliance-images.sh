#!/usr/bin/env bash
#
# save-appliance-images.sh — rebuild the TWO shippable Docker image tars for the
# RTOS appliance:
#
#   (1) RTOS tar  — the clean container's current state (your installed system
#       programs) with the business software EXCLUDED.  Produced by FLATTENING
#       (`docker export | docker import`), NOT `docker commit`: flattening drops
#       every lower layer so deleted-but-previously-present SW cannot ride along
#       in the tar (commit would keep it, recoverable).  Image metadata
#       (CMD/ENTRYPOINT/ENV/WORKDIR/USER/EXPOSE) is copied off the source
#       container and re-applied (export/import otherwise loses it).
#
#   (2) QEMU tar  — the qemu base image with the SHA-256-PINNED gate qemu baked
#       in (a `FROM ... COPY` build; the binary's +x bit is set on the host so
#       COPY carries it — no emulated `RUN chmod`, which would run the ARM64
#       shell under qemu and can hit the bash xmalloc bug during build).
#
# Your deployment Dockerfile then combines them (FROM rtos + COPY --from=qemu).
# If instead you want a single self-contained rtos image, set
# BAKE_QEMU_INTO_RTOS=1 and the gate qemu is baked into the RTOS tar too.
#
# Both tars are VERIFIED without emulating the ARM64 guest (docker create +
# export + tar): SW absent, and (where expected) the gate qemu present + pinned.
#
# Run ON THE HOST where docker + the containers live.  Fill in the CONFIG blanks
# from `docker ps -a` / `docker images`.

set -euo pipefail

# ===================== CONFIG — FILL THESE IN =====================
# ---- (1) RTOS tar: from the CLEAN container (you already rm -rf /root/*) ----
RTOS_CONTAINER=""                         # name/ID from `docker ps -a`
RTOS_IMAGE="lch_rtos:v0.0.2"              # tag for the SW-free image created
RTOS_OUT_TAR="lch_rtos_v0.0.2.tar"        # output tar

# ---- (2) QEMU tar: gate qemu baked into the qemu base image ----
QEMU_BASE_IMAGE=""                        # repo:tag from `docker images` (qemu_user_static)
QEMU_IMAGE="qemu_user_static:v0.0.1"      # tag for the image created
QEMU_OUT_TAR="qemu_user_static_v0.0.1.tar"  # output tar

# ---- gate qemu binary, its destination, and the pin ----
GATE_QEMU="kmod2/qemu-gate/prebuilt/qemu-aarch64-static"   # git prebuilt
QEMU_DEST="/usr/bin/qemu-aarch64-static"                   # path inside the images
EXPECTED_SHA="e15a16be5a29c74109579404ad285b937d208c6bcef5fbeed495c8e444cc19db"

# ---- behaviour ----
# 0 = keep rtos and qemu separate (default; your multi-stage Dockerfile combines
#     them).  1 = also bake the gate qemu INTO the rtos image (self-contained).
BAKE_QEMU_INTO_RTOS=0

# tar member paths have NO leading slash — anchor SW exclusions with ^root/... :
SW_PATHS_REGEX='^root/SW($|/)|^root/proj_protect($|/)|^root/SW_enc($|/)'
# =================================================================

say() { printf '\n=== %s ===\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---- sanity ----
command -v docker    >/dev/null 2>&1 || die "docker not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
[ -n "$RTOS_CONTAINER" ]  || die "fill in RTOS_CONTAINER (see: docker ps -a)"
[ -n "$QEMU_BASE_IMAGE" ] || die "fill in QEMU_BASE_IMAGE (see: docker images)"
docker inspect "$RTOS_CONTAINER"  >/dev/null 2>&1 || die "container '$RTOS_CONTAINER' not found"
docker image inspect "$QEMU_BASE_IMAGE" >/dev/null 2>&1 || die "image '$QEMU_BASE_IMAGE' not found (docker load it first?)"
[ -r "$GATE_QEMU" ] || die "gate qemu not found at '$GATE_QEMU'"

# ---- verify the gate qemu is the pinned build ----
say "checking gate qemu pin"
GOT_SHA=$(sha256sum "$GATE_QEMU" | cut -d' ' -f1)
echo "  sha256($GATE_QEMU) = $GOT_SHA"
# grep the file DIRECTLY (-a = treat binary as text).  Do NOT pipe `strings | grep -q`:
# under `set -o pipefail`, grep -q closes the pipe on first match, strings dies with
# SIGPIPE (141), and pipefail reports the pipeline as failed even though it matched.
grep -qa AREV_PROTECT_ROOTS "$GATE_QEMU" \
  || die "'$GATE_QEMU' has no gate compiled in (no AREV_PROTECT_ROOTS)"
if [ "$GOT_SHA" != "$EXPECTED_SHA" ]; then
  echo "  WARNING: does NOT match the pinned digest ($EXPECTED_SHA)."
  echo "  The .ko will REJECT this qemu unless you re-embed the digest via"
  echo "    kmod2/tools/authz-embed-qemu-hash.sh ... && rebuild the module."
  printf "  Continue anyway? [y/N] "; read -r a; [ "$a" = y ] || [ "$a" = Y ] || die "aborted"
fi

# a build context holding just the pinned qemu (reused for both bakes)
CTX=$(mktemp -d); trap 'rm -rf "$CTX"' EXIT
cp "$GATE_QEMU" "$CTX/qemu-aarch64-static"; chmod +x "$CTX/qemu-aarch64-static"

# bake_qemu <from-image> <out-image>
bake_qemu() {
  cat > "$CTX/Dockerfile" <<EOF
FROM $1
COPY qemu-aarch64-static $QEMU_DEST
LABEL description="+ gate qemu (pinned)"
EOF
  docker build -t "$2" "$CTX"
}

# verify_image <image> <expect_qemu:0|1>
# NB: all grep checks read FILES, never `producer | grep -q` — that combination
# trips `set -o pipefail` via SIGPIPE (see the gate-qemu pin check above).
verify_image() {
  local img="$1" want_qemu="$2" cid tmp list qref qbin rc=0
  cid=$(docker create "$img" /x)          # /x = dummy cmd, never executed
  tmp=$(mktemp); list=$(mktemp)
  docker export "$cid" > "$tmp"; docker rm "$cid" >/dev/null
  tar tf "$tmp" > "$list"                  # member listing to a file (no pipe)
  if grep -qE "$SW_PATHS_REGEX" "$list"; then
    echo "  !! SW paths STILL present:"; grep -E "$SW_PATHS_REGEX" "$list" | head; rc=1
  else
    echo "  OK: no SW paths"
  fi
  if [ "$want_qemu" = 1 ]; then
    qref="${QEMU_DEST#/}"
    if grep -qx "$qref" "$list"; then
      qbin=$(mktemp)
      tar xO -f "$tmp" "$qref" > "$qbin" 2>/dev/null || true
      if grep -qa AREV_PROTECT_ROOTS "$qbin"; then
        echo "  OK: gate qemu present + compiled-in at $QEMU_DEST"
      else
        echo "  !! qemu at $QEMU_DEST has NO gate compiled in"; rc=1
      fi
      rm -f "$qbin"
    else
      echo "  !! qemu not found at $QEMU_DEST"; rc=1
    fi
  fi
  rm -f "$tmp" "$list"; return $rc
}

# ---- collect metadata from the source container (import drops it otherwise) ----
say "capturing rtos image metadata from '$RTOS_CONTAINER'"
changes=()
cmd=$(docker inspect -f '{{json .Config.Cmd}}' "$RTOS_CONTAINER")
[ "$cmd" != "null" ] && changes+=( -c "CMD $cmd" )
ep=$(docker inspect -f '{{json .Config.Entrypoint}}' "$RTOS_CONTAINER")
[ "$ep" != "null" ] && changes+=( -c "ENTRYPOINT $ep" )
wd=$(docker inspect -f '{{.Config.WorkingDir}}' "$RTOS_CONTAINER")
[ -n "$wd" ] && changes+=( -c "WORKDIR $wd" )
usr=$(docker inspect -f '{{.Config.User}}' "$RTOS_CONTAINER")
[ -n "$usr" ] && changes+=( -c "USER $usr" )
while IFS= read -r e; do [ -n "$e" ] && changes+=( -c "ENV $e" ); done \
  < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$RTOS_CONTAINER")
while IFS= read -r p; do [ -n "$p" ] && changes+=( -c "EXPOSE ${p%%/*}" ); done \
  < <(docker inspect -f '{{range $k,$v := .Config.ExposedPorts}}{{println $k}}{{end}}' "$RTOS_CONTAINER")
echo "  ${#changes[@]} metadata change(s) captured"

# ---- (1) RTOS tar ----
say "flattening '$RTOS_CONTAINER' -> $RTOS_IMAGE (single layer, SW-free)"
docker export "$RTOS_CONTAINER" | docker import "${changes[@]}" - "$RTOS_IMAGE"
if [ "$BAKE_QEMU_INTO_RTOS" = 1 ]; then
  say "baking gate qemu into rtos image"
  bake_qemu "$RTOS_IMAGE" "$RTOS_IMAGE"
fi
say "saving rtos -> $RTOS_OUT_TAR"
docker save -o "$RTOS_OUT_TAR" "$RTOS_IMAGE"
say "verifying $RTOS_IMAGE"
verify_image "$RTOS_IMAGE" "$BAKE_QEMU_INTO_RTOS" || echo "  (review warnings)"

# ---- (2) QEMU tar ----
say "baking gate qemu -> $QEMU_IMAGE (from $QEMU_BASE_IMAGE)"
bake_qemu "$QEMU_BASE_IMAGE" "$QEMU_IMAGE"
say "saving qemu -> $QEMU_OUT_TAR"
docker save -o "$QEMU_OUT_TAR" "$QEMU_IMAGE"
say "verifying $QEMU_IMAGE"
verify_image "$QEMU_IMAGE" 1 || echo "  (review warnings)"

say "done"
ls -lh "$RTOS_OUT_TAR" "$QEMU_OUT_TAR" 2>/dev/null || true
cat <<'NOTE'

Reminders:
  * Neither tar contains /dev/vcachefs, mounts, --privileged/--shm-size, or the
    binfmt registration — those are runtime.  Recreate them on container start
    (mknod + vcache-mount + register-binfmt.sh) or from your saved `docker run`
    line; the tars alone will not bring them back.
  * The RTOS image is ARM64 — run/verify guest commands with
    `-e QEMU_RESERVED_VA=0x400000000` to avoid the bash xmalloc-under-qemu error.
  * Keep these tars off any medium a client could copy — treat like the .enc
    tree (embedded-key ciphertext is decryptable).
NOTE
