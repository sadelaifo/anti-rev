#!/usr/bin/env bash
# register-binfmt.sh — register the gate-enabled qemu-aarch64 as the aarch64
# binfmt_misc interpreter, escape-safe.
#
#   sudo kmod2/qemu-gate/register-binfmt.sh [register|unregister|status]
#
# Uses the F (fix-binary) flag: the kernel OPENS the interpreter at registration
# time and holds the fd, so transparent execution works inside containers even
# though the qemu binary isn't present in the container's filesystem (that is why
# /proc/sys/fs/binfmt_misc looks empty inside the container).
#
# Why a script (not a bare `echo`): plain `echo` under sh/dash interprets the
# \x.. magic escapes and appends a newline that corrupts the flags field, so the
# entry ends up missing or with a magic that matches nothing -> "Exec format
# error" on aarch64 binaries.  printf '%s' writes the backslash sequences
# literally (the kernel parses them) with no stray newline.
#
# Env overrides:
#   AREV_QEMU_SRC     built gate qemu to install (default: this dir/prebuilt/qemu-aarch64-static)
#   AREV_QEMU_INTERP  install path / interpreter  (default: /usr/bin/qemu-aarch64-static)
#   AREV_BINFMT_NAME  binfmt entry name           (default: qemu-aarch64)
#   AREV_BINFMT_FLAGS binfmt flags                (default: F; add C for setuid guests)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NAME="${AREV_BINFMT_NAME:-qemu-aarch64}"
INTERP="${AREV_QEMU_INTERP:-/usr/bin/qemu-aarch64-static}"
SRC="${AREV_QEMU_SRC:-$HERE/prebuilt/qemu-aarch64-static}"
FLAGS="${AREV_BINFMT_FLAGS:-F}"
BM=/proc/sys/fs/binfmt_misc

# aarch64 ELF signature (little-endian, e_machine=0xb7) — the same magic/mask
# qemu-user-static registers.  Safe to use verbatim.
MAGIC='\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00'
MASK='\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff'

die(){ echo "register-binfmt: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root (writes $BM)"

ensure_bm(){
  mountpoint -q "$BM" || mount -t binfmt_misc none "$BM" 2>/dev/null \
    || die "binfmt_misc not available (CONFIG_BINFMT_MISC? 'modprobe binfmt_misc')"
  grep -q enabled "$BM/status" 2>/dev/null || echo 1 > "$BM/status"
}

case "${1:-register}" in
  status)
    ensure_bm
    echo "status: $(cat "$BM/status")"
    if [ -e "$BM/$NAME" ]; then cat "$BM/$NAME"; else echo "($NAME not registered)"; fi
    ;;
  unregister)
    ensure_bm
    if [ -e "$BM/$NAME" ]; then echo -1 > "$BM/$NAME"; echo "unregistered $NAME"; else echo "$NAME not registered"; fi
    ;;
  register)
    ensure_bm
    [ -f "$SRC" ] || die "gate qemu not found: $SRC (set AREV_QEMU_SRC)"
    install -m0755 "$SRC" "$INTERP"
    # re-point cleanly: drop any existing entry first (F holds an fd to the old one)
    [ -e "$BM/$NAME" ] && echo -1 > "$BM/$NAME" 2>/dev/null || true
    printf '%s' ":$NAME:M::$MAGIC:$MASK:$INTERP:$FLAGS" > "$BM/register" \
      || die "registration write failed (magic/interp?)"
    echo "registered $NAME -> $INTERP (flags $FLAGS)"
    cat "$BM/$NAME"
    ;;
  *) die "usage: $0 [register|unregister|status]";;
esac
