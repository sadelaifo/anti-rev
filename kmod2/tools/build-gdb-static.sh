#!/bin/sh
# build-gdb-static.sh — build a fully-static, multiarch "vcache-coredbg" for debugging
# coredumps of protected (encrypted-binary) processes at a client site.
#
# WHY: a client's stock gdb is denied by the vcachefs gate when it tries to read
# the ENCRYPTED binaries/.debug it needs to symbolize a core (the OS core itself
# is plaintext).  A company technician's gdb, once VENDOR-SIGNED, is authorized
# by the gate (per-exe signature) and can read those decrypted through the mount.
# This tool is NOT shipped to the client; the technician brings it when a core
# needs debugging.
#
# WHAT this produces: ONE statically-linked gdb (x86_64 host) with ALL targets
# enabled (--enable-targets=all), so it reads BOTH x86_64 and aarch64 cores and
# binaries.  Fully static (-all-static -no-pie) so it runs on any client box
# regardless of its glibc.  Two flags are REQUIRED and non-obvious:
#   * -all-static (NOT plain -static): gdb links its final executable through
#     LIBTOOL, which SWALLOWS a plain -static (it means "static only against
#     libtool archives") and still emits a dynamic binary needing the client's
#     ld.so/libc.  -all-static is libtool's "fully static, no dynamic linking"
#     flag and is what actually produces a static ELF here.
#   * -no-pie / -fno-PIE: distros that default gcc to -pie (Ubuntu/Debian)
#     otherwise emit a PIE that ignores static linking.
# ALWAYS verify the result with `ldd` / `file`: it must say "statically linked"
# / "not a dynamic executable", NOT "interpreter /lib64/ld-linux...".  The
# system static libs this needs — libc.a libm.a libstdc++.a libz.a libexpat.a
# libzstd.a — come from gcc/g++ + zlib1g-dev libexpat1-dev libzstd-dev.
# (For a technician who must run gdb natively ON an arm64 box, build
# an aarch64 host gdb on an arm64 machine, or cross — see the notes at the end.)
#
# UNIQUE HASH (the "magic number"): a random 128-bit build marker is baked into
# the version string via gdb's official --with-pkgversion, so this binary's
# SHA-256 CANNOT match any public gdb — no upstream/distro build carries the
# "vcachefs-coredbg" pkgversion prefix, and the 16 random bytes make a collision
# with any other build astronomically improbable.  `gdb --version` prints it
# (e.g. "vcachefs-coredbg a1b2c3d4...") so a technician can identify the binary.
# Pin a specific magic with BUILD_ID=<hex>; the default is fresh randomness per
# build.  Do NOT pad trailing garbage to force uniqueness — the vendor signature
# footer (sign-exe.sh) lives at the END of the file and the gate reads it from
# there; a marker in .rodata is the ONLY clean way to make the build unique.
#
# NO sudo / root: gmp, mpfr and ncurses are built from source into a local
# prefix (modern gdb REQUIRES gmp+mpfr; readline/TUI need a curses/termcap lib).
#
# AFTER building: sign it with your vendor key so the gate trusts it —
#     kmod2/tools/sign-exe.sh <vendor.key> <vendor.crt> vcache-coredbg
#   and make sure the matching vendor cert is embedded in the module
#   (gate_authz_pubkey.h) and the .ko rebuilt.  The technician runs the SIGNED
#   vcache-coredbg on the client box against the (plaintext) core, with the encrypted
#   binary tree mounted so symbols resolve through the gated mount.
#
# Usage:  build-gdb-static.sh [OUTPUT_BINARY]
#   env:  GDB_VER (default 14.2)   JOBS (default nproc)
#         BUILD_ID (default random 8 bytes hex -> the unique marker)
#         WORK (default $PWD/gdb-static-work — put this on a NATIVE fs, not /mnt)
# Run on Linux (WSL ok).  Deps that must already exist: gcc/g++ (C++17), make,
# bison, flex, xz, tar, curl.  (makeinfo is optional; stubbed below.)
set -eu

GDB_VER=${GDB_VER:-14.2}
GMP_VER=${GMP_VER:-6.3.0}
MPFR_VER=${MPFR_VER:-4.2.1}
NCURSES_VER=${NCURSES_VER:-6.4}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}
BUILD_ID=${BUILD_ID:-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}
WORK=${WORK:-$(pwd)/gdb-static-work}
OUT=${1:-$(pwd)/vcache-coredbg}
PKGVERSION="vcachefs-coredbg ${BUILD_ID}"

PREFIX="$WORK/prefix"
SRC="$WORK/src"
mkdir -p "$SRC" "$PREFIX/lib" "$PREFIX/include"
GNU=https://ftp.gnu.org/gnu

log() { echo "[gdb-build] $*"; }
fetch() {           # fetch <url>  (idempotent)
	f="$SRC/$(basename "$1")"
	[ -f "$f" ] || curl -fL --retry 3 --connect-timeout 20 -o "$f" "$1"
	echo "$f"
}
unpack() {          # unpack <tarball> -> prints extracted dir
	d="$SRC/$(basename "$1" | sed 's/\.tar\.[gx]z$//')"
	rm -rf "$d"; tar -C "$SRC" -xf "$1"; echo "$d"
}

log "deps -> $PREFIX   gdb=$GDB_VER id=$BUILD_ID jobs=$JOBS"
log "work dir: $WORK   output: $OUT"

# ---------------------------------------------------------------- gmp
log "building gmp $GMP_VER"
d=$(unpack "$(fetch "$GNU/gmp/gmp-$GMP_VER.tar.xz")")
( cd "$d" && ./configure --prefix="$PREFIX" --disable-shared --enable-static \
	--with-pic >/dev/null && make -j"$JOBS" >/dev/null && make install >/dev/null )

# ---------------------------------------------------------------- mpfr
log "building mpfr $MPFR_VER"
d=$(unpack "$(fetch "$GNU/mpfr/mpfr-$MPFR_VER.tar.xz")")
( cd "$d" && ./configure --prefix="$PREFIX" --disable-shared --enable-static \
	--with-pic --with-gmp="$PREFIX" >/dev/null && make -j"$JOBS" >/dev/null && \
	make install >/dev/null )

# ---------------------------------------------------------------- ncurses
# Static curses for readline/TUI.  Default build keeps termcap routines inside
# libncurses.a; alias libtinfo.a to it so either -lncurses or -ltinfo resolves.
log "building ncurses $NCURSES_VER"
d=$(unpack "$(fetch "$GNU/ncurses/ncurses-$NCURSES_VER.tar.gz")")
( cd "$d" && ./configure --prefix="$PREFIX" --without-shared --without-debug \
	--without-cxx-binding --without-ada --without-manpages --without-tests \
	>/dev/null 2>&1 && make -j"$JOBS" >/dev/null 2>&1 && make install >/dev/null 2>&1 )
[ -f "$PREFIX/lib/libtinfo.a" ] || ln -sf libncurses.a "$PREFIX/lib/libtinfo.a"

# ---------------------------------------------------------------- gdb
log "building gdb $GDB_VER (static, --enable-targets=all)"
d=$(unpack "$(fetch "$GNU/gdb/gdb-$GDB_VER.tar.xz")")
(
	cd "$d"
	# --disable-tui: the full-screen TUI needs ncurses HEADERS wired in (WINDOW/
	# chtype), which is fiddly with a custom-prefix ncurses and unnecessary for
	# core debugging; the CLI is enough.  readline still links libtinfo.a (from
	# the prefix) for line editing.
	./configure \
		--prefix="$PREFIX" \
		--enable-targets=all \
		--disable-gdbserver \
		--disable-nls \
		--disable-tui \
		--without-python \
		--with-pkgversion="$PKGVERSION" \
		--with-gmp="$PREFIX" --with-mpfr="$PREFIX" \
		--with-expat --with-system-zlib \
		CPPFLAGS="-I$PREFIX/include" \
		CFLAGS="-O2 -no-pie -fno-PIE" \
		CXXFLAGS="-O2 -no-pie -fno-PIE" \
		LDFLAGS="-all-static -no-pie -L$PREFIX/lib" \
		>/dev/null
	# MAKEINFO=true: skip doc generation (texinfo not required to build gdb).
	make -j"$JOBS" MAKEINFO=true all-gdb
)

cp "$d/gdb/gdb" "$OUT"
strip "$OUT" 2>/dev/null || true

log "done."
echo "---------------------------------------------------------------"
file "$OUT" || true
"$OUT" --version | head -2 || true
echo "sha256: $(sha256sum "$OUT" | cut -d' ' -f1)"
echo "---------------------------------------------------------------"
echo "NEXT: sign it so the vcachefs gate trusts it:"
echo "  kmod2/tools/sign-exe.sh <vendor.key> <vendor.crt> \"$OUT\""
echo "(signing appends the ANTRSIG footer; the gate verifies it against the"
echo " vendor cert embedded in gate_authz_pubkey.h.)"
#
# ---- aarch64 host build (run gdb natively ON an arm64 client box) ----
# This script builds an x86_64-host gdb that already READS aarch64 cores, which
# covers the qemu-user "sim" deployment (mount + gate live on the x86 host).  A
# native aarch64 gdb is only needed to run ON a real arm64 slave; build this same
# script on an arm64 machine, or cross-build with an aarch64 toolchain
# (CC=aarch64-linux-gnu-gcc etc.) plus aarch64 static gmp/mpfr/ncurses.
