# shellcheck shell=bash
# keyhelper.sh — key-in-.ko test support.  Since the AES key is compiled into
# the module (not the ciphertext), a test must build the .ko with the SAME key
# it packs with.  Source this and call, after the keyfile exists and before
# insmod:
#
#     arev_build_with_key "$WORK/key.hex" "$KMOD/module"
#
# It (1) creates a random 32-byte hex keyfile if absent, (2) regenerates
# module/key_blob.c from it (shared/gen_key_blob.py — only key_blob.o then
# recompiles), (3) builds the module.  Honors env:
#     AREV_CC        compiler (e.g. gcc-4.8 on SLES12, or the strip wrapper)
#     AREV_DEV_MODE  default 1 — the gate tests need the dev gate_enforce param
#
# Requires $ROOT (repo root) to be set by the caller (every kmod2 test defines
# it as "$KMOD/..").
arev_build_with_key() {
	local kf="$1" moddir="$2"
	: "${ROOT:?arev_build_with_key: \$ROOT (repo root) not set}"
	[ -s "$kf" ] || python3 -c 'import os,sys; open(sys.argv[1],"w").write(os.urandom(32).hex())' "$kf"
	python3 "$ROOT/shared/gen_key_blob.py" "$kf" "$moddir/key_blob.c" >&2
	make -C "$moddir" ${AREV_CC:+CC="$AREV_CC"} AREV_DEV_MODE="${AREV_DEV_MODE:-1}" >&2 \
		|| { echo "arev_build_with_key: module build failed" >&2; return 1; }
}
