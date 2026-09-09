#!/usr/bin/env bash
# gcc wrapper: drop aarch64 hardening flags that an older gcc (e.g. the
# company-pinned 7.3) can't parse, then exec the real gcc.
#
# WHY A WRAPPER AND NOT THE MODULE MAKEFILE:
#   The openEuler/EulerOS kernel-devel was built with gcc 10, and its config
#   claims compiler features gcc 7.3 lacks, so arch/arm64/Makefile injects
#   -mbranch-protection / -fpatchable-function-entry / -mstack-protector-guard=*
#   into KBUILD_CFLAGS.  The module Makefile's ccflags-remove-y strips these from
#   OUR objects (super.o, inode.o, ...) — but NOT from the auto-generated
#   vcachefs.mod.o glue, which kbuild's final stage (scripts/Makefile.modfinal)
#   compiles with raw KBUILD_CFLAGS without ever reading our Makefile.  A CC
#   wrapper is the only seam every compile stage passes through, so it strips
#   uniformly.
#
# USAGE:
#   make -C kmod2/module KDIR=<tree> AREV_DEV_MODE=1 \
#        CC=$(pwd)/kmod2/tools/gcc-strip-unknown-flags.sh
#   # real gcc defaults to `gcc` on PATH; override with REALCC=/abs/path/gcc
#
# The .ko stays loadable: PAC return-signing, ftrace patchable-entries, and the
# per-task stack canary are self-contained per-function codegen, not part of the
# module<->kernel ABI.  When the stack-protector sysreg flags are dropped, we add
# -fno-stack-protector so gcc emits NO canary at all (otherwise it falls back to
# the global __stack_chk_guard, which a per-task-canary arm64 kernel does not
# export to modules -> "modpost: __stack_chk_guard undefined").
set -u
: "${REALCC:=gcc}"

new=()
strip_ssp=0
for a in "$@"; do
	case "$a" in
	-mbranch-protection=*|-fpatchable-function-entry=*)
		continue ;;
	-mstack-protector-guard=*|-mstack-protector-guard-reg=*|-mstack-protector-guard-offset=*)
		strip_ssp=1
		continue ;;
	esac
	new+=("$a")
done

# If we removed the per-task canary flags, turn the canary off entirely so gcc
# doesn't emit a reference to the unexported global __stack_chk_guard.  Appended
# last, it overrides any earlier -fstack-protector-strong.
if [ "$strip_ssp" -eq 1 ]; then
	new+=(-fno-stack-protector)
fi

exec "$REALCC" "${new[@]}"
