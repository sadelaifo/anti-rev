/*
 * gate_whitelist.h — HARD-CODED authorization whitelist, compiled into vcachefsd.
 *
 * A caller process whose executable BASENAME is listed here passes the gate
 * unconditionally.  Use it for the small, stable set of launchers/interpreters
 * that legitimately read encrypted content:
 *   - the qemu emulator (the ARM64 lib reads are gated on ITS identity)
 *   - interpreters that import/dlopen encrypted modules (python3, ...)
 *   - your product launcher
 *
 * Being compiled in, the client cannot edit it; to change it, edit this list
 * and rebuild the daemon.  Match is by exact basename of /proc/<pid>/exe.
 *
 * SECURITY NOTE: basename-only trust means any file so named passes.  kmod2
 * pins qemu by name+SHA-256 (gate_trusted_hashes.h) for exactly this reason;
 * porting that hash-pin here is future work (see ../DESIGN.md).
 */
#ifndef FUSEFS_GATE_WHITELIST_H
#define FUSEFS_GATE_WHITELIST_H

#include <stddef.h>		/* NULL */

static const char *const fusefs_whitelist[] = {
	/* "python3", */
	/* "qemu-aarch64-static", */
	/* "your-launcher", */
	NULL
};

#endif /* FUSEFS_GATE_WHITELIST_H */
