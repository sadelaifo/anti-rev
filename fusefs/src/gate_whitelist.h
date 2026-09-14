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
	"java",			/* JVM: reads encrypted .jar */
	/*
	 * CPython.  The gate matches the basename that /proc/<pid>/exe RESOLVES to,
	 * and distro `python`/`python3` are SYMLINKS to a concrete minor binary
	 * (e.g. `python3.10`), which is the name exe_file reports.  So we must list
	 * the real binary names, not just `python3`.  We enumerate the realistic
	 * set explicitly (a security whitelist should be explicit, not a fuzzy
	 * prefix match).  If your interpreter resolves to something not listed
	 * (`readlink -f "$(command -v python3)"`), add it here and rebuild.
	 */
	"python", "python2", "python2.7",
	"python3",
	"python3.6", "python3.7", "python3.8", "python3.9",
	"python3.10", "python3.11", "python3.12", "python3.13",
	/* "qemu-aarch64-static", */
	/* "your-launcher", */
	NULL
};

#endif /* FUSEFS_GATE_WHITELIST_H */
