/*
 * gate_whitelist.h — HARD-CODED authorization whitelist, compiled into the .ko.
 *
 * A process whose executable BASENAME is listed here passes the gate
 * unconditionally (no signature, no file).  This is the second of the two
 * pass-types (the first is a valid per-exe in-file signature); use it for the
 * small, stable set that can't ship as signed antirevfs containers:
 *   - the qemu emulator (the sim path gates ARM64 lib reads on ITS identity)
 *   - interpreters that load encrypted modules (python3, ...)
 *   - any always-allowed launcher/tool you control
 *
 * Being compiled in, the client cannot edit it (unlike a file), and there is
 * nothing to ship.  To change it: edit this list and REBUILD the module.
 * Match is by exact basename (what d_name shows for the running exe).
 */
#ifndef ANTIREVFS_GATE_WHITELIST_H
#define ANTIREVFS_GATE_WHITELIST_H

static const char *const antirev_whitelist[] = {
	"qemu-aarch64-static",
	/* "python3", */
	/* "your-launcher", */
	NULL
};

#endif /* ANTIREVFS_GATE_WHITELIST_H */
