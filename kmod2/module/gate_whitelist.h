/*
 * gate_whitelist.h — HARD-CODED authorization whitelist, compiled into the .ko.
 *
 * A process whose executable BASENAME is listed here passes the gate
 * unconditionally (no signature, no file).  This is the second of the two
 * pass-types (the first is a valid per-exe in-file signature); use it for the
 * small, stable set that can't ship as signed vcachefs containers:
 *   - the qemu emulator (the sim path gates ARM64 lib reads on ITS identity)
 *   - interpreters that load encrypted modules (python3, ...)
 *   - any always-allowed launcher/tool you control
 *
 * Being compiled in, the client cannot edit it (unlike a file), and there is
 * nothing to ship.  To change it: edit this list and REBUILD the module.
 * Match is by exact basename (what d_name shows for the running exe).
 */
#ifndef VCACHEFS_GATE_WHITELIST_H
#define VCACHEFS_GATE_WHITELIST_H

static const char *const antirev_whitelist[] = {
	/*
	 * NOTE: qemu-aarch64-static is intentionally NOT here — it is pinned by
	 * name+SHA-256 in gate_trusted_hashes.h so only a specific qemu build is
	 * trusted (a plain basename match would trust any file so named).  List
	 * here only interpreters/launchers you accept by basename alone.
	 */
	/* "python3", */
	/* "your-launcher", */

	/*
	 * vcache-replace: the live per-file upgrade tool.  It drives the
	 * /dev/vcachefs control device (AREV_IOC_LOWER_DIRFD + REFRESH_PATH) to
	 * swap one encrypted executable in an in-place mount without a remount.
	 * NOTE: this whitelist is shared with the data-read gate, so listing a
	 * basename here also lets a process so named read DECRYPTED content
	 * through the mount.  vcache-replace never does (it only writes
	 * ciphertext into the lower dir), but a different binary renamed to
	 * "vcache-replace" would inherit that trust — acceptable under the
	 * rookie/competitor threat model (needs root at the box).  HARDENING:
	 * drop this entry and instead per-exe-sign vcache-replace (passes via
	 * the signature branch) or pin it by name+SHA-256 in
	 * gate_trusted_hashes.h, exactly as qemu-aarch64-static is.
	 */
	"vcache-replace",
	NULL
};

#endif /* VCACHEFS_GATE_WHITELIST_H */
