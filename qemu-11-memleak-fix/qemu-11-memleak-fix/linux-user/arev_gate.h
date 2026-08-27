/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * arev_gate.h — qemu-user per-guest decrypt gate (talks to /dev/vcachefs).
 * See arev_uapi.h for the model.
 */
#ifndef AREV_GATE_H
#define AREV_GATE_H

#include <stdbool.h>

/*
 * Open /dev/vcachefs and read config from the environment.  Idempotent; safe to
 * call more than once.  If the device is absent (non-vcachefs deployment, or a
 * plaintext build), the gate stays INACTIVE and every hook below is a no-op /
 * passthrough — so a qemu with these hooks still runs everything normally.
 *
 * Env:
 *   AREV_GATE=off             force the gate off even if the device exists
 *   AREV_PROTECT_ROOTS=a:b:c  colon-separated absolute path prefixes whose files
 *                             are protected (default: none -> nothing gated).
 *                             Set this to the mount roots, e.g. /root/SW.
 *   AREV_GATE_LOG=path        line-buffered decision log (optional)
 */
void arev_gate_init(void);

/* True once arev_gate_init() has opened the control device. */
bool arev_gate_active(void);

/*
 * Set the current guest process's authorization from its program binary.
 * Called from the ELF loader with the guest binary path.  Asks the kernel to
 * verify the binary's vendor signature; the verdict governs whether this
 * guest's later reads of protected files see plaintext (mount) or ciphertext.
 * A no-op when the gate is inactive.
 */
void arev_gate_set_guest(const char *guest_filename);

/*
 * Open-time hook.  Returns:
 *   >= 0  a host fd to hand the guest (the keyless-ciphertext fd)
 *   -1    a handled error (errno set) — DENY, do NOT fall back to a real open
 *   -2    not handled: the caller should perform its normal open
 *
 * Contract mirrors maybe_do_fake_open(): -2 means "not mine".  For an
 * unauthorized guest reading a protected file we NEVER return -2 (that would let
 * the normal open hit the decrypting mount and leak plaintext) — we return the
 * ciphertext fd, or -1/EACCES if we cannot produce it.
 */
int arev_gate_open(int dirfd, const char *host_pathname, int flags);

#endif /* AREV_GATE_H */
