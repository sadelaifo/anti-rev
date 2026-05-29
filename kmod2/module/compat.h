/* SPDX-License-Identifier: GPL-2.0 */
/*
 * antirevfs cross-kernel compatibility shims.
 *
 * Primary targets: SLES 12 (4.12.14-default) and mainline 6.8.  Version guards
 * use LINUX_VERSION_CODE, which on enterprise distro kernels reflects the base
 * version (e.g. 4.12.14) — SUSE/RHEL backport newer APIs, so if a guard guesses
 * wrong for your kernel, override it with the AREV_* defines documented below
 * (pass e.g. `make EXTRA_CFLAGS=-DAREV_NEW_KERNEL_READ`).
 */
#ifndef _ANTIREVFS_COMPAT_H
#define _ANTIREVFS_COMPAT_H

#include <linux/version.h>
#include <linux/fs.h>

/* hex2bin() moved from linux/kernel.h to linux/hex.h in 5.18. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
#include <linux/hex.h>
#else
#include <linux/kernel.h>
#endif

/* Superblock flags renamed MS_* -> SB_* in 4.15 (internal use). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#ifndef SB_RDONLY
#define SB_RDONLY	MS_RDONLY
#endif
#ifndef SB_NOSUID
#define SB_NOSUID	MS_NOSUID
#endif
#ifndef SB_NODEV
#define SB_NODEV	MS_NODEV
#endif
#endif

/*
 * kernel_read() gained the modern (file, buf, count, *pos) signature in 4.14;
 * before that it was int kernel_read(file, loff_t offset, char *addr, count)
 * and did not advance a position.  Define AREV_NEW_KERNEL_READ if your <4.14
 * distro kernel backported the new prototype.
 */
static inline ssize_t arev_kernel_read(struct file *f, void *buf, size_t count,
				       loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || defined(AREV_NEW_KERNEL_READ)
	return kernel_read(f, buf, count, pos);
#else
	ssize_t n = kernel_read(f, *pos, (char *)buf, count);

	if (n > 0)
		*pos += n;
	return n;
#endif
}

#endif /* _ANTIREVFS_COMPAT_H */
