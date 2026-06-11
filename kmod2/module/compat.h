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

/*
 * get_mm_exe_file() is defined in kernel/fork.c but is NOT exported to modules
 * on every kernel (e.g. Ubuntu's 6.8.0-x generic build drops the EXPORT_SYMBOL
 * while SLES 4.12 keeps it), so linking against it fails modpost with an
 * "undefined" error on those kernels.  Open-code the same refcount dance the
 * kernel does internally, using the always-exported get_file_rcu().  The
 * get_file_rcu() prototype changed in 6.7 (commit 0ede61d8589c) from a
 * try-get-on-a-bare-pointer macro to a function taking the __rcu slot address.
 */
static inline struct file *arev_get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
	exe_file = get_file_rcu(&mm->exe_file);
#else
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
#endif
	rcu_read_unlock();
	return exe_file;
}

/*
 * True when `file` is being opened by the kernel to load it AS a program
 * (execve / load_elf_binary), as opposed to a plain data read (cp, cat, a
 * library open).  The exec-load gate uses this to authorize on the program's
 * OWN path instead of the caller's exe identity.
 *
 * The signal moved across kernels: SLES 4.12 sets FMODE_EXEC in f_mode by the
 * time a stacked fs's ->open runs, but mainline 6.8 reaches ->open with
 * FMODE_EXEC clear (f_mode 0x801d) and the intent surviving only as
 * __FMODE_EXEC in f_flags (0x8020).  current->in_execve is NOT usable here:
 * the kernel opens the binary in alloc_bprm() *before* bprm_execve() sets
 * in_execve=1, so it still reads 0 at this point.  Test both flag homes.
 */
static inline bool arev_is_exec_open(struct file *file)
{
	return (file->f_mode & FMODE_EXEC) || (file->f_flags & __FMODE_EXEC);
}

#endif /* _ANTIREVFS_COMPAT_H */
