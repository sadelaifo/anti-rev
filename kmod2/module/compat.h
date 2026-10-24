/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vcachefs cross-kernel compatibility shims.
 *
 * Primary targets: SLES 12 (4.12.14-default) and mainline 6.8.  Version guards
 * use LINUX_VERSION_CODE, which on enterprise distro kernels reflects the base
 * version (e.g. 4.12.14) — SUSE/RHEL backport newer APIs, so if a guard guesses
 * wrong for your kernel, override it with the AREV_* defines documented below
 * (pass e.g. `make EXTRA_CFLAGS=-DAREV_NEW_KERNEL_READ`).
 */
#ifndef _VCACHEFS_COMPAT_H
#define _VCACHEFS_COMPAT_H

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/dcache.h>

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
 * Pre-4.12 accessor shims (RHEL/CentOS 7 3.10.0-1160 and similar backported
 * enterprise kernels).  Each is inert on kernels new enough to provide the
 * real thing, so the 4.12+/6.8 builds are unaffected.
 */

/* d_inode()/d_really_is_positive() convenience accessors arrived in 3.19. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
#ifndef d_inode
#define d_inode(dentry)			((dentry)->d_inode)
#endif
#ifndef d_really_is_positive
#define d_really_is_positive(dentry)	((dentry)->d_inode != NULL)
#endif
#endif

/*
 * lookup_one_len_unlocked() arrived in 4.6.  vcachefs only calls it from
 * ->lookup, where the VFS already holds the parent inode lock, so the locked
 * lookup_one_len() (identical 3-arg signature) is the correct equivalent.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
#ifndef lookup_one_len_unlocked
#define lookup_one_len_unlocked(name, base, len) \
	lookup_one_len(name, base, len)
#endif
#endif

/*
 * SLAB_ACCOUNT (kmemcg accounting of the slab) arrived in 4.5.  It is a pure
 * accounting hint, so on older kernels drop it to 0 — the inode cache works
 * identically, just without per-cgroup memory accounting.
 */
#ifndef SLAB_ACCOUNT
#define SLAB_ACCOUNT	0
#endif

/*
 * memzero_explicit() (a memset the compiler may not elide) arrived in 3.18.
 * RHEL/CentOS 7 backported it into its 3.10 kernel, so gate the shim out on
 * RHEL (RHEL_RELEASE_CODE) to avoid a redefinition; only genuinely-old mainline
 * kernels below 3.18 need it.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) && !defined(RHEL_RELEASE_CODE)
static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
	barrier();
}
#endif

/*
 * kernel_read() gained the modern (file, buf, count, *pos) signature in 4.14;
 * before that it was int kernel_read(file, loff_t offset, char *addr, count)
 * and did not advance a position.  Define AREV_NEW_KERNEL_READ if your <4.14
 * distro kernel backported the new prototype.
 */
static inline ssize_t vcf_kernel_read(struct file *f, void *buf, size_t count,
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
 * kernel_write() got the modern (file, buf, count, *pos) prototype in 4.14
 * (older: kernel_write(file, buf, count, pos) with the offset BY VALUE).
 *
 * IMPORTANT: kernel_read and kernel_write did NOT necessarily change together on
 * enterprise kernels.  FIELD FACT: SLES 12 SP5 (4.12.14-120) ships the OLD
 * kernel_read but the NEW kernel_write — so this must NOT reuse the
 * AREV_NEW_KERNEL_READ guard.  Default to the modern prototype (correct for
 * mainline 4.14+, Ubuntu 6.8, AND SLES 12 SP5); define AREV_OLD_KERNEL_WRITE
 * only for a genuinely pre-4.14 kernel that did NOT backport it (symptom without
 * the flag there: "makes integer from pointer without a cast" on arg 4).
 *
 * FIELD FACT: RHEL/CentOS 7 (3.10) ships the OLD by-value-offset kernel_write
 * and did NOT backport the modern one, so auto-select the old path there —
 * keyed on RHEL_RELEASE_CODE so SLES 12 SP5 (also <4.14, but modern) is
 * unaffected.  RHEL 8+ is >=4.14 and falls to the modern default.
 */
static inline ssize_t vcf_kernel_write(struct file *f, const void *buf,
					size_t count, loff_t *pos)
{
#if defined(AREV_OLD_KERNEL_WRITE) || \
	(defined(RHEL_RELEASE_CODE) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
	ssize_t n = kernel_write(f, (const char *)buf, count, *pos);

	if (n > 0)
		*pos += n;
	return n;
#else
	return kernel_write(f, buf, count, pos);
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
static inline struct file *vcf_get_mm_exe_file(struct mm_struct *mm)
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
static inline bool vcf_is_exec_open(struct file *file)
{
	return (file->f_mode & FMODE_EXEC) || (file->f_flags & __FMODE_EXEC);
}

/*
 * d_invalidate() unhashes a dentry and shrinks away its (unused) subtree, so a
 * later lookup re-resolves it against the lower fs.  The prototype changed in
 * 3.18 (commit 5542aa2fa743): before, it returned int and could fail with
 * -EBUSY when the dentry still had busy children/mounts; from 3.18 it returns
 * void and always succeeds (busy children are handled by the shrink).  vcachefs
 * only calls it on a regular-file dentry (no children), so the pre-3.18 return
 * is always 0 here; wrap both forms in a void helper.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
static inline void vcf_d_invalidate(struct dentry *dentry)
{
	(void)d_invalidate(dentry);
}
#else
static inline void vcf_d_invalidate(struct dentry *dentry)
{
	d_invalidate(dentry);
}
#endif

/*
 * Lower-inode mtime/ctime read, normalised to (sec, nsec) scalars across the
 * accessor split: the inode_get_*time() wrappers landed in 6.6 (commit
 * 077c212f0344); before that the stamp lives in i_mtime/i_ctime directly
 * (struct timespec64 from 5.6, struct timespec earlier — both expose tv_sec /
 * tv_nsec, so the field read is uniform and we never name timespec64, which is
 * absent on 3.10).  Used by revalidate-on-open to detect an out-of-band change
 * to the lower file.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static inline void vcf_inode_mtime(struct inode *i, s64 *sec, long *nsec)
{
	struct timespec64 t = inode_get_mtime(i);

	*sec = t.tv_sec;
	*nsec = t.tv_nsec;
}
static inline void vcf_inode_ctime(struct inode *i, s64 *sec, long *nsec)
{
	struct timespec64 t = inode_get_ctime(i);

	*sec = t.tv_sec;
	*nsec = t.tv_nsec;
}
#else
static inline void vcf_inode_mtime(struct inode *i, s64 *sec, long *nsec)
{
	*sec = i->i_mtime.tv_sec;
	*nsec = i->i_mtime.tv_nsec;
}
static inline void vcf_inode_ctime(struct inode *i, s64 *sec, long *nsec)
{
	*sec = i->i_ctime.tv_sec;
	*nsec = i->i_ctime.tv_nsec;
}
#endif

/*
 * ------------------------------------------------------------------------
 * Writable-passthrough ("-o writable") cross-kernel shims.
 *
 * Only compiled when VCACHEFS_WRITE is set (kernels >= 4.9; vcachefs.h defines
 * it BEFORE including this header).  The write inode ops
 * (create/mkdir/symlink/rename/setattr) gained a leading idmap/userns parameter,
 * and the lower-fs VFS helpers they call gained the matching leading argument,
 * over three bands:
 *   >= 6.3      struct mnt_idmap *      (mnt_idmap(mnt))
 *   5.12 - 6.2  struct user_namespace * (mnt_user_ns(mnt))
 *   < 5.12      (no such argument)
 * These shims absorb the difference so one op body serves all three ABIs.
 *
 * Gated on LINUX_VERSION_CODE (NOT VCACHEFS_WRITE) because every .c includes
 * this header before vcachefs.h, i.e. before VCACHEFS_WRITE is defined.  The
 * guard value is identical to vcachefs.h's VCACHEFS_WRITE gate (>= 4.9), so the
 * shims exist exactly when the writable ops that use them are compiled; below
 * 4.9 they are absent (and vfs_rename's positional form here would not even
 * match the pre-3.15 prototype).
 * ------------------------------------------------------------------------
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
typedef struct mnt_idmap *vcf_idmap_t;
#define VCF_IOP_IDMAP_PARAM	struct mnt_idmap *idmap,
#define vcf_mnt_idmap(mnt)	mnt_idmap(mnt)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
typedef struct user_namespace *vcf_idmap_t;
#define VCF_IOP_IDMAP_PARAM	struct user_namespace *idmap,
#define vcf_mnt_idmap(mnt)	mnt_user_ns(mnt)
#else
typedef int vcf_idmap_t;		/* placeholder; the helpers below ignore it */
#define VCF_IOP_IDMAP_PARAM		/* no leading inode-op parameter */
#define vcf_mnt_idmap(mnt)	0
#endif

/*
 * Lower-fs mutation helpers.  On >= 5.12 they take the idmap/userns leading
 * argument; below that they don't.  The `idm` argument is still accepted (and
 * discarded) on < 5.12 so every call site passes it uniformly.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define vcf_vfs_create(idm, dir, de, mode, excl) vfs_create((idm), (dir), (de), (mode), (excl))
#define vcf_vfs_mkdir(idm, dir, de, mode)	 vfs_mkdir((idm), (dir), (de), (mode))
#define vcf_vfs_rmdir(idm, dir, de)		 vfs_rmdir((idm), (dir), (de))
#define vcf_vfs_unlink(idm, dir, de, deleg)	 vfs_unlink((idm), (dir), (de), (deleg))
#define vcf_vfs_symlink(idm, dir, de, name)	 vfs_symlink((idm), (dir), (de), (name))
#define vcf_notify_change(idm, de, attr, deleg)	 notify_change((idm), (de), (attr), (deleg))
#define vcf_setattr_prepare(idm, de, attr)	 setattr_prepare((idm), (de), (attr))
/* Lower-fs xattr forwarders (the idmap/userns leading arg appeared with the
 * idmapped-mount xattr API).  get takes no idmap in any era, so it is called
 * directly at the site; set/remove do. */
#define vcf_vfs_getxattr(idm, de, name, val, sz) \
	vfs_getxattr((idm), (de), (name), (val), (sz))
#define vcf_vfs_setxattr(idm, de, name, val, sz, fl) \
	vfs_setxattr((idm), (de), (name), (val), (sz), (fl))
#define vcf_vfs_removexattr(idm, de, name)	 vfs_removexattr((idm), (de), (name))
#else
#define vcf_vfs_create(idm, dir, de, mode, excl) vfs_create((dir), (de), (mode), (excl))
#define vcf_vfs_mkdir(idm, dir, de, mode)	 vfs_mkdir((dir), (de), (mode))
#define vcf_vfs_rmdir(idm, dir, de)		 vfs_rmdir((dir), (de))
#define vcf_vfs_unlink(idm, dir, de, deleg)	 vfs_unlink((dir), (de), (deleg))
#define vcf_vfs_symlink(idm, dir, de, name)	 vfs_symlink((dir), (de), (name))
#define vcf_notify_change(idm, de, attr, deleg)	 notify_change((de), (attr), (deleg))
#define vcf_setattr_prepare(idm, de, attr)	 setattr_prepare((de), (attr))
#define vcf_vfs_getxattr(idm, de, name, val, sz) \
	vfs_getxattr((de), (name), (val), (sz))
#define vcf_vfs_setxattr(idm, de, name, val, sz, fl) \
	vfs_setxattr((de), (name), (val), (sz), (fl))
#define vcf_vfs_removexattr(idm, de, name)	 vfs_removexattr((de), (name))
#endif

/*
 * vfs_rename(): a single struct renamedata * from 5.12 (whose idmap/userns field
 * was renamed in 6.3); the classic positional 6-arg form (with a delegated-inode
 * slot and flags) below that.  vcachefs never uses delegated-inode breaking, so
 * pass NULL.
 */
static inline int vcf_vfs_rename(vcf_idmap_t idm,
				  struct inode *old_dir, struct dentry *old_de,
				  struct inode *new_dir, struct dentry *new_de,
				  unsigned int flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	struct renamedata rd;

	memset(&rd, 0, sizeof(rd));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rd.old_mnt_idmap  = idm;
	rd.new_mnt_idmap  = idm;
#else
	rd.old_mnt_userns = idm;
	rd.new_mnt_userns = idm;
#endif
	rd.old_dir	  = old_dir;
	rd.old_dentry	  = old_de;
	rd.new_dir	  = new_dir;
	rd.new_dentry	  = new_de;
	rd.flags	  = flags;
	return vfs_rename(&rd);
#else
	(void)idm;
	return vfs_rename(old_dir, old_de, new_dir, new_de, NULL, flags);
#endif
}

/*
 * vfs_iter_read()/vfs_iter_write() gained a trailing rwf_t flags argument in
 * 4.13; before that the call took no flags.  We always pass 0 (no special I/O
 * flags).  Override with AREV_OLD_VFS_ITER if a <4.13 distro kernel backported
 * the flags argument (or AREV_NEW_VFS_ITER for the reverse).
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) || defined(AREV_NEW_VFS_ITER)) \
	&& !defined(AREV_OLD_VFS_ITER)
#define vcf_vfs_iter_read(f, it, pos)	vfs_iter_read((f), (it), (pos), 0)
#define vcf_vfs_iter_write(f, it, pos)	vfs_iter_write((f), (it), (pos), 0)
#else
#define vcf_vfs_iter_read(f, it, pos)	vfs_iter_read((f), (it), (pos))
#define vcf_vfs_iter_write(f, it, pos)	vfs_iter_write((f), (it), (pos))
#endif

/* vma_set_file() (balanced vm_file swap) arrived in 5.13; open-code it below. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#define vcf_vma_set_file(vma, file)	vma_set_file((vma), (file))
#else
static inline void vcf_vma_set_file(struct vm_area_struct *vma,
				     struct file *file)
{
	get_file(file);
	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = file;
}
#endif

/*
 * call_mmap() helper for f_op->mmap arrived in the 4.x series; call it directly
 * on kernels old enough to predate the wrapper (it is a plain forwarder there).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#define vcf_call_mmap(file, vma)	call_mmap((file), (vma))
#else
#define vcf_call_mmap(file, vma)	((file)->f_op->mmap((file), (vma)))
#endif

#endif /* LINUX_VERSION_CODE >= 4.9 (writable-passthrough shims) */

#endif /* _VCACHEFS_COMPAT_H */
