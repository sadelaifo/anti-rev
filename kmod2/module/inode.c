// SPDX-License-Identifier: GPL-2.0
/*
 * vcachefs inode ops: directory lookup proxied to the lower (.enc/) tree, and
 * iget5 caching keyed on the lower dentry so the same path always yields one
 * vcachefs inode — and therefore one shared page cache — across processes.
 */
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/sched.h>	/* task_struct — current_cred() derefs current on 3.10 */
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/slab.h>	/* kmalloc/kfree in the <4.2 symlink shim (not transitive on 3.10) */
#include <linux/uaccess.h>	/* KERNEL_DS/get_fs/set_fs for the <4.5 symlink shim */
#include <linux/version.h>

#include "compat.h"
#include "vcachefs.h"
#include "obfstr_k.h"

static int vcachefs_inode_test(struct inode *inode, void *data)
{
	return VCACHEFS_I(inode)->lower_path.dentry == (struct dentry *)data;
}

static int vcachefs_inode_set(struct inode *inode, void *data)
{
	struct dentry *lower_dentry = data;
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	struct vcachefs_sb_info *sbi = VCACHEFS_SB(inode->i_sb);

	ii->lower_path.dentry = dget(lower_dentry);
	ii->lower_path.mnt = mntget(sbi->lower_root.mnt);
	inode->i_ino = d_inode(lower_dentry)->i_ino;
	return 0;
}

/* Open the lower file, sniff the ANTREV01 trailer, decide the inode's mode.
 * Returns the plaintext (logical) size in *plain_len.  Only for regular files.
 */
static int vcachefs_classify(struct inode *inode, struct dentry *lower_dentry,
			      loff_t *plain_len)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	struct vcachefs_sb_info *sbi = VCACHEFS_SB(inode->i_sb);
	struct inode *lower_inode = d_inode(lower_dentry);
	struct file *lower_file;
	int magic;

	lower_file = dentry_open(&ii->lower_path, O_RDONLY, current_cred());
	if (IS_ERR(lower_file))
		return PTR_ERR(lower_file);

	magic = vcachefs_has_magic(lower_file);
	if (magic < 0) {
		fput(lower_file);
		return magic;
	}

	if (magic) {
		loff_t sz = i_size_read(lower_inode);
		loff_t clen, sig_off;
		u32 sig_len;
		int ps;
		char obf[32];	/* VCF_OBF scratch for the diagnostics below */

		/* An optional per-exe signature is APPENDED after the container;
		 * find the real container size first so every downstream size
		 * calc excludes the sig section. */
		ps = vcachefs_probe_sig(lower_file, sz, &clen, &sig_off, &sig_len);
		fput(lower_file);
		if (ps < 0) {
			/* "vcachefs: classify" — obfuscated so `strings` on the
			 * release .ko shows no self-documenting diagnostic text. */
			pr_err("%s name=%s err=%d sz=%lld\n",
			       VCF_OBF(obf,
				0x21, 0x2d, 0x20, 0x1b, 0x1b, 0x0f, 0x0b, 0x17,
				0x25, 0x36, 0x6a, 0x6c, 0x5a, 0x41, 0x46, 0x45,
				0x41, 0xa7),
			       lower_dentry->d_name.name, ps, (long long)sz);
			return ps;
		}
		/* key-in-.ko: the AES key is compiled into the module, NOT appended
		 * to each file, so a container is just [magic][iv][tag][ct] with no
		 * key trailer.  A header-magic file of at least HDR bytes is a
		 * decryptable container; plain_len = container - HDR. */
		if (clen < ANTREV_HDR_LEN) {
			/* "vcachefs: classify too-small" — obfuscated; generic
			 * field labels below reveal nothing about the format. */
			pr_err("%s name=%s err=%d sz=%lld c=%lld o=%lld n=%u\n",
			       VCF_OBF(obf,
				0x21, 0x2d, 0x20, 0x1b, 0x1b, 0x0f, 0x0b, 0x17,
				0x25, 0x36, 0x6a, 0x6c, 0x5a, 0x41, 0x46, 0x45,
				0x41, 0xa7, 0xf1, 0xbc, 0xac, 0x95, 0xd0, 0x87,
				0x82, 0x87, 0xf5, 0xfc),
			       lower_dentry->d_name.name, ps,
			       (long long)sz, (long long)clen,
			       (long long)sig_off, sig_len);
			return -EIO;
		}
		ii->encrypted = true;
		ii->open_ok = true;
		ii->container_len = clen;
		ii->has_sig = (ps == 1);
		ii->authz_sig = 0;		/* verified lazily by the gate */
		*plain_len = clen - ANTREV_HDR_LEN - ANTREV_TRAILER_LEN;
		return 0;
	}

	fput(lower_file);
	ii->container_len = i_size_read(lower_inode);	/* no sig on non-ANTREV01 */
	ii->has_sig = false;
	ii->authz_sig = 0;
	if (sbi->pass_nonelf || sbi->writable ||
	    vcachefs_ext_whitelisted(sbi, lower_dentry->d_name.name)) {
		/* Plaintext passthrough: an explicit-extension match, (with the
		 * `passdata` mount option) any non-ANTREV01 file, or any non-magic
		 * file on a `writable` mount (the app's own plaintext scratch must
		 * be readable back).  These are not secret and are never gated.
		 */
		ii->encrypted = false;
		ii->open_ok = true;
		*plain_len = i_size_read(lower_inode);
	} else {
		/* strict mode: present but unreadable */
		ii->encrypted = false;
		ii->open_ok = false;
		*plain_len = 0;
	}
	return 0;
}

#ifdef VCACHEFS_WRITE
/*
 * Re-run classification against the CURRENT lower content.  Used by the writable
 * mount's refresh-on-write-close (vcachefs_refresh_after_write in file.c) so a
 * file replaced through the mount — e.g. `cp newver.enc bin/FOO` — is re-sniffed
 * (encrypted vs plaintext, new size / container_len / signature) and picked up
 * live without a remount or vcache-replace.  The caller holds ii->plain_lock and
 * has already dropped the stale decrypt buffer, so re-setting ii->encrypted etc.
 * here cannot race a reader.
 */
int vcachefs_reclassify(struct inode *inode, loff_t *plain_len)
{
	return vcachefs_classify(inode, VCACHEFS_I(inode)->lower_path.dentry,
				 plain_len);
}
#endif

struct inode *vcachefs_iget(struct super_block *sb, struct dentry *lower_dentry)
{
	struct inode *lower_inode = d_inode(lower_dentry);
	struct vcachefs_inode_info *ii;
	struct inode *inode;
	loff_t plain_len = 0;
	int err;

	inode = iget5_locked(sb, lower_inode->i_ino,
			     vcachefs_inode_test, vcachefs_inode_set,
			     lower_dentry);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ii = VCACHEFS_I(inode);

	inode->i_mode = lower_inode->i_mode;
	inode->i_uid = lower_inode->i_uid;
	inode->i_gid = lower_inode->i_gid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	inode_set_atime_to_ts(inode, inode_get_atime(lower_inode));
	inode_set_mtime_to_ts(inode, inode_get_mtime(lower_inode));
	inode_set_ctime_to_ts(inode, inode_get_ctime(lower_inode));
#else
	inode->i_atime = lower_inode->i_atime;
	inode->i_mtime = lower_inode->i_mtime;
	inode->i_ctime = lower_inode->i_ctime;
#endif

	if (S_ISDIR(lower_inode->i_mode)) {
#ifdef VCACHEFS_WRITE
		inode->i_op = VCACHEFS_SB(sb)->writable ?
			      &vcachefs_dir_iops_rw : &vcachefs_dir_iops;
#else
		inode->i_op = &vcachefs_dir_iops;
#endif
		inode->i_fop = &vcachefs_dir_fops;
		set_nlink(inode, lower_inode->i_nlink);
		i_size_write(inode, 0);
	} else if (S_ISREG(lower_inode->i_mode)) {
		err = vcachefs_classify(inode, lower_dentry, &plain_len);
		if (err) {
			iget_failed(inode);
			return ERR_PTR(err);
		}
#ifdef VCACHEFS_WRITE
		inode->i_op = VCACHEFS_SB(sb)->writable ?
			      &vcachefs_file_iops_rw : &vcachefs_file_iops;
#else
		inode->i_op = &vcachefs_file_iops;
#endif
		inode->i_fop = &vcachefs_file_fops;
		inode->i_mapping->a_ops = &vcachefs_aops;
		ii->plain_len = plain_len;
		i_size_write(inode, plain_len);
	} else if (S_ISLNK(lower_inode->i_mode)) {
		/* Symlinks are mirrored verbatim by the packer (SONAME chains,
		 * version links).  Proxy get_link to the lower symlink so they
		 * resolve through the mount; size is the link-target length.
		 */
		inode->i_op = &vcachefs_symlink_iops;
		i_size_write(inode, i_size_read(lower_inode));
	} else {
		/* devices/sockets/fifos not supported under an vcachefs mount */
		iget_failed(inode);
		return ERR_PTR(-EINVAL);
	}

	unlock_new_inode(inode);
	return inode;
}

static struct dentry *vcachefs_lookup(struct inode *dir, struct dentry *dentry,
				       unsigned int flags)
{
	struct vcachefs_inode_info *dii = VCACHEFS_I(dir);
	struct dentry *lower_dir = dii->lower_path.dentry;
	struct dentry *lower;
	struct inode *inode;

	lower = lookup_one_len_unlocked(dentry->d_name.name, lower_dir,
					dentry->d_name.len);
	if (IS_ERR(lower))
		return ERR_CAST(lower);

	if (!d_really_is_positive(lower)) {
		dput(lower);
		d_add(dentry, NULL);	/* negative dentry */
		return NULL;
	}

	inode = vcachefs_iget(dir->i_sb, lower);
	dput(lower);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	d_add(dentry, inode);
	return NULL;
}

/*
 * getattr signature and generic_fillattr arity both shifted across releases:
 *   <4.11        getattr(vfsmount*, dentry*, stat)   generic_fillattr(inode, stat)
 *   4.11..5.11   getattr(path, ...)                  generic_fillattr(inode, stat)
 *   5.12..6.2    getattr(user_namespace*, path, ...) generic_fillattr(ns, inode, stat)
 *   6.3..6.5     getattr(mnt_idmap*, path, ...)      generic_fillattr(idmap, inode, stat)
 *   >=6.6        getattr(mnt_idmap*, path, ...)      generic_fillattr(idmap, mask, inode, stat)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define AREV_GETATTR_PROTO struct mnt_idmap *idmap, const struct path *path, \
			   struct kstat *stat, u32 request_mask, unsigned int flags
#define AREV_FILLATTR	generic_fillattr(idmap, request_mask, inode, stat)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define AREV_GETATTR_PROTO struct mnt_idmap *idmap, const struct path *path, \
			   struct kstat *stat, u32 request_mask, unsigned int flags
#define AREV_FILLATTR	generic_fillattr(idmap, inode, stat)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define AREV_GETATTR_PROTO struct user_namespace *mnt_userns, \
			   const struct path *path, struct kstat *stat, \
			   u32 request_mask, unsigned int flags
#define AREV_FILLATTR	generic_fillattr(mnt_userns, inode, stat)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define AREV_GETATTR_PROTO const struct path *path, struct kstat *stat, \
			   u32 request_mask, unsigned int flags
#define AREV_FILLATTR	generic_fillattr(inode, stat)
#else	/* < 4.11: getattr(vfsmount*, dentry*, stat) */
#define AREV_GETATTR_PROTO struct vfsmount *mnt, struct dentry *dentry, \
			   struct kstat *stat
#define AREV_FILLATTR	generic_fillattr(inode, stat)
#endif

static int vcachefs_getattr(AREV_GETATTR_PROTO)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	struct inode *inode = d_inode(path->dentry);
#else
	struct inode *inode = d_inode(dentry);	/* pre-4.11 getattr takes dentry */
#endif

	AREV_FILLATTR;
	/* report the plaintext (logical) size, never the ciphertext length */
	stat->size = i_size_read(inode);
	stat->blocks = (stat->size + 511) >> 9;

#ifdef VCACHEFS_WRITE
	/*
	 * On a writable mount a plaintext file is served directly from the lower
	 * file (no vcachefs-side cache), so its size changes live as the app
	 * writes.  Report the lower inode's current size so stat() stays accurate
	 * without round-tripping through our (unused) cached i_size.
	 */
	if (VCACHEFS_SB(inode->i_sb)->writable &&
	    !VCACHEFS_I(inode)->encrypted) {
		loff_t sz = i_size_read(vcachefs_lower_inode(inode));

		stat->size = sz;
		stat->blocks = (sz + 511) >> 9;
		return 0;
	}
#endif

	/*
	 * Under gate_passthrough_cipher an unauthorized caller is served the
	 * lower .enc/ ciphertext with the key TRAILER stripped — i.e. the first
	 * (lower_size - TRAILER) bytes.  Report THAT length to such callers so
	 * size-honoring copiers (cp via copy_file_range/sendfile) read the whole
	 * keyless container and stop before the (already withheld) trailer.
	 * getattr runs in the caller's context, so this varies per reader while
	 * the shared inode keeps reporting plaintext size to authorized ones.
	 */
	if (VCACHEFS_I(inode)->encrypted &&
	    vcachefs_gate_passthrough_cipher() &&
	    !vcachefs_task_authorized()) {
		loff_t csz = VCACHEFS_I(inode)->container_len -
			     ANTREV_TRAILER_LEN;

		if (csz < 0)
			csz = 0;
		stat->size = csz;
		stat->blocks = (csz + 511) >> 9;
	}
	return 0;
}

const struct inode_operations vcachefs_dir_iops = {
	.lookup		= vcachefs_lookup,
	.getattr	= vcachefs_getattr,
};

const struct inode_operations vcachefs_file_iops = {
	.getattr	= vcachefs_getattr,
};

#ifdef VCACHEFS_WRITE
/*
 * ------------------------------------------------------------------------
 * Writable passthrough inode ops (mount option `writable`; kernel >= 4.9, with
 * the leading idmap/userns arg absorbed by the compat.h shims across bands).
 *
 * All of these forward the mutation verbatim to the LOWER (.enc/) tree, which
 * is the single source of truth — there is NO encrypt-on-write.  Writes are
 * UNGATED: the only precondition is that the mount is `writable` (else -EROFS,
 * via vcachefs_may_write).  Any caller — the app, an operator's cp/scp/touch, a
 * file-manager drag — may create, overwrite, rename, truncate or delete ANY
 * file, ENCRYPTED ones included, so a stopped subsystem's binary (or a lib it
 * links to) can be swapped for another container.  This does NOT weaken secrecy:
 * the sole gate is on *reading decrypted content* (the encrypted-read path in
 * file.c), and these ops only move RAW bytes (no decrypt, no key).  A file
 * replaced through the mount is picked up live: on close of the write fd the
 * inode is re-classified and its stale decrypt cache dropped (file.c's
 * vcachefs_refresh_after_write via vcachefs_reclassify).
 *
 * The lower directory dentry is pinned by the parent vcachefs inode's
 * ->lower_path, so these ops reach the (possibly overmounted/in-place-shadowed)
 * lower directly in-kernel — no path walk, works on a bare in-place mount.
 * ------------------------------------------------------------------------
 */

/* Refresh a vcachefs inode's cached attrs from its lower inode after a change. */
static void vcachefs_copy_attr(struct inode *inode, struct inode *lower)
{
	inode->i_mode = lower->i_mode;
	inode->i_uid  = lower->i_uid;
	inode->i_gid  = lower->i_gid;
	set_nlink(inode, lower->i_nlink);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	inode_set_atime_to_ts(inode, inode_get_atime(lower));
	inode_set_mtime_to_ts(inode, inode_get_mtime(lower));
	inode_set_ctime_to_ts(inode, inode_get_ctime(lower));
#else
	inode->i_atime = lower->i_atime;
	inode->i_mtime = lower->i_mtime;
	inode->i_ctime = lower->i_ctime;
#endif
	if (S_ISREG(lower->i_mode)) {
		loff_t sz = i_size_read(lower);

		i_size_write(inode, sz);
		VCACHEFS_I(inode)->plain_len = sz;
		VCACHEFS_I(inode)->container_len = sz;
	}
}

/*
 * Gate a mutation on a directory.  Writes are UNGATED on a writable mount: any
 * process (an operator's cp/scp/touch, a file-manager drag) may create/replace/
 * delete files in bin/lib — including encrypted ones, so a stopped subsystem's
 * binary or a lib it links to can be swapped for another container.  This does
 * NOT weaken secrecy: the ONLY gate is on *reading decrypted content* (the
 * encrypted-read path in file.c), and every write forwards RAW bytes to the
 * lower (no decrypt, no key).  A plaintext file written here is served verbatim;
 * an unsigned binary dropped in simply won't run — the writer's problem.
 */
static int vcachefs_may_write(struct inode *dir)
{
	if (!VCACHEFS_SB(dir->i_sb)->writable)
		return -EROFS;
	return 0;
}

static int vcachefs_create(VCF_IOP_IDMAP_PARAM struct inode *dir,
			    struct dentry *dentry, umode_t mode, bool excl)
{
	struct dentry *ldir = VCACHEFS_I(dir)->lower_path.dentry;
	struct inode *ldir_inode = d_inode(ldir);
	vcf_idmap_t lidmap __maybe_unused = vcachefs_lower_idmap(dir);
	struct dentry *lchild;
	struct inode *inode;
	int err;

	err = vcachefs_may_write(dir);
	if (err)
		return err;

	inode_lock_nested(ldir_inode, I_MUTEX_PARENT);
	lchild = lookup_one_len(dentry->d_name.name, ldir, dentry->d_name.len);
	if (IS_ERR(lchild)) {
		inode_unlock(ldir_inode);
		return PTR_ERR(lchild);
	}
	err = vcf_vfs_create(lidmap, ldir_inode, lchild, mode, excl);
	inode_unlock(ldir_inode);
	if (err) {
		dput(lchild);
		return err;
	}

	inode = vcachefs_iget(dir->i_sb, lchild);
	dput(lchild);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);
	vcachefs_copy_attr(dir, ldir_inode);		/* dir times bumped */
	return 0;
}

static int vcachefs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct dentry *ldir = VCACHEFS_I(dir)->lower_path.dentry;
	struct inode *ldir_inode = d_inode(ldir);
	vcf_idmap_t lidmap __maybe_unused = vcachefs_lower_idmap(dir);
	struct inode *victim = d_inode(dentry);
	struct dentry *lchild;
	int err;

	err = vcachefs_may_write(dir);
	if (err)
		return err;

	inode_lock_nested(ldir_inode, I_MUTEX_PARENT);
	lchild = lookup_one_len(dentry->d_name.name, ldir, dentry->d_name.len);
	if (IS_ERR(lchild)) {
		inode_unlock(ldir_inode);
		return PTR_ERR(lchild);
	}
	err = vcf_vfs_unlink(lidmap, ldir_inode, lchild, NULL);
	dput(lchild);
	inode_unlock(ldir_inode);
	if (!err && victim) {
		struct inode *lvictim = d_inode(VCACHEFS_I(victim)->lower_path.dentry);

		set_nlink(victim, lvictim->i_nlink);
		vcachefs_copy_attr(dir, ldir_inode);
	}
	return err;
}

static int vcachefs_mkdir(VCF_IOP_IDMAP_PARAM struct inode *dir,
			   struct dentry *dentry, umode_t mode)
{
	struct dentry *ldir = VCACHEFS_I(dir)->lower_path.dentry;
	struct inode *ldir_inode = d_inode(ldir);
	vcf_idmap_t lidmap __maybe_unused = vcachefs_lower_idmap(dir);
	struct dentry *lchild;
	struct inode *inode;
	int err;

	err = vcachefs_may_write(dir);
	if (err)
		return err;

	inode_lock_nested(ldir_inode, I_MUTEX_PARENT);
	lchild = lookup_one_len(dentry->d_name.name, ldir, dentry->d_name.len);
	if (IS_ERR(lchild)) {
		inode_unlock(ldir_inode);
		return PTR_ERR(lchild);
	}
	err = vcf_vfs_mkdir(lidmap, ldir_inode, lchild, mode);
	if (err) {
		inode_unlock(ldir_inode);
		dput(lchild);
		return err;
	}
	/* some filesystems leave the dentry negative after a successful mkdir */
	if (!d_really_is_positive(lchild)) {
		dput(lchild);
		lchild = lookup_one_len(dentry->d_name.name, ldir,
					dentry->d_name.len);
		if (IS_ERR(lchild)) {
			inode_unlock(ldir_inode);
			return PTR_ERR(lchild);
		}
	}
	inode_unlock(ldir_inode);

	inode = vcachefs_iget(dir->i_sb, lchild);
	dput(lchild);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);
	set_nlink(dir, ldir_inode->i_nlink);
	return 0;
}

static int vcachefs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *ldir = VCACHEFS_I(dir)->lower_path.dentry;
	struct inode *ldir_inode = d_inode(ldir);
	vcf_idmap_t lidmap __maybe_unused = vcachefs_lower_idmap(dir);
	struct inode *victim = d_inode(dentry);
	struct dentry *lchild;
	int err;

	err = vcachefs_may_write(dir);
	if (err)
		return err;

	inode_lock_nested(ldir_inode, I_MUTEX_PARENT);
	lchild = lookup_one_len(dentry->d_name.name, ldir, dentry->d_name.len);
	if (IS_ERR(lchild)) {
		inode_unlock(ldir_inode);
		return PTR_ERR(lchild);
	}
	err = vcf_vfs_rmdir(lidmap, ldir_inode, lchild);
	dput(lchild);
	inode_unlock(ldir_inode);
	if (!err) {
		if (victim)
			clear_nlink(victim);
		set_nlink(dir, ldir_inode->i_nlink);
	}
	return err;
}

static int vcachefs_symlink(VCF_IOP_IDMAP_PARAM struct inode *dir,
			     struct dentry *dentry, const char *symname)
{
	struct dentry *ldir = VCACHEFS_I(dir)->lower_path.dentry;
	struct inode *ldir_inode = d_inode(ldir);
	vcf_idmap_t lidmap __maybe_unused = vcachefs_lower_idmap(dir);
	struct dentry *lchild;
	struct inode *inode;
	int err;

	err = vcachefs_may_write(dir);
	if (err)
		return err;

	inode_lock_nested(ldir_inode, I_MUTEX_PARENT);
	lchild = lookup_one_len(dentry->d_name.name, ldir, dentry->d_name.len);
	if (IS_ERR(lchild)) {
		inode_unlock(ldir_inode);
		return PTR_ERR(lchild);
	}
	err = vcf_vfs_symlink(lidmap, ldir_inode, lchild, symname);
	inode_unlock(ldir_inode);
	if (err) {
		dput(lchild);
		return err;
	}
	inode = vcachefs_iget(dir->i_sb, lchild);
	dput(lchild);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);
	return 0;
}

static int vcachefs_rename(VCF_IOP_IDMAP_PARAM
			    struct inode *old_dir, struct dentry *old_dentry,
			    struct inode *new_dir, struct dentry *new_dentry,
			    unsigned int flags)
{
	struct dentry *lold_dir = VCACHEFS_I(old_dir)->lower_path.dentry;
	struct dentry *lnew_dir = VCACHEFS_I(new_dir)->lower_path.dentry;
	vcf_idmap_t lidmap __maybe_unused = vcachefs_lower_idmap(old_dir);
	struct dentry *lold = NULL, *lnew = NULL, *trap;
	int err;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EINVAL;
	err = vcachefs_may_write(old_dir);
	if (err)
		return err;
	err = vcachefs_may_write(new_dir);
	if (err)
		return err;

	trap = lock_rename(lnew_dir, lold_dir);

	lold = lookup_one_len(old_dentry->d_name.name, lold_dir,
			      old_dentry->d_name.len);
	if (IS_ERR(lold)) {
		err = PTR_ERR(lold);
		lold = NULL;
		goto unlock;
	}
	lnew = lookup_one_len(new_dentry->d_name.name, lnew_dir,
			      new_dentry->d_name.len);
	if (IS_ERR(lnew)) {
		err = PTR_ERR(lnew);
		lnew = NULL;
		goto unlock;
	}
	if (!d_really_is_positive(lold)) {	/* source vanished */
		err = -ENOENT;
		goto unlock;
	}
	if (trap == lold) {			/* lower dir is an ancestor of src */
		err = -EINVAL;
		goto unlock;
	}
	if (trap == lnew) {			/* lower dir is an ancestor of dst */
		err = -ENOTEMPTY;
		goto unlock;
	}

	/* VFS d_move()s our upper dentries on success.  vcf_vfs_rename packs the
	 * renamedata (>= 5.12) or calls the positional 6-arg form (< 5.12). */
	err = vcf_vfs_rename(lidmap, d_inode(lold_dir), lold,
			     d_inode(lnew_dir), lnew, flags);
unlock:
	dput(lold);
	dput(lnew);
	unlock_rename(lnew_dir, lold_dir);
	return err;
}

static int vcachefs_setattr(VCF_IOP_IDMAP_PARAM struct dentry *dentry,
			     struct iattr *ia)
{
	struct inode *inode = d_inode(dentry);
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	struct dentry *lower = ii->lower_path.dentry;
	struct inode *lower_inode = d_inode(lower);
	vcf_idmap_t lidmap __maybe_unused = vcachefs_lower_idmap(inode);
	struct iattr lia;
	int err;

	if (!VCACHEFS_SB(inode->i_sb)->writable)
		return -EROFS;
	/* writes ungated: truncate/chmod allowed for any caller, encrypted files
	 * included (replacing a shipped binary implies truncating/overwriting it). */

	err = vcf_setattr_prepare(idmap, dentry, ia);
	if (err)
		return err;

	lia = *ia;
	/* ATTR_FILE pins the UPPER struct file; the lower op must not deref it */
	lia.ia_valid &= ~ATTR_FILE;

	inode_lock(lower_inode);
	err = vcf_notify_change(lidmap, lower, &lia, NULL);
	inode_unlock(lower_inode);
	if (!err)
		vcachefs_copy_attr(inode, lower_inode);
	return err;
}

const struct inode_operations vcachefs_dir_iops_rw = {
	.lookup		= vcachefs_lookup,
	.getattr	= vcachefs_getattr,
	.create		= vcachefs_create,
	.unlink		= vcachefs_unlink,
	.mkdir		= vcachefs_mkdir,
	.rmdir		= vcachefs_rmdir,
	.symlink	= vcachefs_symlink,
	.rename		= vcachefs_rename,
	.setattr	= vcachefs_setattr,
};

const struct inode_operations vcachefs_file_iops_rw = {
	.getattr	= vcachefs_getattr,
	.setattr	= vcachefs_setattr,
};
#endif /* VCACHEFS_WRITE */

/*
 * Follow a symlink by proxying to the lower (.enc/) symlink's body.  The packer
 * mirrors symlinks verbatim, so the target string is identical to the original
 * — relative SONAME chains resolve through the mount, absolute / out-of-tree
 * targets behave exactly as on the underlying fs (i.e. they may dangle, same as
 * without vcachefs).  vfs_get_link() arranges the cleanup via @done.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
static const char *vcachefs_get_link(struct dentry *dentry, struct inode *inode,
				      struct delayed_call *done)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);

	if (!dentry)			/* RCU lookup — fall back to ref-walk */
		return ERR_PTR(-ECHILD);
	return vfs_get_link(ii->lower_path.dentry, done);
}

const struct inode_operations vcachefs_symlink_iops = {
	.get_link	= vcachefs_get_link,
	.getattr	= vcachefs_getattr,
};
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
/*
 * Pre-4.2 kernels (e.g. RHEL/CentOS 7 3.10) have neither get_link nor
 * vfs_get_link/delayed_call — they use the older follow_link/put_link pair with
 * a struct nameidata and an nd_set_link()/cookie handshake.  (Kernels 4.2..4.4
 * use yet another form — a cookie-returning follow_link with no nameidata — but
 * they are not a target; the #error below flags them rather than miscompiling.)
 * Proxy the lower (.enc/) symlink's body by calling its own ->readlink under
 * KERNEL_DS (the
 * ecryptfs-on-3.10 idiom: the lower fs writes the target into our kernel buffer
 * as if it were a userspace one), then hand that string to the resolver.  The
 * buffer is the cookie put_link frees.
 */
static void *vcachefs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(dentry->d_inode);
	struct dentry *lower = ii->lower_path.dentry;
	struct inode *lower_inode = lower->d_inode;
	mm_segment_t old_fs;
	char *buf;
	int rc;

	if (!lower_inode->i_op || !lower_inode->i_op->readlink)
		return ERR_PTR(-EINVAL);

	buf = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = lower_inode->i_op->readlink(lower, (char __user *)buf, PATH_MAX);
	set_fs(old_fs);

	if (rc < 0) {
		kfree(buf);
		return ERR_PTR(rc);
	}
	buf[rc] = '\0';
	nd_set_link(nd, buf);
	return buf;			/* cookie -> put_link */
}

static void vcachefs_put_link(struct dentry *dentry, struct nameidata *nd,
			      void *cookie)
{
	kfree(cookie);
}

const struct inode_operations vcachefs_symlink_iops = {
	.readlink	= generic_readlink,
	.follow_link	= vcachefs_follow_link,
	.put_link	= vcachefs_put_link,
	.getattr	= vcachefs_getattr,
};
#else
#error "vcachefs symlink shim: kernels 4.2-4.4 use the cookie follow_link form; not a supported target"
#endif
