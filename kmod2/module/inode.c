// SPDX-License-Identifier: GPL-2.0
/*
 * antirevfs inode ops: directory lookup proxied to the lower (.enc/) tree, and
 * iget5 caching keyed on the lower dentry so the same path always yields one
 * antirevfs inode — and therefore one shared page cache — across processes.
 */
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/version.h>

#include "compat.h"
#include "antirevfs.h"

static int antirevfs_inode_test(struct inode *inode, void *data)
{
	return ANTIREVFS_I(inode)->lower_path.dentry == (struct dentry *)data;
}

static int antirevfs_inode_set(struct inode *inode, void *data)
{
	struct dentry *lower_dentry = data;
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);
	struct antirevfs_sb_info *sbi = ANTIREVFS_SB(inode->i_sb);

	ii->lower_path.dentry = dget(lower_dentry);
	ii->lower_path.mnt = mntget(sbi->lower_root.mnt);
	inode->i_ino = d_inode(lower_dentry)->i_ino;
	return 0;
}

/* Open the lower file, sniff the ANTREV01 trailer, decide the inode's mode.
 * Returns the plaintext (logical) size in *plain_len.  Only for regular files.
 */
static int antirevfs_classify(struct inode *inode, struct dentry *lower_dentry,
			      loff_t *plain_len)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);
	struct antirevfs_sb_info *sbi = ANTIREVFS_SB(inode->i_sb);
	struct inode *lower_inode = d_inode(lower_dentry);
	struct file *lower_file;
	int magic;

	lower_file = dentry_open(&ii->lower_path, O_RDONLY, current_cred());
	if (IS_ERR(lower_file))
		return PTR_ERR(lower_file);

	magic = antirevfs_has_magic(lower_file);
	fput(lower_file);
	if (magic < 0)
		return magic;

	if (magic) {
		if (i_size_read(lower_inode) < ANTREV_HDR_LEN)
			return -EIO;
		ii->encrypted = true;
		ii->open_ok = true;
		*plain_len = i_size_read(lower_inode) - ANTREV_HDR_LEN;
	} else if (sbi->pass_nonelf ||
		   antirevfs_ext_whitelisted(sbi, lower_dentry->d_name.name)) {
		/* Plaintext passthrough: an explicit-extension match, or (with
		 * the `passdata` mount option) any non-ANTREV01 file.  These are
		 * not secret and are never gated — read at full speed.
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

struct inode *antirevfs_iget(struct super_block *sb, struct dentry *lower_dentry)
{
	struct inode *lower_inode = d_inode(lower_dentry);
	struct antirevfs_inode_info *ii;
	struct inode *inode;
	loff_t plain_len = 0;
	int err;

	inode = iget5_locked(sb, lower_inode->i_ino,
			     antirevfs_inode_test, antirevfs_inode_set,
			     lower_dentry);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ii = ANTIREVFS_I(inode);

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
		inode->i_op = &antirevfs_dir_iops;
		inode->i_fop = &antirevfs_dir_fops;
		set_nlink(inode, lower_inode->i_nlink);
		i_size_write(inode, 0);
	} else if (S_ISREG(lower_inode->i_mode)) {
		err = antirevfs_classify(inode, lower_dentry, &plain_len);
		if (err) {
			iget_failed(inode);
			return ERR_PTR(err);
		}
		inode->i_op = &antirevfs_file_iops;
		inode->i_fop = &antirevfs_file_fops;
		inode->i_mapping->a_ops = &antirevfs_aops;
		ii->plain_len = plain_len;
		i_size_write(inode, plain_len);
	} else if (S_ISLNK(lower_inode->i_mode)) {
		/* Symlinks are mirrored verbatim by the packer (SONAME chains,
		 * version links).  Proxy get_link to the lower symlink so they
		 * resolve through the mount; size is the link-target length.
		 */
		inode->i_op = &antirevfs_symlink_iops;
		i_size_write(inode, i_size_read(lower_inode));
	} else {
		/* devices/sockets/fifos not supported under an antirevfs mount */
		iget_failed(inode);
		return ERR_PTR(-EINVAL);
	}

	unlock_new_inode(inode);
	return inode;
}

static struct dentry *antirevfs_lookup(struct inode *dir, struct dentry *dentry,
				       unsigned int flags)
{
	struct antirevfs_inode_info *dii = ANTIREVFS_I(dir);
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

	inode = antirevfs_iget(dir->i_sb, lower);
	dput(lower);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	d_add(dentry, inode);
	return NULL;
}

/*
 * getattr signature and generic_fillattr arity both shifted across releases:
 *   <5.12        getattr(path, ...)                  generic_fillattr(inode, stat)
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
#else
#define AREV_GETATTR_PROTO const struct path *path, struct kstat *stat, \
			   u32 request_mask, unsigned int flags
#define AREV_FILLATTR	generic_fillattr(inode, stat)
#endif

static int antirevfs_getattr(AREV_GETATTR_PROTO)
{
	struct inode *inode = d_inode(path->dentry);

	AREV_FILLATTR;
	/* report the plaintext (logical) size, never the ciphertext length */
	stat->size = i_size_read(inode);
	stat->blocks = (stat->size + 511) >> 9;

	/*
	 * Under gate_passthrough_cipher an unauthorized caller reads the lower
	 * .enc/ ciphertext (longer than the plaintext by the ANTREV01 header).
	 * Report THAT length to such callers so size-honoring copiers (cp via
	 * copy_file_range/sendfile) read the whole container, not a truncation.
	 * getattr runs in the caller's context, so this varies per reader while
	 * the shared inode keeps reporting plaintext size to authorized ones.
	 */
	if (ANTIREVFS_I(inode)->encrypted &&
	    antirevfs_gate_passthrough_cipher() &&
	    !antirevfs_task_authorized()) {
		loff_t csz = i_size_read(antirevfs_lower_inode(inode));

		stat->size = csz;
		stat->blocks = (csz + 511) >> 9;
	}
	return 0;
}

const struct inode_operations antirevfs_dir_iops = {
	.lookup		= antirevfs_lookup,
	.getattr	= antirevfs_getattr,
};

const struct inode_operations antirevfs_file_iops = {
	.getattr	= antirevfs_getattr,
};

/*
 * Follow a symlink by proxying to the lower (.enc/) symlink's body.  The packer
 * mirrors symlinks verbatim, so the target string is identical to the original
 * — relative SONAME chains resolve through the mount, absolute / out-of-tree
 * targets behave exactly as on the underlying fs (i.e. they may dangle, same as
 * without antirevfs).  vfs_get_link() arranges the cleanup via @done.
 */
static const char *antirevfs_get_link(struct dentry *dentry, struct inode *inode,
				      struct delayed_call *done)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);

	if (!dentry)			/* RCU lookup — fall back to ref-walk */
		return ERR_PTR(-ECHILD);
	return vfs_get_link(ii->lower_path.dentry, done);
}

const struct inode_operations antirevfs_symlink_iops = {
	.get_link	= antirevfs_get_link,
	.getattr	= antirevfs_getattr,
};
