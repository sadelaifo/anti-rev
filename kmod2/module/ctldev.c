// SPDX-License-Identifier: GPL-2.0
/*
 * ctldev.c — /dev/vcachefs control device for the qemu-user decrypt gate.
 *
 * Under qemu-user the kernel cannot tell which GUEST is running (every guest's
 * exe_file is qemu), so the emulator supplies the per-guest decision and asks
 * this device for what it needs — the key never leaves the kernel:
 *
 *   AREV_IOC_AUTHORIZE_FD(fd): verify a guest binary's vendor signature so qemu
 *       can decide whether the guest is authorized.
 *   AREV_IOC_OPEN_CIPHER(path): return the KEYLESS ciphertext of a vcachefs
 *       mount file as a fresh read-only fd, for the unauthorized-guest branch
 *       (authorized guests just read the mount and share the decrypted cache).
 *   AREV_IOC_INSTALL_CIPHER(path,data): write a ciphertext blob into the lower
 *       (.enc) store of a vcachefs mount so it is thereafter served DECRYPTED
 *       through the mount — the "drop a hot-patch at runtime" primitive for the
 *       in-place layover deployment, where the real lower dir is shadowed by
 *       the mount and only the kernel (which pinned the lower dentry) can write
 *       there.  Validates the FS_MAGIC header, never overwrites, unlinks a
 *       partial file on error.  Still keyless: the caller supplies ciphertext
 *       produced off-box with the project key; the AES key never leaves the .ko.
 *
 * All ioctls are gated on the caller being the genuine emulator / a trusted
 * installer (vcf_ctl_caller_ok(): whitelisted basename or a signed exe).
 * Opening the device is unrestricted (mode 0666); all enforcement is per-ioctl.
 *
 * NOTE: not yet built/tested on a real kernel.  The kernel-version-sensitive
 * spots are shmem_file_setup(), fdget/fd_install, kernel_write (via the compat.h
 * wrapper), and — for INSTALL_CIPHER — vfs_create()/vfs_unlink() (the leading
 * idmap/userns arg via compat.h VCF_IDMAP_ARG) + mnt_want_write(); confirm on
 * SLES 4.12 / mainline.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mount.h>	/* mnt_want_write / mnt_drop_write */
#include <linux/dcache.h>	/* d_hash_and_lookup / d_drop (negative-dentry flush) */
#include <linux/string.h>	/* strrchr / memcmp */
#include <linux/sched.h>	/* task_struct — current_cred() derefs current on 3.10 */
#include <linux/cred.h>
#include <linux/version.h>

#include "compat.h"
#include "vcachefs.h"
#include "arev_uapi.h"

/* AREV_IOC_AUTHORIZE_FD: verify the vendor signature of the file at `fd`.
 * fget/fput are used (not fdget/struct fd) — the struct fd layout changed in
 * recent kernels, whereas fget has been stable across the 4.12..6.8 range.
 *
 * vcf_verify_authorize_fd() (not vcf_verify_file_sig) covers the common case
 * where the guest binary is ENCRYPTED on the vcachefs mount: the fd qemu opened
 * is the mount's decrypted view (signature footer stripped), so the signature
 * must be read from the LOWER container, not the fd bytes. */
static long do_authorize_fd(unsigned long arg)
{
	struct file *f = fget((int)arg);
	bool ok;

	if (!f)
		return -EBADF;
	ok = vcf_verify_authorize_fd(f);
	fput(f);
	return ok ? 0 : -EACCES;
}

/*
 * AREV_IOC_OPEN_CIPHER: resolve a path under a vcachefs mount and return a new
 * read-only fd whose contents are the KEYLESS ciphertext (encrypted file: lower
 * container minus the key trailer) or the plaintext (non-secret passthrough
 * file).  Copies into a fresh shmem file so the caller gets a private,
 * seekable/mmapable fd that never exposes the key.
 */
static long do_open_cipher(unsigned long arg)
{
	struct arev_cipher_arg carg;
	char *pathbuf;
	struct path p;
	struct inode *inode;
	struct vcachefs_inode_info *ii;
	struct file *lf, *out;
	void *buf;
	loff_t rpos = 0, wpos = 0, outlen, remaining;
	int nfd;
	long ret;

	if (copy_from_user(&carg, (void __user *)arg, sizeof(carg)))
		return -EFAULT;
	if (carg.path_len == 0 || carg.path_len > AREV_PATH_MAX)
		return -EINVAL;

	pathbuf = kmalloc(carg.path_len, GFP_KERNEL);
	if (!pathbuf)
		return -ENOMEM;
	if (copy_from_user(pathbuf, (void __user *)(uintptr_t)carg.path,
			   carg.path_len)) {
		kfree(pathbuf);
		return -EFAULT;
	}
	pathbuf[carg.path_len - 1] = '\0';	/* force NUL-termination */

	ret = kern_path(pathbuf, LOOKUP_FOLLOW, &p);
	kfree(pathbuf);
	if (ret)
		return ret;

	inode = d_inode(p.dentry);
	if (inode->i_sb->s_magic != VCACHEFS_MAGIC) {
		ret = -EINVAL;			/* not a vcachefs file */
		goto put_path;
	}
	if (!S_ISREG(inode->i_mode)) {
		ret = -EISDIR;			/* dir/special: not a leak vector */
		goto put_path;
	}
	ii = VCACHEFS_I(inode);
	if (!ii->lower_path.dentry) {
		ret = -EINVAL;
		goto put_path;
	}

	lf = dentry_open(&ii->lower_path, O_RDONLY, current_cred());
	if (IS_ERR(lf)) {
		ret = PTR_ERR(lf);
		goto put_path;
	}

	if (ii->encrypted) {
		outlen = ii->container_len - ANTREV_TRAILER_LEN;
		if (outlen < 0) {
			ret = -EIO;
			goto put_lf;
		}
	} else {
		outlen = i_size_read(file_inode(lf));	/* plaintext, not secret */
	}

	out = shmem_file_setup("vcachefs", outlen, 0);
	if (IS_ERR(out)) {
		ret = PTR_ERR(out);
		goto put_lf;
	}
	/*
	 * shmem_file_setup() builds the file via alloc_file_pseudo(), which — unlike
	 * a normal open() through do_dentry_open() — does NOT set FMODE_LSEEK.  With
	 * that bit clear, vfs_llseek() returns -ESPIPE ("illegal seek"), so an
	 * unauthorized reader (objdump/less/…) fails its very first seek instead of
	 * cleanly reading the keyless container and reporting "file format not
	 * recognized".  The shmem file IS seekable (shmem_file_operations.llseek),
	 * so advertise it.  f_pos stays 0 — the ciphertext below is written with an
	 * explicit loff_t (&wpos), never touching out->f_pos.
	 */
	out->f_mode |= FMODE_LSEEK;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto put_out;
	}
	remaining = outlen;
	while (remaining > 0) {
		size_t chunk = remaining < PAGE_SIZE ? (size_t)remaining : PAGE_SIZE;
		ssize_t rn = vcf_kernel_read(lf, buf, chunk, &rpos);
		ssize_t wn;

		if (rn <= 0) {
			ret = rn < 0 ? rn : -EIO;
			kfree(buf);
			goto put_out;
		}
		wn = vcf_kernel_write(out, buf, rn, &wpos);
		if (wn != rn) {
			ret = wn < 0 ? wn : -EIO;
			kfree(buf);
			goto put_out;
		}
		remaining -= rn;
	}
	kfree(buf);

	nfd = get_unused_fd_flags(O_CLOEXEC);
	if (nfd < 0) {
		ret = nfd;
		goto put_out;
	}
	carg.out_fd = nfd;
	if (copy_to_user((void __user *)arg, &carg, sizeof(carg))) {
		put_unused_fd(nfd);
		ret = -EFAULT;
		goto put_out;
	}

	fd_install(nfd, out);		/* transfers the 'out' reference */
	fput(lf);
	path_put(&p);
	return 0;

put_out:
	fput(out);
put_lf:
	fput(lf);
put_path:
	path_put(&p);
	return ret;
}

/*
 * AREV_IOC_INSTALL_CIPHER: write a ciphertext blob into the LOWER (.enc) store
 * of a vcachefs mount.  See arev_uapi.h.  The destination path's PARENT must be
 * a vcachefs directory; the leaf is created in the pinned lower directory
 * (dii->lower_path) and the ciphertext streamed in, so the mount then serves it
 * decrypted.  Fails closed: validates the FS_MAGIC header, refuses to overwrite,
 * and unlinks the partial file on any error.
 */
static long do_install_cipher(unsigned long arg)
{
	struct arev_install_arg iarg;
	char *pathbuf = NULL, *base, *slash;
	const char *dir;
	const char __user *src;
	struct path dpath, np;
	struct inode *dinode, *ldir_inode;
	struct vcachefs_inode_info *dii;
	struct dentry *ld, *nd = NULL, *cached;
	struct vfsmount *lmnt;
	struct file *wf = NULL;
	void *buf = NULL;
	struct qstr q;
	u64 remaining;
	loff_t wpos = 0;
	bool created = false, got_write = false, magic_checked = false;
	umode_t mode;
	long ret;

	if (copy_from_user(&iarg, (void __user *)arg, sizeof(iarg)))
		return -EFAULT;
	if (iarg.path_len == 0 || iarg.path_len > AREV_PATH_MAX)
		return -EINVAL;
	if (iarg.data_len < ANTREV_HDR_LEN || iarg.data_len > AREV_INSTALL_MAX)
		return -EINVAL;
	mode = (umode_t)(iarg.mode & 0777);
	if (!mode)
		mode = 0644;

	pathbuf = kmalloc(iarg.path_len, GFP_KERNEL);
	if (!pathbuf)
		return -ENOMEM;
	if (copy_from_user(pathbuf, (void __user *)(uintptr_t)iarg.path,
			   iarg.path_len)) {
		ret = -EFAULT;
		goto out;
	}
	pathbuf[iarg.path_len - 1] = '\0';

	/* split "<dir>/<leaf>" — the leaf must not already exist (no overwrite) */
	slash = strrchr(pathbuf, '/');
	if (!slash || slash[1] == '\0') {	/* need a non-empty leaf */
		ret = -EINVAL;
		goto out;
	}
	*slash = '\0';
	base = slash + 1;
	dir = pathbuf[0] ? pathbuf : "/";
	if (!strcmp(base, ".") || !strcmp(base, "..")) {
		ret = -EINVAL;
		goto out;
	}

	ret = kern_path(dir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dpath);
	if (ret)
		goto out;
	dinode = d_inode(dpath.dentry);
	if (dinode->i_sb->s_magic != VCACHEFS_MAGIC) {
		ret = -EINVAL;			/* parent is not a vcachefs dir */
		goto put_dpath;
	}
	dii = VCACHEFS_I(dinode);
	if (!dii->lower_path.dentry) {
		ret = -EINVAL;
		goto put_dpath;
	}
	ld = dii->lower_path.dentry;
	lmnt = dii->lower_path.mnt;
	ldir_inode = d_inode(ld);

	ret = mnt_want_write(lmnt);		/* -EROFS if the lower is read-only */
	if (ret)
		goto put_dpath;
	got_write = true;

	/* create the leaf in the pinned lower directory */
	inode_lock(ldir_inode);
	nd = lookup_one_len(base, ld, strlen(base));
	if (IS_ERR(nd)) {
		ret = PTR_ERR(nd);
		nd = NULL;
		inode_unlock(ldir_inode);
		goto drop_write;
	}
	if (d_really_is_positive(nd)) {
		ret = -EEXIST;			/* never overwrite (stale-cache hazard) */
		inode_unlock(ldir_inode);
		goto drop_write;
	}
	ret = vfs_create(VCF_IDMAP_ARG ldir_inode, nd, mode, true);
	inode_unlock(ldir_inode);
	if (ret)
		goto drop_write;
	created = true;

	/* open the new lower file for writing (through the lower mnt) */
	np.mnt = lmnt;
	np.dentry = nd;
	wf = dentry_open(&np, O_WRONLY | O_LARGEFILE, current_cred());
	if (IS_ERR(wf)) {
		ret = PTR_ERR(wf);
		wf = NULL;
		goto unlink;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto unlink;
	}

	src = (const char __user *)(uintptr_t)iarg.data;
	remaining = iarg.data_len;
	while (remaining > 0) {
		size_t chunk = remaining < PAGE_SIZE ? (size_t)remaining : PAGE_SIZE;
		ssize_t wn;

		if (copy_from_user(buf, src, chunk)) {
			ret = -EFAULT;
			goto unlink;
		}
		if (!magic_checked) {		/* first bytes must be the container magic */
			if (chunk < ANTREV_MAGIC_LEN ||
			    memcmp(buf, ANTREV_MAGIC, ANTREV_MAGIC_LEN)) {
				ret = -EINVAL;
				goto unlink;
			}
			magic_checked = true;
		}
		wn = vcf_kernel_write(wf, buf, chunk, &wpos);
		if (wn != (ssize_t)chunk) {
			ret = wn < 0 ? wn : -EIO;
			goto unlink;
		}
		src += chunk;
		remaining -= chunk;
	}

	/* Flush any cached NEGATIVE vcachefs dentry for this leaf so the next
	 * lookup through the mount sees the file we just created (vcachefs has no
	 * d_revalidate, so a stale negative dentry would otherwise mask it). */
	q.name = (const unsigned char *)base;
	q.len = strlen(base);
	cached = d_hash_and_lookup(dpath.dentry, &q);
	if (!IS_ERR_OR_NULL(cached)) {
		if (!d_really_is_positive(cached))
			d_drop(cached);
		dput(cached);
	}

	ret = 0;
	kfree(buf);
	fput(wf);
	wf = NULL;
	goto drop_write;			/* success: skip the unlink block */

unlink:
	kfree(buf);
	if (wf)
		fput(wf);
	if (created) {
		inode_lock(ldir_inode);
		vfs_unlink(VCF_IDMAP_ARG ldir_inode, nd, NULL);
		inode_unlock(ldir_inode);
	}
drop_write:
	if (got_write)
		mnt_drop_write(lmnt);
	if (nd)
		dput(nd);
put_dpath:
	path_put(&dpath);
out:
	kfree(pathbuf);
	return ret;
}

static long vcf_ctl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (!vcf_ctl_caller_ok())
		return -EACCES;		/* only the genuine emulator / trusted installer */

	switch (cmd) {
	case AREV_IOC_AUTHORIZE_FD:
		return do_authorize_fd(arg);
	case AREV_IOC_OPEN_CIPHER:
		return do_open_cipher(arg);
	case AREV_IOC_INSTALL_CIPHER:
		return do_install_cipher(arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations vcf_ctl_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= vcf_ctl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vcf_ctl_ioctl,	/* fixed-width UAPI: same handler */
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice vcf_ctl_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= AREV_DEV_NAME,		/* -> /dev/vcachefs */
	.fops	= &vcf_ctl_fops,
	.mode	= 0666,				/* open is free; ioctls are gated */
};

int vcf_ctldev_init(void)
{
	return misc_register(&vcf_ctl_dev);
}

void vcf_ctldev_exit(void)
{
	misc_deregister(&vcf_ctl_dev);
}
