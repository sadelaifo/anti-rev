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
 *
 * Both ioctls are gated on the caller being the genuine emulator
 * (arev_ctl_caller_ok(): whitelisted basename or a signed exe).  Opening the
 * device is unrestricted (mode 0666); all enforcement is per-ioctl.
 *
 * NOTE: not yet built/tested on a real kernel.  The kernel-version-sensitive
 * spots are shmem_file_setup(), fdget/fd_install, and kernel_write (via the
 * compat.h wrapper) — confirm on SLES 4.12 / mainline.
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
#include <linux/cred.h>
#include <linux/version.h>

#include "compat.h"
#include "antirevfs.h"
#include "arev_uapi.h"

/* AREV_IOC_AUTHORIZE_FD: verify the vendor signature of the file at `fd`.
 * fget/fput are used (not fdget/struct fd) — the struct fd layout changed in
 * recent kernels, whereas fget has been stable across the 4.12..6.8 range. */
static long do_authorize_fd(unsigned long arg)
{
	struct file *f = fget((int)arg);
	bool ok;

	if (!f)
		return -EBADF;
	ok = arev_verify_file_sig(f);
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
	struct antirevfs_inode_info *ii;
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
	if (inode->i_sb->s_magic != ANTIREVFS_MAGIC) {
		ret = -EINVAL;			/* not a vcachefs file */
		goto put_path;
	}
	if (!S_ISREG(inode->i_mode)) {
		ret = -EISDIR;			/* dir/special: not a leak vector */
		goto put_path;
	}
	ii = ANTIREVFS_I(inode);
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

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto put_out;
	}
	remaining = outlen;
	while (remaining > 0) {
		size_t chunk = remaining < PAGE_SIZE ? (size_t)remaining : PAGE_SIZE;
		ssize_t rn = arev_kernel_read(lf, buf, chunk, &rpos);
		ssize_t wn;

		if (rn <= 0) {
			ret = rn < 0 ? rn : -EIO;
			kfree(buf);
			goto put_out;
		}
		wn = arev_kernel_write(out, buf, rn, &wpos);
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

static long arev_ctl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (!arev_ctl_caller_ok())
		return -EACCES;		/* only the genuine emulator */

	switch (cmd) {
	case AREV_IOC_AUTHORIZE_FD:
		return do_authorize_fd(arg);
	case AREV_IOC_OPEN_CIPHER:
		return do_open_cipher(arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations arev_ctl_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= arev_ctl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= arev_ctl_ioctl,	/* fixed-width UAPI: same handler */
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice arev_ctl_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= AREV_DEV_NAME,		/* -> /dev/vcachefs */
	.fops	= &arev_ctl_fops,
	.mode	= 0666,				/* open is free; ioctls are gated */
};

int arev_ctldev_init(void)
{
	return misc_register(&arev_ctl_dev);
}

void arev_ctldev_exit(void)
{
	misc_deregister(&arev_ctl_dev);
}
