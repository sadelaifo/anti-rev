// SPDX-License-Identifier: GPL-2.0
/*
 * vcachefs file ops + address_space ops.
 *
 * read_folio is the heart of the design: the first page fault on a file
 * triggers a one-shot whole-file AES-256-GCM decrypt into a per-inode buffer
 * (GCM tag verified once), and every read_folio then copies the requested page
 * out of that buffer into the page cache.  Because the page cache is keyed on
 * the (shared) vcachefs inode, all processes mmapping the file share the
 * decrypted physical pages with no daemon and no fd passing.
 */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>	/* task_struct — current_cred() derefs current on 3.10 */
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>	/* copy_to_user for the <3.16 aio_read path */
#include <linux/compat.h>	/* compat_ptr() for the 32-on-64 chattr ioctls */

#include "compat.h"
#include "vcachefs.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
#include <linux/aio.h>	/* struct kiocb lived here before 3.16 (moved to fs.h);
			 * needed by the <3.16 .aio_read path below */
#endif

/*
 * Lazy, idempotent whole-file decrypt into ii->plain.  The caller MUST hold
 * ii->plain_lock, and must keep holding it across the copy out of ii->plain
 * (see vcachefs_fill_page): there is NO lockless reader of ii->plain, so a
 * concurrent writer's refresh (vcachefs_refresh_after_write) can swap it to NULL
 * and free the old buffer under the same lock without racing a page fault.
 */
static int vcachefs_ensure_plain_locked(struct inode *inode)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	struct file *lower_file;
	void *buf;
	int ret = 0;

	if (ii->plain)
		return 0;

	buf = vmalloc(ii->plain_len ? ii->plain_len : 1);
	if (!buf)
		return -ENOMEM;

	lower_file = dentry_open(&ii->lower_path, O_RDONLY, current_cred());
	if (IS_ERR(lower_file)) {
		vfree(buf);
		return PTR_ERR(lower_file);
	}

	if (ii->encrypted) {
		/* container_len excludes any appended per-exe signature section,
		 * so the GCM key trailer is found at the right offset. */
		ret = vcachefs_decrypt_file(inode->i_sb, lower_file,
					     ii->container_len,
					     buf, ii->plain_len);
	} else {
		loff_t pos = 0;
		ssize_t n = vcf_kernel_read(lower_file, buf, ii->plain_len, &pos);

		ret = (n == (ssize_t)ii->plain_len) ? 0 : (n < 0 ? n : -EIO);
	}
	fput(lower_file);

	if (ret) {
		vfree(buf);
		return ret;
	}
	ii->plain = buf;
	return 0;
}

/*
 * Fill one (order-0) page of the plaintext from the per-inode decrypt buffer.
 * We never enable large folios, so a folio is always a single page here.
 * Returns 0 on success; does NOT touch the page/folio lock or uptodate state.
 */
static int vcachefs_fill_page(struct inode *inode, struct page *page)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	loff_t off = (loff_t)page->index << PAGE_SHIFT;
	size_t copy = 0;
	void *kaddr;
	int ret;

	/* Hold plain_lock across BOTH the decrypt and the copy: this is the only
	 * reader of ii->plain, so the writable-mount refresh can swap/free it
	 * safely (no lockless fast path).  read_folio is called only on a page
	 * cache miss (cold fault), so the mutex is off the steady-state path. */
	mutex_lock(&ii->plain_lock);
	ret = vcachefs_ensure_plain_locked(inode);
	if (ret) {
		mutex_unlock(&ii->plain_lock);
		return ret;
	}

	if (off < (loff_t)ii->plain_len)
		copy = min_t(size_t, PAGE_SIZE, ii->plain_len - off);

	kaddr = kmap(page);
	if (copy)
		memcpy(kaddr, ii->plain + off, copy);
	if (copy < PAGE_SIZE)
		memset(kaddr + copy, 0, PAGE_SIZE - copy);
	kunmap(page);
	mutex_unlock(&ii->plain_lock);

	flush_dcache_page(page);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
static int vcachefs_read_folio(struct file *file, struct folio *folio)
{
	struct page *page = folio_page(folio, 0);
	int ret = vcachefs_fill_page(folio->mapping->host, page);

	if (!ret)
		folio_mark_uptodate(folio);
	folio_unlock(folio);
	return ret;
}
#else
static int vcachefs_readpage(struct file *file, struct page *page)
{
	int ret = vcachefs_fill_page(page->mapping->host, page);

	if (!ret)
		SetPageUptodate(page);
	unlock_page(page);
	return ret;
}
#endif

/*
 * Per-open passthrough state for an UNAUTHORIZED reader (gate_passthrough_cipher
 * on).  Holds the lower (ciphertext) file plus the byte LIMIT we expose: the
 * lower size minus the key trailer, so the embedded key is never served.  The
 * unauthorized reader thus gets a valid-looking but keyless ANTREV01 container.
 */
struct vcachefs_passthrough {
	struct file	*lower;
	loff_t		limit;		/* lower_size - ANTREV_TRAILER_LEN (cipher-RO) */
	bool		direct;		/* true: forward ALL ops to lower (writable plaintext) */
};

/*
 * Drop an inode's cached whole-file decrypt + clean page-cache pages and re-sniff
 * the lower (encrypted vs plaintext, new size / container_len / signature, and —
 * via classify resetting authz_sig — the per-exe signature verdict).  Shared by
 * the writable mount's refresh-on-write-close and revalidate-on-open.
 *
 * Safe against concurrent readers: ii->plain is touched ONLY under plain_lock
 * (vcachefs_fill_page holds it across the copy — there is no lockless reader), so
 * swapping it to NULL here and freeing the old buffer after the lock cannot race
 * a fault.  Cached pages are dropped with invalidate_mapping_pages, which evicts
 * only clean, UNMAPPED pages — the intended case is a quiescent file (e.g. a
 * subsystem the operator stopped before swapping its binary); a page still mapped
 * by a live reader is left alone, exactly as overwriting an in-use file behaves on
 * any filesystem.
 */
static void vcachefs_drop_and_reclassify(struct inode *inode)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	loff_t plain_len = 0;
	void *old;

	mutex_lock(&ii->plain_lock);
	old = ii->plain;
	ii->plain = NULL;			/* force re-decrypt on next fault */
	if (vcachefs_reclassify(inode, &plain_len) == 0) {
		ii->plain_len = plain_len;
		i_size_write(inode, plain_len);
	} else {
		ii->open_ok = false;		/* fail-closed if the re-sniff failed */
	}
	mutex_unlock(&ii->plain_lock);

	if (old)
		vfree(old);
	invalidate_mapping_pages(inode->i_mapping, 0, -1);
}

/*
 * Revalidate the cached classification against the LIVE lower inode at open time.
 * If the lower file changed IN PLACE after this vcachefs inode was first
 * classified — a deploy/sign that landed after (or raced) the mount, OR a
 * metadata op such as `chmod -R` whose ctime bump used to leave the inode's
 * cached container_len correct but is a cheap, reliable "something touched this"
 * signal — the cached verdict (encrypted / has_sig / container_len and the
 * lazily-cached authz_sig) may be stale, and the gate could wrongly deny a
 * properly-signed binary until a remount.  Comparing the lower's size + mtime +
 * ctime (stamped by classify) catches it and reclassifies here, so the next
 * open/exec sees a fresh verdict with NO remount, vcache-replace, or
 * write-through-the-mount.
 *
 * Steady-state cost on the unchanged fast path is five scalar compares, no I/O
 * and no lock (the app loading hundreds of libs pays essentially nothing).  Only
 * an IN-PLACE change (same lower inode) is observable through the pinned
 * lower_path; an atomic rename-over installs a NEW lower inode handled by
 * refresh-on-write-close or vcache-replace's REFRESH_PATH ioctl.
 */
static void vcachefs_revalidate(struct inode *inode)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	struct inode *lower = d_inode(ii->lower_path.dentry);
	s64 msec, csec;
	long mnsec, cnsec;
	loff_t lsize;

	if (!lower)
		return;
	lsize = i_size_read(lower);
	vcf_inode_mtime(lower, &msec, &mnsec);
	vcf_inode_ctime(lower, &csec, &cnsec);
	if (lsize == ii->cls_size &&
	    msec == ii->cls_mtime_sec && mnsec == ii->cls_mtime_nsec &&
	    csec == ii->cls_ctime_sec && cnsec == ii->cls_ctime_nsec)
		return;				/* unchanged: cheap no-op */

	/* Changed in place — reclassify (drops stale decrypt, resets authz_sig,
	 * re-stamps cls_* so this fires once per real change, not every open). */
	vcachefs_drop_and_reclassify(inode);
}

static int vcachefs_file_open(struct inode *inode, struct file *file)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
#ifdef VCACHEFS_WRITE
	struct vcachefs_sb_info *sbi = VCACHEFS_SB(inode->i_sb);
#endif

	/* Pick up an out-of-band IN-PLACE change to the lower file (a deploy that
	 * landed after — or raced — the mount, or a metadata sweep like chmod -R)
	 * BEFORE the gate below, so a freshly-signed binary authorizes on this open
	 * with no remount. */
	vcachefs_revalidate(inode);

	if (!ii->open_ok)
		return -EIO;	/* strict mode: unencrypted, non-whitelisted */

#ifdef VCACHEFS_WRITE
	/*
	 * Writable mount (`-o writable`): writes are UNGATED so an operator (cp/
	 * scp/touch/a file-manager drag) can replace a stopped subsystem's binary
	 * or a lib it links to.  ANY open carrying FMODE_WRITE forwards straight to
	 * a per-open lower file and moves RAW bytes — plaintext written verbatim,
	 * an encrypted file replaced by whatever container the writer supplies.
	 * There is NO encrypt-on-write and NO decrypt on this path, so no key or
	 * plaintext is ever involved; opening writes up therefore does NOT weaken
	 * the read gate below (decrypted content is still served only to authorized
	 * readers).  A replacement written through the mount is picked up LIVE:
	 * ->release re-classifies the inode and drops its stale decrypt cache
	 * (vcachefs_refresh_after_write), so the next exec decrypts the new bytes
	 * with no remount or vcache-replace.
	 */
	if (sbi->writable && (file->f_mode & FMODE_WRITE)) {
		struct vcachefs_passthrough *pd;
		struct file *lower;
		/* mirror access mode + append; O_CREAT/O_TRUNC were already applied
		 * to the upper open (O_TRUNC via our ->setattr), don't replay them. */
		int lflags = file->f_flags & (O_ACCMODE | O_APPEND | O_LARGEFILE);

		pd = kmalloc(sizeof(*pd), GFP_KERNEL);
		if (!pd)
			return -ENOMEM;
		lower = dentry_open(&ii->lower_path, lflags, current_cred());
		if (IS_ERR(lower)) {
			kfree(pd);
			return PTR_ERR(lower);
		}
		pd->lower = lower;
		pd->limit = 0;
		pd->direct = true;
		file->private_data = pd;
		return 0;
	}
	/*
	 * Non-encrypted (plaintext) READ on a writable mount: serve straight from a
	 * per-open lower file (the overlayfs idiom), so this fd sees its own and
	 * others' live writes and mmap/exec of plaintext third-party libs works.
	 * Plaintext isn't secret, so this read is ungated.
	 */
	if (sbi->writable && !ii->encrypted) {
		struct vcachefs_passthrough *pd;
		struct file *lower;
		int lflags = O_RDONLY | (file->f_flags & O_LARGEFILE);

		pd = kmalloc(sizeof(*pd), GFP_KERNEL);
		if (!pd)
			return -ENOMEM;
		lower = dentry_open(&ii->lower_path, lflags, current_cred());
		if (IS_ERR(lower)) {
			kfree(pd);
			return PTR_ERR(lower);
		}
		pd->lower = lower;
		pd->limit = 0;
		pd->direct = true;
		file->private_data = pd;
		return 0;
	}
#endif /* VCACHEFS_WRITE */

	/*
	 * Decrypt-authorization gate.  Gating at open — before any read/mmap/
	 * splice — is what keeps `cp`, backups, and file managers on ciphertext
	 * while the business app loads natively.  Non-encrypted (passthrough-
	 * whitelisted) files are not secret and are never gated.
	 *
	 * Exec-load vs data-read need DIFFERENT identities:
	 *  - FMODE_EXEC (kernel loading this file AS a program): at exec-open
	 *    current->mm->exe_file is still the caller (the shell), not this
	 *    program, so the task gate would deny every encrypted executable.
	 *    Gate on the program's OWN path instead — running a program is not a
	 *    plaintext-file exfiltration vector.
	 *  - everything else (lib loads, cp, source): gate on the calling
	 *    process's exe identity, which is what keeps cp on ciphertext.
	 */
	if (ii->encrypted) {
		if (vcf_is_exec_open(file)) {
			if (!vcachefs_file_authorized(file))
				return -EACCES;
		} else if (!vcachefs_task_authorized()) {
			/*
			 * Unauthorized data read.  Default: deny (-EACCES).  With
			 * gate_passthrough_cipher: serve the lower .enc/ ciphertext
			 * WITH THE KEY TRAILER STRIPPED — stash an O_RDONLY lower
			 * file plus an exposure limit in ->private_data; the
			 * read/splice ops below route to it capped at the limit
			 * (mmap is refused), bypassing this inode's (possibly
			 * plaintext) page cache entirely.  The withheld trailer is
			 * what keeps the embedded key out of the reader's hands.
			 */
			struct vcachefs_passthrough *pd;
			struct file *lower;
			loff_t lsz;

			if (!vcachefs_gate_passthrough_cipher())
				return -EACCES;

			pd = kmalloc(sizeof(*pd), GFP_KERNEL);
			if (!pd)
				return -ENOMEM;
			lower = dentry_open(&ii->lower_path, O_RDONLY,
					    current_cred());
			if (IS_ERR(lower)) {
				kfree(pd);
				return PTR_ERR(lower);
			}
			lsz = ii->container_len;	/* excludes any appended sig */
			pd->lower = lower;
			pd->limit = lsz > ANTREV_TRAILER_LEN ?
				    lsz - ANTREV_TRAILER_LEN : 0;
			pd->direct = false;		/* cipher-RO passthrough */
			file->private_data = pd;
		}
	}

	return 0;
}

/*
 * Below: the ciphertext-passthrough data ops.  They are reached only when
 * vcachefs_file_open() put an vcachefs_passthrough in ->private_data (an
 * unauthorized read under gate_passthrough_cipher); otherwise ->private_data is
 * NULL and we fall through to the normal decrypt-via-page-cache generics.
 * Every data path is served from the lower file but CAPPED at pd->limit (lower
 * size minus the key trailer) so the embedded key is never exposed; touching
 * this inode's i_mapping is also avoided (a concurrent authorized reader may
 * have cached decrypted pages there).  mmap is refused outright — a file-backed
 * mapping of the lower file would expose the trailer in its final page.
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
/* Bounce the lower (ciphertext) file into the reader's iter, page at a time,
 * but never past `limit`.  Built on vcf_kernel_read + copy_to_iter — the
 * lowest-common-denominator primitives present on the 4.12 and 6.8 targets.
 * (Pre-3.16 kernels lack iov_iter reads; see the aio_read variant below.) */
static ssize_t vcachefs_passthrough_read(struct file *lower, loff_t limit,
					  struct iov_iter *to, loff_t *ppos)
{
	size_t want = iov_iter_count(to);
	ssize_t total = 0;
	void *buf;

	/* clamp the request to the exposed (trailer-stripped) region */
	if (*ppos >= limit)
		return 0;
	if ((loff_t)want > limit - *ppos)
		want = limit - *ppos;
	if (!want)
		return 0;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	while (want) {
		size_t chunk = min(want, (size_t)PAGE_SIZE);
		loff_t pos = *ppos;
		ssize_t n = vcf_kernel_read(lower, buf, chunk, &pos);
		size_t copied;

		if (n <= 0) {
			if (n < 0 && total == 0)
				total = n;
			break;
		}
		copied = copy_to_iter(buf, n, to);
		total += copied;
		*ppos += copied;
		want -= copied;
		if (copied < (size_t)n)		/* iter full */
			break;
		if (n < (ssize_t)chunk)		/* lower EOF */
			break;
	}

	kfree(buf);
	return total;
}

static ssize_t vcachefs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct vcachefs_passthrough *pd = iocb->ki_filp->private_data;

	if (pd) {
		loff_t pos = iocb->ki_pos;
		ssize_t ret;

#ifdef VCACHEFS_WRITE
		if (pd->direct)
			/* writable-mount plaintext: read straight from the lower
			 * file so this fd sees its own (and others') writes. */
			ret = vcf_vfs_iter_read(pd->lower, to, &pos);
		else
#endif
			ret = vcachefs_passthrough_read(pd->lower, pd->limit,
							to, &pos);
		iocb->ki_pos = pos;
		return ret;
	}
	return generic_file_read_iter(iocb, to);
}

#ifdef VCACHEFS_WRITE
static ssize_t vcachefs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct vcachefs_passthrough *pd = iocb->ki_filp->private_data;
	loff_t pos;
	ssize_t ret;

	if (!pd || !pd->direct)
		return -EROFS;			/* not a writable-plaintext fd */
	pos = iocb->ki_pos;
	ret = vcf_vfs_iter_write(pd->lower, from, &pos);
	iocb->ki_pos = pos;
	return ret;
}

static int vcachefs_fsync(struct file *file, loff_t start, loff_t end,
			   int datasync)
{
	struct vcachefs_passthrough *pd = file->private_data;

	if (pd && pd->direct)
		return vfs_fsync_range(pd->lower, start, end, datasync);
	return 0;	/* read-only fd: nothing of ours to flush */
}
#endif /* VCACHEFS_WRITE */
#else	/* LINUX_VERSION_CODE < 3.16: no iov_iter reads (RHEL/CentOS 7 3.10) */
/*
 * Classic .aio_read dispatcher.  read(2) reaches this via do_sync_read (which
 * wraps a single-iovec kiocb), and readv(2)/preadv(2) call it directly — so
 * BOTH funnel through here.  That is essential: routing only .read would let a
 * readv() from an UNAUTHORIZED passthrough reader hit generic_file_aio_read and
 * pull decrypted pages out of this inode's page cache.  When ->private_data is
 * set (unauthorized, gate_passthrough_cipher) we serve the lower ciphertext
 * capped at pd->limit via copy_to_user; otherwise we hand off to the page-cache
 * decrypt path (generic_file_aio_read -> readpage -> whole-file decrypt).
 */
static ssize_t vcachefs_aio_read(struct kiocb *iocb, const struct iovec *iov,
				 unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct vcachefs_passthrough *pd = file->private_data;
	loff_t ppos = pos;
	ssize_t total = 0;
	unsigned long seg;
	void *buf;

	if (!pd)
		return generic_file_aio_read(iocb, iov, nr_segs, pos);

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (seg = 0; seg < nr_segs; seg++) {
		char __user *ubuf = iov[seg].iov_base;
		size_t count = iov[seg].iov_len;

		while (count) {
			size_t chunk;
			loff_t rpos = ppos;
			ssize_t n;

			if (ppos >= pd->limit)		/* trailer-stripped EOF */
				goto out;
			chunk = min(count, (size_t)PAGE_SIZE);
			if ((loff_t)chunk > pd->limit - ppos)
				chunk = pd->limit - ppos;

			n = vcf_kernel_read(pd->lower, buf, chunk, &rpos);
			if (n <= 0) {
				if (n < 0 && total == 0)
					total = n;
				goto out;
			}
			if (copy_to_user(ubuf, buf, n)) {
				if (total == 0)
					total = -EFAULT;
				goto out;
			}
			ubuf += n;
			ppos += n;
			total += n;
			count -= n;
			if (n < (ssize_t)chunk)		/* lower EOF */
				goto out;
		}
	}
out:
	kfree(buf);
	iocb->ki_pos = ppos;		/* do_sync_read copies this back to *ppos */
	return total;
}
#endif

static int vcachefs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct vcachefs_passthrough *pd = file->private_data;

	if (pd) {
#ifdef VCACHEFS_WRITE
		if (pd->direct) {
			/* writable-mount plaintext: back the mapping with the
			 * LOWER file's address space (overlayfs idiom), so mmap
			 * /exec of plaintext works and shares the lower page
			 * cache across processes.  Retarget the vma's file, then
			 * call the lower mmap; restore on failure to keep refs
			 * balanced. */
			struct file *realfile = pd->lower;
			int ret;

			if (!realfile->f_op->mmap)
				return -ENODEV;
			vcf_vma_set_file(vma, realfile);
			ret = vcf_call_mmap(vma->vm_file, vma);
			if (ret)
				vcf_vma_set_file(vma, file);
			return ret;
		}
#endif
		/* cipher-RO passthrough: refuse mmap.  A file-backed mapping of
		 * the lower file would surface the key trailer in the final page
		 * (it can't be capped the way read/splice are); fall back to
		 * read(). */
		return -ENODEV;
	}
	return generic_file_mmap(file, vma);
}

static ssize_t vcachefs_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len, unsigned int flags)
{
	struct vcachefs_passthrough *pd = in->private_data;

	if (pd) {
		if (!pd->lower->f_op->splice_read)
			return -EINVAL;
#ifdef VCACHEFS_WRITE
		/* writable-mount plaintext: splice the whole lower file (not
		 * secret, no key trailer to withhold). */
		if (pd->direct)
			return pd->lower->f_op->splice_read(pd->lower, ppos,
							    pipe, len, flags);
#endif
		/* cipher-RO: never let splice/sendfile read into the key trailer */
		if (*ppos >= pd->limit)
			return 0;
		if ((loff_t)len > pd->limit - *ppos)
			len = pd->limit - *ppos;
		return pd->lower->f_op->splice_read(pd->lower, ppos, pipe,
						    len, flags);
	}
	/*
	 * generic_file_splice_read() was removed in 6.5 (replaced by
	 * filemap_splice_read()).  SLE 15 SP7 backported that removal into its
	 * 6.4 kernel, so version code alone is wrong — key on CONFIG_SUSE_VERSION
	 * too.  AREV_HAVE_FILEMAP_SPLICE_READ is a manual escape hatch for any
	 * other enterprise kernel that backported it under a <6.5 version code.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0) || \
	defined(AREV_HAVE_FILEMAP_SPLICE_READ) || \
	(defined(CONFIG_SUSE_VERSION) && LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
	return filemap_splice_read(in, ppos, pipe, len, flags);
#else
	return generic_file_splice_read(in, ppos, pipe, len, flags);
#endif
}

static loff_t vcachefs_llseek(struct file *file, loff_t offset, int whence)
{
	struct vcachefs_passthrough *pd = file->private_data;

	if (pd) {
#ifdef VCACHEFS_WRITE
		/*
		 * Writable-mount plaintext.  Reads/writes are driven by THIS
		 * file's position: vcachefs_read_iter/write_iter forward to the
		 * lower with an EXPLICIT offset taken from iocb->ki_pos (==
		 * file->f_pos), and never consult pd->lower->f_pos.  So the seek
		 * must move file->f_pos — seeking pd->lower instead left
		 * file->f_pos stale, so the next read landed a whole buffer away
		 * from where lseek() claimed to be.  Sequential readers (cat,
		 * sha256sum) never seek and were fine; bash, which parses a
		 * script by read()-ing a buffer then lseek()ing back to the byte
		 * it consumed, skipped a buffer's worth and silently dropped the
		 * variable assignments in it.  Use generic_file_llseek_size on
		 * OUR file with the LIVE lower size so SEEK_END still follows a
		 * growing file.
		 */
		if (pd->direct)
			return generic_file_llseek_size(
				file, offset, whence, MAX_LFS_FILESIZE,
				i_size_read(file_inode(pd->lower)));
#endif
		/* cipher-RO: seek against the exposed (trailer-stripped) length
		 * so SEEK_END lands at the limit, not the real ciphertext end. */
		return generic_file_llseek_size(file, offset, whence,
						MAX_LFS_FILESIZE, pd->limit);
	}
	return generic_file_llseek(file, offset, whence);
}

static int vcachefs_file_release(struct inode *inode, struct file *file)
{
	struct vcachefs_passthrough *pd = file->private_data;
#ifdef VCACHEFS_WRITE
	/* A write through a writable mount may have replaced the file's content;
	 * re-classify + drop the stale decrypt cache so the new bytes are served
	 * on the next open (the "cp a new container and it just runs" path). */
	bool refresh = (file->f_mode & FMODE_WRITE) &&
		       VCACHEFS_SB(inode->i_sb)->writable;
#endif

	if (pd) {
		file->private_data = NULL;
		fput(pd->lower);		/* flush/close the lower write fd first */
		kfree(pd);
	}
#ifdef VCACHEFS_WRITE
	if (refresh)
		vcachefs_drop_and_reclassify(inode);
#endif
	return 0;
}

/*
 * Directory reads must keep ONE lower directory file open for the whole
 * lifetime of the vcachefs dir file.  A getdents(2) on a large directory spans
 * multiple ->iterate_shared calls, and stateful lower filesystems (ext4 htree,
 * overlayfs) hold their readdir cursor / dedup cache in the lower file's
 * private_data across those calls.  Re-opening the lower dir per call (as an
 * earlier version did) discarded that state every call, so the hash position
 * never reached EOF and readdir looped forever on any directory too big to
 * return in a single getdents buffer (e.g. a real bin/ or lib/ tree).  Open the
 * lower dir once in ->open, reuse it here, release it in ->release.
 */
static int vcachefs_dir_open(struct inode *inode, struct file *file)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	struct file *lower;

	lower = dentry_open(&ii->lower_path, O_RDONLY | O_DIRECTORY,
			    current_cred());
	if (IS_ERR(lower))
		return PTR_ERR(lower);
	file->private_data = lower;
	return 0;
}

static int vcachefs_dir_release(struct inode *inode, struct file *file)
{
	struct file *lower = file->private_data;

	if (lower) {
		file->private_data = NULL;
		fput(lower);
	}
	return 0;
}

static int vcachefs_dir_iterate(struct file *file, struct dir_context *ctx)
{
	struct file *lower = file->private_data;
	int ret;

	if (!lower)
		return -EBADF;

	lower->f_pos = ctx->pos;
	ret = iterate_dir(lower, ctx);
	ctx->pos = lower->f_pos;
	return ret;
}

/*
 * chattr/lsattr passthrough (PRE-5.13 half).  vcachefs keeps no inode flags of
 * its own, so we forward the attribute ioctls to a LOWER file and mirror the
 * resulting VFS flag bits (S_IMMUTABLE / S_APPEND / S_NOATIME) onto our inode.
 * Reaching the lower through the pinned ->lower_path is what makes this work on
 * an IN-PLACE mount, where the lower tree is shadowed by the overmount and
 * unreachable by path: `chattr +i /root/proj/bin/FOO` sets the immutable bit on
 * the real backing inode, so writes vcachefs forwards there are rejected with
 * -EPERM — a live, per-file read-only lock with no unmount.
 *
 * This ioctl path is for kernels BEFORE 5.13, where filesystems still implement
 * FS_IOC_{GET,SET}FLAGS / FS_IOC_FS{GET,SET}XATTR in their ->unlocked_ioctl.
 * From 5.13 the in-tree filesystems moved those to the fileattr inode ops and no
 * longer answer them via unlocked_ioctl, so forwarding there would -ENOTTY;
 * >= 5.13 is handled by vcachefs_fileattr_get/set in inode.c instead.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
static long vcachefs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);
	struct file *lower;
	bool is_set;
	long ret;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
	case FS_IOC_SETFLAGS:
	case FS_IOC_FSGETXATTR:
	case FS_IOC_FSSETXATTR:
		break;
	default:
		return -ENOTTY;
	}

	is_set = (cmd == FS_IOC_SETFLAGS || cmd == FS_IOC_FSSETXATTR);
	/* Honour the vcachefs mount's own read-only state for mutating cmds: the
	 * lower mount is always writable, so without this a SETFLAGS could slip
	 * through a read-only vcachefs mount. */
	if (is_set) {
		ret = mnt_want_write_file(file);
		if (ret)
			return ret;
	}

	lower = dentry_open(&ii->lower_path, O_RDONLY, current_cred());
	if (IS_ERR(lower)) {
		ret = PTR_ERR(lower);
		goto out;
	}
	if (!lower->f_op->unlocked_ioctl) {
		fput(lower);
		ret = -ENOTTY;
		goto out;
	}
	ret = lower->f_op->unlocked_ioctl(lower, cmd, arg);
	fput(lower);

	if (!ret && is_set) {
		/* keep VFS-level IS_IMMUTABLE/IS_APPEND checks on our inode in sync
		 * with the lower (lsattr still reads through GETFLAGS above). */
		struct inode *li = d_inode(ii->lower_path.dentry);

		inode->i_flags = (inode->i_flags &
				  ~(S_IMMUTABLE | S_APPEND | S_NOATIME)) |
				 (li->i_flags &
				  (S_IMMUTABLE | S_APPEND | S_NOATIME));
	}
out:
	if (is_set)
		mnt_drop_write_file(file);
	return ret;
}

#ifdef CONFIG_COMPAT
static long vcachefs_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:   cmd = FS_IOC_GETFLAGS;   break;
	case FS_IOC32_SETFLAGS:   cmd = FS_IOC_SETFLAGS;   break;
	}
	return vcachefs_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif
#endif /* LINUX_VERSION_CODE < 5.13 */

const struct address_space_operations vcachefs_aops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	.read_folio	= vcachefs_read_folio,
#else
	.readpage	= vcachefs_readpage,
#endif
};

const struct file_operations vcachefs_file_fops = {
	.open		= vcachefs_file_open,
	.release	= vcachefs_file_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	.read_iter	= vcachefs_read_iter,
#else
	.read		= do_sync_read,		/* wraps a 1-iovec .aio_read call */
	.aio_read	= vcachefs_aio_read,
#endif
#ifdef VCACHEFS_WRITE
	/* Present unconditionally; inert on a RO mount (write opens never create
	 * a write-through pd, so write_iter returns -EROFS and fsync is a no-op). */
	.write_iter	= vcachefs_write_iter,
	.fsync		= vcachefs_fsync,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
	.unlocked_ioctl	= vcachefs_ioctl,	/* chattr/lsattr -> lower (>=5.13: fileattr ops) */
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vcachefs_compat_ioctl,
#endif
#endif
	.mmap		= vcachefs_mmap,
	.splice_read	= vcachefs_splice_read,
	.llseek		= vcachefs_llseek,
};

const struct file_operations vcachefs_dir_fops = {
	.open		= vcachefs_dir_open,
	.release	= vcachefs_dir_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	.iterate_shared	= vcachefs_dir_iterate,	/* parallel readdir (4.7+) */
#else
	.iterate	= vcachefs_dir_iterate,	/* 3.11..4.6 single-cursor readdir */
#endif
	.read		= generic_read_dir,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
	.unlocked_ioctl	= vcachefs_ioctl,	/* chattr/lsattr on a dir -> lower */
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vcachefs_compat_ioctl,
#endif
#endif
	.llseek		= generic_file_llseek,
};
