// SPDX-License-Identifier: GPL-2.0
/*
 * antirevfs file ops + address_space ops.
 *
 * read_folio is the heart of the design: the first page fault on a file
 * triggers a one-shot whole-file AES-256-GCM decrypt into a per-inode buffer
 * (GCM tag verified once), and every read_folio then copies the requested page
 * out of that buffer into the page cache.  Because the page cache is keyed on
 * the (shared) antirevfs inode, all processes mmapping the file share the
 * decrypted physical pages with no daemon and no fd passing.
 */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uio.h>

#include "compat.h"
#include "antirevfs.h"

/* Lazy, idempotent whole-file decrypt into ii->plain. */
static int antirevfs_ensure_plain(struct inode *inode)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);
	struct inode *lower_inode = antirevfs_lower_inode(inode);
	struct file *lower_file;
	void *buf;
	int ret = 0;

	if (smp_load_acquire(&ii->plain))
		return 0;

	mutex_lock(&ii->plain_lock);
	if (ii->plain)
		goto out;

	buf = vmalloc(ii->plain_len ? ii->plain_len : 1);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	lower_file = dentry_open(&ii->lower_path, O_RDONLY, current_cred());
	if (IS_ERR(lower_file)) {
		ret = PTR_ERR(lower_file);
		vfree(buf);
		goto out;
	}

	if (ii->encrypted) {
		ret = antirevfs_decrypt_file(inode->i_sb, lower_file,
					     i_size_read(lower_inode),
					     buf, ii->plain_len);
	} else {
		loff_t pos = 0;
		ssize_t n = arev_kernel_read(lower_file, buf, ii->plain_len, &pos);

		ret = (n == (ssize_t)ii->plain_len) ? 0 : (n < 0 ? n : -EIO);
	}
	fput(lower_file);

	if (ret) {
		vfree(buf);
		goto out;
	}
	smp_store_release(&ii->plain, buf);
out:
	mutex_unlock(&ii->plain_lock);
	return ret;
}

/*
 * Fill one (order-0) page of the plaintext from the per-inode decrypt buffer.
 * We never enable large folios, so a folio is always a single page here.
 * Returns 0 on success; does NOT touch the page/folio lock or uptodate state.
 */
static int antirevfs_fill_page(struct inode *inode, struct page *page)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);
	loff_t off = (loff_t)page->index << PAGE_SHIFT;
	size_t copy = 0;
	void *kaddr;
	int ret;

	ret = antirevfs_ensure_plain(inode);
	if (ret)
		return ret;

	if (off < (loff_t)ii->plain_len)
		copy = min_t(size_t, PAGE_SIZE, ii->plain_len - off);

	kaddr = kmap(page);
	if (copy)
		memcpy(kaddr, ii->plain + off, copy);
	if (copy < PAGE_SIZE)
		memset(kaddr + copy, 0, PAGE_SIZE - copy);
	kunmap(page);

	flush_dcache_page(page);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
static int antirevfs_read_folio(struct file *file, struct folio *folio)
{
	struct page *page = folio_page(folio, 0);
	int ret = antirevfs_fill_page(folio->mapping->host, page);

	if (!ret)
		folio_mark_uptodate(folio);
	folio_unlock(folio);
	return ret;
}
#else
static int antirevfs_readpage(struct file *file, struct page *page)
{
	int ret = antirevfs_fill_page(page->mapping->host, page);

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
struct antirevfs_passthrough {
	struct file	*lower;
	loff_t		limit;		/* lower_size - ANTREV_TRAILER_LEN */
};

static int antirevfs_file_open(struct inode *inode, struct file *file)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);

	if (!ii->open_ok)
		return -EIO;	/* strict mode: unencrypted, non-whitelisted */

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
		if (arev_is_exec_open(file)) {
			if (!antirevfs_file_authorized(file))
				return -EACCES;
		} else if (!antirevfs_task_authorized()) {
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
			struct antirevfs_passthrough *pd;
			struct file *lower;
			loff_t lsz;

			if (!antirevfs_gate_passthrough_cipher())
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
			lsz = i_size_read(antirevfs_lower_inode(inode));
			pd->lower = lower;
			pd->limit = lsz > ANTREV_TRAILER_LEN ?
				    lsz - ANTREV_TRAILER_LEN : 0;
			file->private_data = pd;
		}
	}

	return 0;
}

/*
 * Below: the ciphertext-passthrough data ops.  They are reached only when
 * antirevfs_file_open() put an antirevfs_passthrough in ->private_data (an
 * unauthorized read under gate_passthrough_cipher); otherwise ->private_data is
 * NULL and we fall through to the normal decrypt-via-page-cache generics.
 * Every data path is served from the lower file but CAPPED at pd->limit (lower
 * size minus the key trailer) so the embedded key is never exposed; touching
 * this inode's i_mapping is also avoided (a concurrent authorized reader may
 * have cached decrypted pages there).  mmap is refused outright — a file-backed
 * mapping of the lower file would expose the trailer in its final page.
 */

/* Bounce the lower (ciphertext) file into the reader's iter, page at a time,
 * but never past `limit`.  Built on arev_kernel_read + copy_to_iter — the
 * lowest-common-denominator primitives present on both the 4.12 and 6.8 targets. */
static ssize_t antirevfs_passthrough_read(struct file *lower, loff_t limit,
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
		ssize_t n = arev_kernel_read(lower, buf, chunk, &pos);
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

static ssize_t antirevfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct antirevfs_passthrough *pd = iocb->ki_filp->private_data;

	if (pd) {
		loff_t pos = iocb->ki_pos;
		ssize_t ret = antirevfs_passthrough_read(pd->lower, pd->limit,
							 to, &pos);

		iocb->ki_pos = pos;
		return ret;
	}
	return generic_file_read_iter(iocb, to);
}

static int antirevfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* Unauthorized passthrough: refuse mmap.  A file-backed mapping of the
	 * lower file would surface the key trailer in the final page (it can't
	 * be capped the way read/splice are).  Readers fall back to read(). */
	if (file->private_data)
		return -ENODEV;
	return generic_file_mmap(file, vma);
}

static ssize_t antirevfs_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len, unsigned int flags)
{
	struct antirevfs_passthrough *pd = in->private_data;

	if (pd) {
		if (!pd->lower->f_op->splice_read)
			return -EINVAL;
		/* never let splice/sendfile read into the key trailer */
		if (*ppos >= pd->limit)
			return 0;
		if ((loff_t)len > pd->limit - *ppos)
			len = pd->limit - *ppos;
		return pd->lower->f_op->splice_read(pd->lower, ppos, pipe,
						    len, flags);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	return filemap_splice_read(in, ppos, pipe, len, flags);
#else
	return generic_file_splice_read(in, ppos, pipe, len, flags);
#endif
}

static loff_t antirevfs_llseek(struct file *file, loff_t offset, int whence)
{
	struct antirevfs_passthrough *pd = file->private_data;

	/* Seek against the exposed (trailer-stripped) length so SEEK_END lands
	 * at the limit, not the real ciphertext end. */
	if (pd)
		return generic_file_llseek_size(file, offset, whence,
						MAX_LFS_FILESIZE, pd->limit);
	return generic_file_llseek(file, offset, whence);
}

static int antirevfs_file_release(struct inode *inode, struct file *file)
{
	struct antirevfs_passthrough *pd = file->private_data;

	if (pd) {
		file->private_data = NULL;
		fput(pd->lower);
		kfree(pd);
	}
	return 0;
}

/*
 * Directory reads must keep ONE lower directory file open for the whole
 * lifetime of the antirevfs dir file.  A getdents(2) on a large directory spans
 * multiple ->iterate_shared calls, and stateful lower filesystems (ext4 htree,
 * overlayfs) hold their readdir cursor / dedup cache in the lower file's
 * private_data across those calls.  Re-opening the lower dir per call (as an
 * earlier version did) discarded that state every call, so the hash position
 * never reached EOF and readdir looped forever on any directory too big to
 * return in a single getdents buffer (e.g. a real bin/ or lib/ tree).  Open the
 * lower dir once in ->open, reuse it here, release it in ->release.
 */
static int antirevfs_dir_open(struct inode *inode, struct file *file)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);
	struct file *lower;

	lower = dentry_open(&ii->lower_path, O_RDONLY | O_DIRECTORY,
			    current_cred());
	if (IS_ERR(lower))
		return PTR_ERR(lower);
	file->private_data = lower;
	return 0;
}

static int antirevfs_dir_release(struct inode *inode, struct file *file)
{
	struct file *lower = file->private_data;

	if (lower) {
		file->private_data = NULL;
		fput(lower);
	}
	return 0;
}

static int antirevfs_dir_iterate(struct file *file, struct dir_context *ctx)
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

const struct address_space_operations antirevfs_aops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	.read_folio	= antirevfs_read_folio,
#else
	.readpage	= antirevfs_readpage,
#endif
};

const struct file_operations antirevfs_file_fops = {
	.open		= antirevfs_file_open,
	.release	= antirevfs_file_release,
	.read_iter	= antirevfs_read_iter,
	.mmap		= antirevfs_mmap,
	.splice_read	= antirevfs_splice_read,
	.llseek		= antirevfs_llseek,
};

const struct file_operations antirevfs_dir_fops = {
	.open		= antirevfs_dir_open,
	.release	= antirevfs_dir_release,
	.iterate_shared	= antirevfs_dir_iterate,
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
};
