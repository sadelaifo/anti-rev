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

static int antirevfs_file_open(struct inode *inode, struct file *file)
{
	if (!ANTIREVFS_I(inode)->open_ok)
		return -EIO;	/* strict mode: unencrypted, non-whitelisted */
	return 0;
}

static int antirevfs_dir_iterate(struct file *file, struct dir_context *ctx)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(file_inode(file));
	struct file *lower;
	int ret;

	lower = dentry_open(&ii->lower_path, O_RDONLY | O_DIRECTORY,
			    current_cred());
	if (IS_ERR(lower))
		return PTR_ERR(lower);

	lower->f_pos = ctx->pos;
	ret = iterate_dir(lower, ctx);
	ctx->pos = lower->f_pos;
	fput(lower);
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
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_mmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	.splice_read	= filemap_splice_read,
#else
	.splice_read	= generic_file_splice_read,
#endif
	.llseek		= generic_file_llseek,
};

const struct file_operations antirevfs_dir_fops = {
	.iterate_shared	= antirevfs_dir_iterate,
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
};
