// SPDX-License-Identifier: GPL-2.0
/*
 * antirevfs superblock / mount / module glue.
 *
 * mount -t antirevfs <lowerdir> <mountpoint> [-o passthrough=json:md|passdata]
 *
 * The lower directory is the ciphertext .enc/ subtree.  There is NO mount-time
 * key: every encrypted file embeds its own AES key in a trailer, which the
 * module reads at decrypt time (see crypto.c / antirevfs.h).  So mounting is
 * key-free — no key= option, no keyring lookup, no session-keyring dance.
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/seq_file.h>

#include "compat.h"
#include "antirevfs.h"

struct kmem_cache *antirevfs_inode_cachep;

struct antirevfs_mount_ctx {
	const char	*lowerdir;
	char		*opts;
};

/* ---- inode cache ---- */

static struct inode *antirevfs_alloc_inode(struct super_block *sb)
{
	struct antirevfs_inode_info *ii;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	ii = alloc_inode_sb(sb, antirevfs_inode_cachep, GFP_KERNEL);
#else
	ii = kmem_cache_alloc(antirevfs_inode_cachep, GFP_KERNEL);
#endif
	if (!ii)
		return NULL;
	mutex_init(&ii->plain_lock);
	ii->plain = NULL;
	ii->plain_len = 0;
	ii->encrypted = false;
	ii->open_ok = false;
	ii->container_len = 0;
	ii->has_sig = false;
	ii->authz_sig = 0;
	ii->lower_path.dentry = NULL;
	ii->lower_path.mnt = NULL;
	return &ii->vfs_inode;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
static void antirevfs_free_inode(struct inode *inode)
{
	kmem_cache_free(antirevfs_inode_cachep, ANTIREVFS_I(inode));
}
#else
static void antirevfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(antirevfs_inode_cachep, ANTIREVFS_I(inode));
}

static void antirevfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, antirevfs_i_callback);
}
#endif

static void antirevfs_evict_inode(struct inode *inode)
{
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	if (ii->plain) {
		memzero_explicit(ii->plain, ii->plain_len);
		vfree(ii->plain);
		ii->plain = NULL;
	}
	if (ii->lower_path.dentry)
		path_put(&ii->lower_path);
}

static int antirevfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct antirevfs_sb_info *sbi = ANTIREVFS_SB(root->d_sb);

	if (sbi->passthrough)
		seq_printf(m, ",passthrough=%s", sbi->passthrough);
	if (sbi->pass_nonelf)
		seq_printf(m, ",passdata");
	return 0;
}

const struct super_operations antirevfs_sops = {
	.alloc_inode	= antirevfs_alloc_inode,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.free_inode	= antirevfs_free_inode,
#else
	.destroy_inode	= antirevfs_destroy_inode,
#endif
	.evict_inode	= antirevfs_evict_inode,
	.statfs		= simple_statfs,
	.show_options	= antirevfs_show_options,
};

/* ---- option parsing ---- */

static int antirevfs_parse_opts(struct antirevfs_sb_info *sbi, char *opts)
{
	char *p;

	while ((p = strsep(&opts, ",")) != NULL) {
		if (!*p)
			continue;
		if (!strncmp(p, "passthrough=", 12)) {
			char *list, *c;

			kfree(sbi->passthrough);
			list = kstrdup(p + 12, GFP_KERNEL);
			if (!list)
				return -ENOMEM;
			/* ':' is the inner separator (',' splits mount opts) */
			for (c = list; *c; c++)
				if (*c == ':')
					*c = ',';
			sbi->passthrough = list;
		} else if (!strcmp(p, "passdata")) {
			/* serve ANY non-ANTREV01 file as plaintext passthrough
			 * (data files, scripts, third-party plaintext libs).
			 * For complete mixed-content read-only trees produced by
			 * antirev-fs-pack.py with mirror_plaintext.  Encrypted
			 * (ANTREV01) files are still decrypted + gated as usual.
			 */
			sbi->pass_nonelf = true;
		}
		/* unknown options (ro, relatime, ...) ignored */
	}
	return 0;
}

/* ---- superblock setup ---- */

static int antirevfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct antirevfs_mount_ctx *ctx = data;
	struct antirevfs_sb_info *sbi;
	struct inode *root_inode;
	int err;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;

	err = kern_path(ctx->lowerdir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&sbi->lower_root);
	if (err) {
		if (!silent)
			pr_err("antirevfs: bad lowerdir '%s': %d\n",
			       ctx->lowerdir, err);
		return err;
	}

	err = antirevfs_parse_opts(sbi, ctx->opts);
	if (err)
		return err;

	sb->s_magic = ANTIREVFS_MAGIC;
	sb->s_op = &antirevfs_sops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_time_gran = 1;
	sb->s_flags |= SB_RDONLY | SB_NOSUID | SB_NODEV;

	root_inode = antirevfs_iget(sb, sbi->lower_root.dentry);
	if (IS_ERR(root_inode))
		return PTR_ERR(root_inode);

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		return -ENOMEM;
	return 0;
}

static struct dentry *antirevfs_mount(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *data)
{
	struct antirevfs_mount_ctx ctx = {
		.lowerdir = dev_name,
		.opts = data,
	};

	if (!dev_name)
		return ERR_PTR(-EINVAL);
	return mount_nodev(fs_type, flags, &ctx, antirevfs_fill_super);
}

static void antirevfs_kill_sb(struct super_block *sb)
{
	struct antirevfs_sb_info *sbi = ANTIREVFS_SB(sb);

	kill_anon_super(sb);	/* evicts inodes (drops their lower refs) */
	if (sbi) {
		if (sbi->lower_root.dentry)
			path_put(&sbi->lower_root);
		kfree(sbi->passthrough);
		kfree(sbi);
	}
}

static struct file_system_type antirevfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= ANTIREVFS_NAME,
	.mount		= antirevfs_mount,
	.kill_sb	= antirevfs_kill_sb,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(ANTIREVFS_NAME);

static void antirevfs_inode_init_once(void *obj)
{
	struct antirevfs_inode_info *ii = obj;

	inode_init_once(&ii->vfs_inode);
}

static int __init antirevfs_init(void)
{
	int err;

	antirevfs_inode_cachep = kmem_cache_create(
		"antirevfs_inode_cache",
		sizeof(struct antirevfs_inode_info), 0,
		SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
		antirevfs_inode_init_once);
	if (!antirevfs_inode_cachep)
		return -ENOMEM;

	err = register_filesystem(&antirevfs_fs_type);
	if (err) {
		kmem_cache_destroy(antirevfs_inode_cachep);
		return err;
	}
	/* Build the trusted keyring for signed-allow-list mode (no-op when no
	 * vendor key is embedded).  Non-fatal: a failure here only means signed
	 * mode will deny; the FS still loads. */
	if (antirevfs_authz_init())
		pr_warn("antirevfs: authz keyring init failed; gate_require_sig will deny\n");
	pr_info("antirevfs: loaded\n");
	return 0;
}

static void __exit antirevfs_exit(void)
{
	unregister_filesystem(&antirevfs_fs_type);
	rcu_barrier();	/* let free_inode RCU callbacks drain before slab free */
	kmem_cache_destroy(antirevfs_inode_cachep);
	antirevfs_authz_exit();		/* release the signed-authz keyring */
	pr_info("antirevfs: unloaded\n");
}

module_init(antirevfs_init);
module_exit(antirevfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("antirev");
MODULE_DESCRIPTION("Stacked read-only filesystem decrypting ANTREV01 AES-256-GCM files on page fault");
MODULE_VERSION("0.1");
