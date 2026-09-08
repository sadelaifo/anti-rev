// SPDX-License-Identifier: GPL-2.0
/*
 * vcachefs superblock / mount / module glue.
 *
 * mount -t vcachefs <lowerdir> <mountpoint> [-o passthrough=json:md|passdata]
 *
 * The lower directory is the ciphertext .enc/ subtree.  There is NO mount-time
 * key: every encrypted file embeds its own AES key in a trailer, which the
 * module reads at decrypt time (see crypto.c / vcachefs.h).  So mounting is
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
#include "vcachefs.h"

struct kmem_cache *vcachefs_inode_cachep;

struct vcachefs_mount_ctx {
	const char	*lowerdir;
	char		*opts;
};

/* ---- inode cache ---- */

static struct inode *vcachefs_alloc_inode(struct super_block *sb)
{
	struct vcachefs_inode_info *ii;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	ii = alloc_inode_sb(sb, vcachefs_inode_cachep, GFP_KERNEL);
#else
	ii = kmem_cache_alloc(vcachefs_inode_cachep, GFP_KERNEL);
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
static void vcachefs_free_inode(struct inode *inode)
{
	kmem_cache_free(vcachefs_inode_cachep, VCACHEFS_I(inode));
}
#else
static void vcachefs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(vcachefs_inode_cachep, VCACHEFS_I(inode));
}

static void vcachefs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, vcachefs_i_callback);
}
#endif

static void vcachefs_evict_inode(struct inode *inode)
{
	struct vcachefs_inode_info *ii = VCACHEFS_I(inode);

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

static int vcachefs_show_options(struct seq_file *m, struct dentry *root)
{
	struct vcachefs_sb_info *sbi = VCACHEFS_SB(root->d_sb);

	if (sbi->passthrough)
		seq_printf(m, ",passthrough=%s", sbi->passthrough);
	if (sbi->pass_nonelf)
		seq_printf(m, ",passdata");
	return 0;
}

const struct super_operations vcachefs_sops = {
	.alloc_inode	= vcachefs_alloc_inode,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.free_inode	= vcachefs_free_inode,
#else
	.destroy_inode	= vcachefs_destroy_inode,
#endif
	.evict_inode	= vcachefs_evict_inode,
	.statfs		= simple_statfs,
	.show_options	= vcachefs_show_options,
};

/* ---- option parsing ---- */

static int vcachefs_parse_opts(struct vcachefs_sb_info *sbi, char *opts)
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

static int vcachefs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct vcachefs_mount_ctx *ctx = data;
	struct vcachefs_sb_info *sbi;
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
			pr_err("vcachefs: bad lowerdir '%s': %d\n",
			       ctx->lowerdir, err);
		return err;
	}

	err = vcachefs_parse_opts(sbi, ctx->opts);
	if (err)
		return err;

	sb->s_magic = VCACHEFS_MAGIC;
	sb->s_op = &vcachefs_sops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_time_gran = 1;
	sb->s_flags |= SB_RDONLY | SB_NOSUID | SB_NODEV;

	root_inode = vcachefs_iget(sb, sbi->lower_root.dentry);
	if (IS_ERR(root_inode))
		return PTR_ERR(root_inode);

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		return -ENOMEM;
	return 0;
}

static struct dentry *vcachefs_mount(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *data)
{
	struct vcachefs_mount_ctx ctx = {
		.lowerdir = dev_name,
		.opts = data,
	};

	if (!dev_name)
		return ERR_PTR(-EINVAL);
	return mount_nodev(fs_type, flags, &ctx, vcachefs_fill_super);
}

static void vcachefs_kill_sb(struct super_block *sb)
{
	struct vcachefs_sb_info *sbi = VCACHEFS_SB(sb);

	kill_anon_super(sb);	/* evicts inodes (drops their lower refs) */
	if (sbi) {
		if (sbi->lower_root.dentry)
			path_put(&sbi->lower_root);
		kfree(sbi->passthrough);
		kfree(sbi);
	}
}

static struct file_system_type vcachefs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= VCACHEFS_NAME,
	.mount		= vcachefs_mount,
	.kill_sb	= vcachefs_kill_sb,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(VCACHEFS_NAME);

static void vcachefs_inode_init_once(void *obj)
{
	struct vcachefs_inode_info *ii = obj;

	inode_init_once(&ii->vfs_inode);
}

static int __init vcachefs_init(void)
{
	int err;

	vcachefs_inode_cachep = kmem_cache_create(
		"vcachefs_inode_cache",
		sizeof(struct vcachefs_inode_info), 0,
		SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
		vcachefs_inode_init_once);
	if (!vcachefs_inode_cachep)
		return -ENOMEM;

	err = register_filesystem(&vcachefs_fs_type);
	if (err) {
		kmem_cache_destroy(vcachefs_inode_cachep);
		return err;
	}
	/* Build the trusted keyring for signed-allow-list mode (no-op when no
	 * vendor key is embedded).  Non-fatal: a failure here only means signed
	 * mode will deny; the FS still loads. */
	if (vcachefs_authz_init())
		pr_warn("vcachefs: authz keyring init failed; gate_require_sig will deny\n");

	/* /dev/vcachefs control device for the qemu-user gate.  Non-fatal: a
	 * failure only disables the qemu gate path; the FS still mounts. */
	if (vcf_ctldev_init())
		pr_warn("vcachefs: control device registration failed; qemu gate unavailable\n");

	pr_info("vcachefs: loaded\n");
	return 0;
}

static void __exit vcachefs_exit(void)
{
	unregister_filesystem(&vcachefs_fs_type);
	rcu_barrier();	/* let free_inode RCU callbacks drain before slab free */
	kmem_cache_destroy(vcachefs_inode_cachep);
	vcf_ctldev_exit();		/* unregister /dev/vcachefs */
	vcachefs_authz_exit();		/* release the signed-authz keyring */
	pr_info("vcachefs: unloaded\n");
}

module_init(vcachefs_init);
module_exit(vcachefs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vcachefs");
MODULE_DESCRIPTION("Stacked read-only cache filesystem");
MODULE_VERSION("0.1");
