/* SPDX-License-Identifier: GPL-2.0 */
/*
 * antirevfs — stacked read-only filesystem that decrypts ANTREV01-format
 * AES-256-GCM files on page-fault, so glibc/ld.so see plaintext while the
 * on-disk bytes (under the lower .enc/ tree) stay ciphertext.
 *
 * See kmod2/DESIGN.md for the architecture rationale.
 */
#ifndef _ANTIREVFS_H
#define _ANTIREVFS_H

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/mutex.h>

#define ANTIREVFS_NAME		"antirevfs"
#define ANTIREVFS_MAGIC		0x416E5246	/* "AnRF" */

/* On-disk container format (antirev-fs-pack.py / protect.py --embed-key):
 *   [magic:8][iv:12][tag:16][ciphertext...][key:32][magic:8]
 * The whole plaintext is one AES-256-GCM message (no chunking).  Unlike the
 * keyless daemon/shim container, antirevfs embeds the AES key in a per-file
 * TRAILER (key + a second magic), mirroring the master branch's stub trailer.
 * There is no mount-time key: the module reads each file's key from its own
 * trailer at decrypt time.  An unauthorized reader is served the file with the
 * trailer stripped — a valid-looking but keyless, undecryptable container.
 */
#define ANTREV_MAGIC		"ANTREV01"
#define ANTREV_MAGIC_LEN	8
#define ANTREV_IV_LEN		12
#define ANTREV_TAG_LEN		16
#define ANTREV_HDR_LEN		(ANTREV_MAGIC_LEN + ANTREV_IV_LEN + ANTREV_TAG_LEN)
#define ANTREV_KEY_LEN		32	/* AES-256 */
/* Trailer = embedded key + a trailing magic (so the trailer is self-marking). */
#define ANTREV_TRAILER_LEN	(ANTREV_KEY_LEN + ANTREV_MAGIC_LEN)

/*
 * OPTIONAL per-exe authorization signature, APPENDED after the container:
 *   [container...][sig:sig_len][sig_len:4 LE][ANTRSIG1:8]
 * where `container` is the whole ANTREV01 blob above and `sig` is a detached
 * PKCS#7 (DER) over those container bytes, made with the vendor private key
 * (antirev-fs-pack.py --sign-key).  The module verifies it against the key
 * embedded in gate_authz_pubkey.h.  Detected by the trailing ANTRSIG1 magic;
 * when absent the file ends in ANTREV01 (the key trailer) and is treated as
 * unsigned.  Kept in-file (not an xattr) so it survives tmpfs staging / overlay
 * / Docker layers / cp -a, none of which reliably preserve user xattrs.
 */
#define ANTREV_SIG_MAGIC	"ANTRSIG1"
#define ANTREV_SIG_MAGIC_LEN	8
#define ANTREV_SIG_LENFIELD	4			/* u32 LE sig length */
#define ANTREV_SIG_FOOTER_LEN	(ANTREV_SIG_LENFIELD + ANTREV_SIG_MAGIC_LEN)
#define ANTREV_SIG_MAX		(16 * 1024)		/* sanity cap on sig blob */

/* Per-mount state.  No key here — keys live in each file's trailer. */
struct antirevfs_sb_info {
	struct path	lower_root;		/* the .enc/ subtree */
	char		*passthrough;		/* comma list of extensions, or NULL */
	bool		pass_nonelf;		/* passdata: serve ANY non-magic file plaintext */
};

/* Per-inode state.  One antirevfs inode per lower inode (iget5 cached) so the
 * page cache — and therefore decrypted pages — is shared across every process
 * and every path that reaches the same file.
 */
struct antirevfs_inode_info {
	struct path	lower_path;	/* lower dentry + mnt; pins lower inode */
	struct mutex	plain_lock;	/* serialises the lazy whole-file decrypt */
	void		*plain;		/* vmalloc'd plaintext, NULL until faulted */
	size_t		plain_len;	/* == i_size */
	bool		encrypted;	/* true: GCM decrypt; false: passthrough copy */
	bool		open_ok;	/* false: strict-mode reject (return -EIO) */
	/* Per-exe authorization signature (see ANTREV_SIG_* above).  Computed at
	 * classify; container_len is the size EXCLUDING any appended sig section
	 * (== lower i_size when unsigned) and is what all the crypto/size math
	 * uses.  authz_sig caches the PKCS#7 verdict (a file property): 0 unknown,
	 * 1 verified-ok, -1 verified-bad — filled lazily by the gate. */
	loff_t		container_len;	/* bytes before the sig section */
	bool		has_sig;	/* an ANTRSIG1 section is present */
	int		authz_sig;	/* 0 unknown / 1 ok / -1 bad (gate cache) */
	struct inode	vfs_inode;
};

static inline struct antirevfs_sb_info *ANTIREVFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct antirevfs_inode_info *ANTIREVFS_I(struct inode *inode)
{
	return container_of(inode, struct antirevfs_inode_info, vfs_inode);
}

static inline struct inode *antirevfs_lower_inode(struct inode *inode)
{
	return d_inode(ANTIREVFS_I(inode)->lower_path.dentry);
}

/* super.c */
extern struct kmem_cache *antirevfs_inode_cachep;
extern const struct super_operations antirevfs_sops;

/* inode.c */
extern const struct inode_operations antirevfs_dir_iops;
extern const struct inode_operations antirevfs_file_iops;
extern const struct inode_operations antirevfs_symlink_iops;
struct inode *antirevfs_iget(struct super_block *sb, struct dentry *lower_dentry);

/* file.c */
extern const struct file_operations antirevfs_dir_fops;
extern const struct file_operations antirevfs_file_fops;
extern const struct address_space_operations antirevfs_aops;

/* gate.c — per-process decrypt authorization (the one seam swapped in step 2) */
bool antirevfs_task_authorized(void);		/* data reads: gate on caller's exe */
bool antirevfs_file_authorized(struct file *file);	/* exec-load: gate on file's own path */
bool antirevfs_gate_passthrough_cipher(void);	/* deny-mode: serve ciphertext vs -EACCES */
int  antirevfs_authz_init(void);		/* build signed-authz keyring (module init) */
void antirevfs_authz_exit(void);		/* release it (module exit) */

/* crypto.c */
int antirevfs_has_magic(struct file *lower_file);	/* >0 yes, 0 no, <0 err */
int antirevfs_has_trailer(struct file *lower_file, loff_t size);  /* >0/0/<0: trailing magic? */
int antirevfs_decrypt_file(struct super_block *sb, struct file *lower_file,
			   loff_t lower_size, void *out, size_t out_len);
bool antirevfs_ext_whitelisted(struct antirevfs_sb_info *sbi, const char *name);
/* Detect an appended ANTRSIG1 signature section.  Sets *container_len (bytes
 * before the section, == file_size when unsigned), *sig_off, *sig_len.
 * Returns 1 signed, 0 unsigned, <0 on error. */
int antirevfs_probe_sig(struct file *lower_file, loff_t file_size,
			loff_t *container_len, loff_t *sig_off, u32 *sig_len);

#endif /* _ANTIREVFS_H */
