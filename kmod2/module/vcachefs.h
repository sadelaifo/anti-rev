/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vcachefs — stacked read-only filesystem that decrypts ANTREV01-format
 * AES-256-GCM files on page-fault, so glibc/ld.so see plaintext while the
 * on-disk bytes (under the lower .enc/ tree) stay ciphertext.
 *
 * See kmod2/DESIGN.md for the architecture rationale.
 */
#ifndef _VCACHEFS_H
#define _VCACHEFS_H

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/mutex.h>

#define VCACHEFS_NAME		"vcachefs"
#define VCACHEFS_MAGIC		0x9E2B1147	/* non-descriptive sb magic */

/* On-disk container format (antirev-fs-pack.py / protect.py --embed-key):
 *   [magic:8][iv:12][tag:16][ciphertext...][key:32][magic:8]
 * The whole plaintext is one AES-256-GCM message (no chunking).  Unlike the
 * keyless daemon/shim container, vcachefs embeds the AES key in a per-file
 * TRAILER (key + a second magic), mirroring the master branch's stub trailer.
 * There is no mount-time key: the module reads each file's key from its own
 * trailer at decrypt time.  An unauthorized reader is served the file with the
 * trailer stripped — a valid-looking but keyless, undecryptable container.
 */
/* Non-descriptive 8-byte container magic — MUST byte-match antirev-fs-pack.py's
 * FS_MAGIC (bytes.fromhex "a74c2e91d63b085f").  Stored as a byte-escape string
 * literal (no readable marker lands in .rodata / on disk); compared with memcmp
 * over ANTREV_MAGIC_LEN, so the implicit trailing NUL is irrelevant. */
#define ANTREV_MAGIC		"\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f"
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
/* Non-descriptive 8-byte signature-footer magic — MUST byte-match
 * antirev-fs-pack.py's SIG_MAGIC (bytes.fromhex "3d6af0128c55b427"). */
#define ANTREV_SIG_MAGIC	"\x3d\x6a\xf0\x12\x8c\x55\xb4\x27"
#define ANTREV_SIG_MAGIC_LEN	8
#define ANTREV_SIG_LENFIELD	4			/* u32 LE sig length */
#define ANTREV_SIG_FOOTER_LEN	(ANTREV_SIG_LENFIELD + ANTREV_SIG_MAGIC_LEN)
#define ANTREV_SIG_MAX		(16 * 1024)		/* sanity cap on sig blob */

/* Per-mount state.  No key here — keys live in each file's trailer. */
struct vcachefs_sb_info {
	struct path	lower_root;		/* the .enc/ subtree */
	char		*passthrough;		/* comma list of extensions, or NULL */
	bool		pass_nonelf;		/* passdata: serve ANY non-magic file plaintext */
};

/* Per-inode state.  One vcachefs inode per lower inode (iget5 cached) so the
 * page cache — and therefore decrypted pages — is shared across every process
 * and every path that reaches the same file.
 */
struct vcachefs_inode_info {
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

static inline struct vcachefs_sb_info *VCACHEFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct vcachefs_inode_info *VCACHEFS_I(struct inode *inode)
{
	return container_of(inode, struct vcachefs_inode_info, vfs_inode);
}

static inline struct inode *vcachefs_lower_inode(struct inode *inode)
{
	return d_inode(VCACHEFS_I(inode)->lower_path.dentry);
}

/* super.c */
extern struct kmem_cache *vcachefs_inode_cachep;
extern const struct super_operations vcachefs_sops;

/* inode.c */
extern const struct inode_operations vcachefs_dir_iops;
extern const struct inode_operations vcachefs_file_iops;
extern const struct inode_operations vcachefs_symlink_iops;
struct inode *vcachefs_iget(struct super_block *sb, struct dentry *lower_dentry);

/* file.c */
extern const struct file_operations vcachefs_dir_fops;
extern const struct file_operations vcachefs_file_fops;
extern const struct address_space_operations vcachefs_aops;

/* gate.c — per-process decrypt authorization (the one seam swapped in step 2) */
bool vcachefs_task_authorized(void);		/* data reads: gate on caller's exe */
bool vcachefs_file_authorized(struct file *file);	/* exec-load: gate on file's own path */
bool vcachefs_gate_passthrough_cipher(void);	/* deny-mode: serve ciphertext vs -EACCES */
int  vcachefs_authz_init(void);		/* build signed-authz keyring (module init) */
void vcachefs_authz_exit(void);		/* release it (module exit) */
bool vcf_verify_file_sig(struct file *f);	/* vendor-sig check on any file */
bool vcf_verify_authorize_fd(struct file *f);	/* AUTHORIZE_FD: lower-container sig for vcachefs fds */
bool vcf_ctl_caller_ok(void);			/* caller may drive /dev/vcachefs? */

/* ctldev.c — /dev/vcachefs control device for the qemu-user gate */
int  vcf_ctldev_init(void);
void vcf_ctldev_exit(void);

/* crypto.c */
int vcachefs_has_magic(struct file *lower_file);	/* >0 yes, 0 no, <0 err */
int vcachefs_has_trailer(struct file *lower_file, loff_t size);  /* >0/0/<0: trailing magic? */
int vcachefs_decrypt_file(struct super_block *sb, struct file *lower_file,
			   loff_t lower_size, void *out, size_t out_len);
bool vcachefs_ext_whitelisted(struct vcachefs_sb_info *sbi, const char *name);
/* Detect an appended ANTRSIG1 signature section.  Sets *container_len (bytes
 * before the section, == file_size when unsigned), *sig_off, *sig_len.
 * Returns 1 signed, 0 unsigned, <0 on error. */
int vcachefs_probe_sig(struct file *lower_file, loff_t file_size,
			loff_t *container_len, loff_t *sig_off, u32 *sig_len);

#endif /* _VCACHEFS_H */
