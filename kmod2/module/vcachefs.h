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
#include <linux/mount.h>	/* mnt_idmap()/mnt_user_ns() for the lower-idmap helper */
#include <linux/version.h>	/* LINUX_VERSION_CODE for the VCACHEFS_WRITE gate */

/*
 * Writable passthrough ("-o writable"): an OPT-IN mode in which writes are
 * UNGATED — ANY process (the app, an operator's cp/scp/touch, a file-manager
 * drag) may create/modify/rename/delete files through the mount, forwarded
 * verbatim to the lower tree.  ENCRYPTED (ANTREV01) files are mutable too, so a
 * stopped subsystem's binary (or a lib it links to) can be swapped for another
 * container while the rest of the system runs.  There is NO encrypt-on-write
 * (raw bytes only), and the SOLE gate is on *reading decrypted content* (the
 * encrypted-read path in file.c), so opening writes up never exposes plaintext
 * or the key.  Dropping in an unsigned/plaintext binary just means it won't run
 * — the writer's problem.  A file replaced through the mount (cp/scp/drag of a
 * new container) is picked up LIVE: on close of the write fd the inode is
 * re-sniffed and its stale decrypt cache dropped (vcachefs_refresh_after_write),
 * so the next exec decrypts the new bytes with no remount.  (vcache-replace is
 * still the tool for writing straight into the lower tree, e.g. on an in-place
 * mount whose lower is shadowed, where you can't reach it through the mount.)
 *
 * Compiled for kernels >= 4.9, where the two VFS APIs the write ops rely on both
 * exist: setattr_prepare() and the flags-carrying ->rename inode op.  The
 * leading idmap/userns parameter of the create/mkdir/symlink/rename/setattr ops
 * (and of the lower-fs vfs_* helpers they call) is absorbed by the shims in
 * compat.h across three ABI bands: mnt_idmap (>= 6.3), user_namespace
 * (5.12-6.2), none (< 5.12).  On kernels < 4.9 the option is rejected at mount
 * and the fs stays RO.  (compat.h gates those shims on the same >= 4.9 version
 * check, not on VCACHEFS_WRITE, since .c files include it before this header.)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#define VCACHEFS_WRITE 1
#endif

/*
 * VCACHEFS_XATTR — forward extended attributes to the lower inode (the
 * overlayfs idiom), so security.capability (file capabilities) and
 * security.selinux / LSM labels on a shipped binary survive being read through
 * the mount.  Without it the vcachefs inode reports NO xattrs, so a setcap'd
 * binary silently loses its caps on exec and an SELinux-enforcing host (e.g.
 * RHEL7) may deny the unlabeled inode outright.  Gated >= 4.9 to match the
 * modern xattr_handler ABI (get/set carry the inode arg since 4.7; the set
 * handler's idmap/userns arg is absorbed by VCF_IOP_IDMAP_PARAM across the same
 * mnt_idmap/user_namespace/none bands as the write ops).  On < 4.9 (RHEL7 3.10)
 * the old handler ABI + inode-op getxattr/setxattr pointers would be needed;
 * left as a documented gap (that target is itself not yet build-verified).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#define VCACHEFS_XATTR 1
#endif

#include "compat.h"	/* d_inode() + writable-mode shims (keyed on VCACHEFS_WRITE) */

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
#define ANTREV_KEY_LEN		32	/* AES-256 (the master key baked into the .ko) */
/* Trailer = embedded key + a trailing magic (so the trailer is self-marking). */
/* key-in-.ko: containers no longer carry a per-file key trailer (the AES key is
 * compiled into the module — see key_blob.c/crypto.c — not appended to each
 * file).  Kept as 0 so existing size math (container_len - ANTREV_TRAILER_LEN)
 * stays correct: an unauthorized passthrough read now yields the WHOLE keyless
 * container, which is useless without this .ko. */
#define ANTREV_TRAILER_LEN	0

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
	bool		writable;		/* -o writable: gated plaintext write passthrough */
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
	/* Lower-inode identity stamped at classify time.  vcachefs_file_open
	 * compares these against the live lower inode and reclassifies if they
	 * differ, so a binary (re)written IN PLACE in the lower tree after this
	 * inode was first classified — a deploy that landed after/raced the mount
	 * — is picked up on the next open with no remount or vcache-replace.  (An
	 * atomic rename-over installs a NEW lower inode the pinned lower_path
	 * can't observe; write through the mount or use vcache-replace for that.) */
	loff_t		cls_size;	/* i_size_read(lower) at classify */
	s64		cls_mtime_sec;
	long		cls_mtime_nsec;
	s64		cls_ctime_sec;	/* ctime too: catches metadata-only swaps */
	long		cls_ctime_nsec;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
/* The idmap/userns of the LOWER mount — what vfs_create/unlink/rename/
 * notify_change (and the xattr forwarders) on the lower inodes expect (NOT the
 * vcachefs mount's idmap passed to our ops).  Type and accessor vary by kernel
 * band; see vcf_idmap_t / vcf_mnt_idmap() in compat.h (mnt_idmap >= 6.3,
 * mnt_user_ns 5.12-6.2, a placeholder 0 on < 5.12 where the lower-fs helpers
 * take no such argument).  Gated >= 4.9 (not on VCACHEFS_WRITE) because the
 * xattr passthrough — available on read-only mounts too — also needs it. */
static inline vcf_idmap_t vcachefs_lower_idmap(struct inode *inode)
{
	return vcf_mnt_idmap(VCACHEFS_I(inode)->lower_path.mnt);
}
#endif

/* super.c */
extern struct kmem_cache *vcachefs_inode_cachep;
extern const struct super_operations vcachefs_sops;

/* inode.c */
extern const struct inode_operations vcachefs_dir_iops;
extern const struct inode_operations vcachefs_file_iops;
extern const struct inode_operations vcachefs_symlink_iops;
#ifdef VCACHEFS_XATTR
/* security.* / user.* / etc. xattr passthrough to the lower inode (see super.c
 * sb->s_xattr and the iops' .listxattr).  Declared here so super.c can install
 * the handler table on the superblock. */
extern const struct xattr_handler * const vcachefs_xattr_handlers[];
ssize_t vcachefs_listxattr(struct dentry *dentry, char *list, size_t size);
#endif
#ifdef VCACHEFS_WRITE
/* Writable-mount variants: add the create/unlink/rename/setattr seam. */
extern const struct inode_operations vcachefs_dir_iops_rw;
extern const struct inode_operations vcachefs_file_iops_rw;
#endif
/* Re-sniff the lower content.  Used by refresh-on-write-close (writable mounts)
 * AND revalidate-on-open (all mounts), so it is NOT gated on VCACHEFS_WRITE. */
int vcachefs_reclassify(struct inode *inode, loff_t *plain_len);
struct inode *vcachefs_iget(struct super_block *sb, struct dentry *lower_dentry);

/* True iff @inode is a vcachefs REGULAR-file inode (either the read-only or the
 * writable-mount iops).  The gate uses this to decide a file is vcachefs-resident
 * and may carry a per-exe signature, so it must match BOTH variants. */
static inline bool vcachefs_is_reg_inode(const struct inode *inode)
{
	if (inode->i_op == &vcachefs_file_iops)
		return true;
#ifdef VCACHEFS_WRITE
	if (inode->i_op == &vcachefs_file_iops_rw)
		return true;
#endif
	return false;
}

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
int vcachefs_crypto_init(void);	/* pick gcm(aes) backend; <0 if none usable */
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
