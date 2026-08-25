// SPDX-License-Identifier: GPL-2.0
/*
 * antirevfs decryption-authorization gate.
 *
 * This file is the ONE place that decides whether the *calling process* is
 * allowed to read decrypted (plaintext) content through an antirevfs mount.
 * antirevfs_file_open() calls antirevfs_task_authorized() for every open of an
 * encrypted file; an unauthorized process gets -EACCES and can therefore only
 * ever reach the lower .enc/ ciphertext (via the lower tree directly).
 *
 * Step 1 (this implementation): the predicate matches the calling process's
 * executable -- current->mm->exe_file, which the kernel updates at execve, so
 * fork() inherits authorization and execve() of an unlisted helper like /bin/cp
 * drops it with no bookkeeping on our side -- against a newline-separated
 * allow-list file (default /etc/authorized_apps.txt).
 *
 * This is a CORRECTNESS DEMONSTRATOR for the gating plumbing, NOT a security
 * boundary: anyone who can write the allow-list, or drop a binary at an allowed
 * path, passes.  Step 2 replaces ONLY the body of authz_exe_allowed() with a
 * signature check (verify the exe's detached signature against a public key in a
 * locked kernel keyring, anchored in measured boot).  The call site, the
 * -EACCES enforcement, the encrypted-only scoping, the fork/execve lifecycle,
 * and the shared-page-cache behaviour are all unchanged -- migration is a
 * one-function swap.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/cred.h>		/* current_cred(), GLOBAL_ROOT_UID/GID */
#include <linux/ratelimit.h>	/* pr_warn_ratelimited (DEFINE_RATELIMIT_STATE) */
#include <linux/key.h>
#include <linux/verification.h>

#include "compat.h"
#include "antirevfs.h"
/* Vendor public key (DER X.509 cert) embedded at build time.  The checked-in
 * placeholder has antirev_authz_cert_der_len == 0; regenerate it with your real
 * cert via kmod2/tools/authz-embed-pubkey.sh.  With a zero-length key, signed
 * mode (gate_require_sig=1) fails safe: every list is rejected. */
#include "gate_authz_pubkey.h"
/* Hard-coded basename whitelist (the second pass-type; edit + rebuild). */
#include "gate_whitelist.h"

#define AUTHZ_MAX_BYTES		(64 * 1024)	/* sanity cap on the allow-list file */

static bool gate_enforce;
module_param(gate_enforce, bool, 0644);
MODULE_PARM_DESC(gate_enforce,
	"Enforce per-process decrypt authorization (0 = allow all, default)");

static char authz_path[256] = "/etc/authorized_apps.txt";
module_param_string(authz_path, authz_path, sizeof(authz_path), 0644);
MODULE_PARM_DESC(authz_path,
	"Allow-list file: newline-separated authorized exe paths or basenames");

/*
 * Tamper-proof allow-list (the "client can't edit it" mode).  When
 * gate_require_sig=1, the allow-list is only trusted if a detached PKCS#7
 * signature at authz_sig_path verifies against the vendor public key embedded
 * in the module (gate_authz_pubkey.h) — so a client editing the plaintext list
 * de-authorizes it (signature no longer matches) and cannot forge a new one
 * without the vendor private key.  Default 0 keeps the legacy plaintext list so
 * existing setups/tests are unaffected; the matching logic is identical either
 * way — only the TRUST of the list bytes changes.  Fails safe: any error
 * (missing sig, bad sig, no embedded key, kernel lacking PKCS#7) => list
 * rejected => deny.
 */
static bool gate_require_sig;
module_param(gate_require_sig, bool, 0644);
MODULE_PARM_DESC(gate_require_sig,
	"Require the allow-list to carry a valid detached PKCS#7 signature from the embedded vendor key (0 = trust plaintext list, default)");

static char authz_sig_path[256] = "/etc/authorized_apps.txt.p7s";
module_param_string(authz_sig_path, authz_sig_path, sizeof(authz_sig_path), 0644);
MODULE_PARM_DESC(authz_sig_path,
	"Detached PKCS#7 (DER) signature file for the allow-list (used when gate_require_sig=1)");

/*
 * When gating denies a data read, do we hard-fail it (-EACCES, default) or
 * quietly serve the lower .enc/ ciphertext?  Passthrough is the stealthier
 * posture: `cp`/`vim`/`objdump` "succeed" but get a valid-but-useless ANTREV01
 * container instead of a permission error that advertises the gate.  Security
 * is identical either way — an unauthorized reader never reaches plaintext.
 * Only affects DATA reads of encrypted files; exec-load of an unlisted program
 * is still -EACCES (running ciphertext can't work and isn't a read-exfil path).
 */
static bool gate_passthrough_cipher;
module_param(gate_passthrough_cipher, bool, 0644);
MODULE_PARM_DESC(gate_passthrough_cipher,
	"On deny, serve lower ciphertext instead of -EACCES (0 = deny, default)");

bool antirevfs_gate_passthrough_cipher(void)
{
	return gate_passthrough_cipher;
}

/*
 * Read the whole allow-list file into a NUL-terminated kmalloc buffer.
 * Returns the buffer (caller kfree()s) or NULL on any error / empty / oversize.
 *
 * Opened with the caller's creds, so the file must be readable by the business
 * processes (e.g. mode 0644).  Re-read on every check so the test (and an admin)
 * can edit the list live; step 2 sheds the shared file entirely by reading a
 * signature off the exe itself.
 */
/* Read a whole small file into a kmalloc'd, NUL-terminated buffer.  On success
 * returns the buffer and (if out_len) sets *out_len to the byte length (NOT
 * counting the added NUL — the signed content is exactly these bytes).  Caller
 * kfree()s. */
static char *authz_read_file(const char *path, size_t *out_len)
{
	struct file *f;
	char *buf;
	loff_t size, pos = 0;
	ssize_t n;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return NULL;

	size = i_size_read(file_inode(f));
	if (size <= 0 || size > AUTHZ_MAX_BYTES) {
		filp_close(f, NULL);
		return NULL;
	}

	buf = kmalloc(size + 1, GFP_KERNEL);
	if (!buf) {
		filp_close(f, NULL);
		return NULL;
	}

	n = arev_kernel_read(f, buf, size, &pos);
	filp_close(f, NULL);

	if (n != size) {
		kfree(buf);
		return NULL;
	}
	buf[size] = '\0';
	if (out_len)
		*out_len = (size_t)size;
	return buf;
}

/* ---- signed-allow-list verification (gate_require_sig=1) ------------------- */
/*
 * Trusted keyring holding ONLY the embedded vendor cert.  Built once at module
 * init from gate_authz_pubkey.h.  NULL when no key is embedded (placeholder) or
 * the kernel lacks the asymmetric-key/PKCS#7 infrastructure.
 */
static struct key *authz_keyring;

int antirevfs_authz_init(void)
{
#if defined(CONFIG_SYSTEM_DATA_VERIFICATION)
	key_ref_t kref;
	struct key *kr;

	if (antirev_authz_cert_der_len == 0)
		return 0;		/* placeholder key: signed mode will deny */

	kr = keyring_alloc(".antirev_authz",
			   GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			   (KEY_POS_ALL & ~KEY_POS_SETATTR) |
			   KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH,
			   KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(kr)) {
		pr_warn("antirevfs: authz keyring_alloc failed (%ld)\n", PTR_ERR(kr));
		return PTR_ERR(kr);
	}

	kref = key_create_or_update(make_key_ref(kr, 1), "asymmetric", NULL,
				    antirev_authz_cert_der,
				    antirev_authz_cert_der_len,
				    (KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_VIEW,
				    KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(kref)) {
		pr_warn("antirevfs: embedding authz cert failed (%ld) — check the DER in gate_authz_pubkey.h\n",
			PTR_ERR(kref));
		key_put(kr);
		return PTR_ERR(kref);
	}
	key_ref_put(kref);
	authz_keyring = kr;
	pr_info("antirevfs: authz vendor key loaded (%u-byte cert)\n",
		antirev_authz_cert_der_len);
#else
	pr_warn("antirevfs: kernel lacks CONFIG_SYSTEM_DATA_VERIFICATION (PKCS#7 verify) — gate_require_sig will deny\n");
#endif
	return 0;
}

void antirevfs_authz_exit(void)
{
	if (authz_keyring) {
		key_put(authz_keyring);
		authz_keyring = NULL;
	}
}

/* True iff `list`/`list_len` is covered by a valid detached PKCS#7 signature
 * (authz_sig_path) chaining to the embedded vendor key.  Fails safe: any
 * missing piece or verify error => false => the list is not trusted. */
static bool authz_list_signature_ok(const char *list, size_t list_len)
{
#if defined(CONFIG_SYSTEM_DATA_VERIFICATION)
	char *sig;
	size_t sig_len = 0;
	int ret;

	if (!authz_keyring)		/* no vendor key embedded/loaded */
		return false;

	sig = authz_read_file(authz_sig_path, &sig_len);
	if (!sig || sig_len == 0) {
		kfree(sig);
		return false;
	}

	ret = verify_pkcs7_signature(list, list_len, sig, sig_len,
				     authz_keyring,
				     VERIFYING_UNSPECIFIED_SIGNATURE,
				     NULL, NULL);
	kfree(sig);
	if (ret) {
		pr_warn_ratelimited("antirevfs: allow-list signature invalid (%d) — rejecting list\n", ret);
		return false;
	}
	return true;
#else
	(void)list; (void)list_len;
	return false;			/* no PKCS#7 support => can't verify => deny */
#endif
}

/*
 * True if exe_path (the canonical absolute path of the caller's executable)
 * matches any allow-list entry.  An entry containing '/' is matched against the
 * full path; an entry with no '/' is matched against the basename only.  Blank
 * lines and '#' comments are ignored.  Mutates `list` in place (strsep/strim).
 */
static bool authz_list_matches(char *list, const char *exe_path)
{
	const char *base = kbasename(exe_path);
	char *line;

	while ((line = strsep(&list, "\n")) != NULL) {
		char *entry = strim(line);

		if (!*entry || *entry == '#')
			continue;
		if (strchr(entry, '/')) {
			if (!strcmp(entry, exe_path))
				return true;
		} else if (!strcmp(entry, base)) {
			return true;
		}
	}
	return false;
}

/* Match a resolved path against the freshly-read allow-list; deny on any error
 * or a missing/unreadable list. */
static bool authz_path_listed(const char *path)
{
	char *list;
	size_t list_len = 0;
	bool ok;

	list = authz_read_file(authz_path, &list_len);
	if (!list)
		return false;		/* enforce + no/unreadable list => deny */
	/* In signed mode, the list bytes must carry a valid vendor signature
	 * before we trust any entry.  Verify BEFORE authz_list_matches (which
	 * mutates `list` via strsep). */
	if (gate_require_sig && !authz_list_signature_ok(list, list_len)) {
		kfree(list);
		return false;		/* untrusted/edited list => deny */
	}
	ok = authz_list_matches(list, path);
	kfree(list);
	return ok;
}

/* ---- pass-type 1: hard-coded whitelist (gate_whitelist.h) ------------------ */
static bool authz_whitelisted(const char *name)
{
	const char *const *w;

	if (!name)
		return false;
	for (w = antirev_whitelist; *w; w++)
		if (!strcmp(*w, name))
			return true;
	return false;
}

/* ---- pass-type 2: per-exe in-file signature ------------------------------- */
/* Verify (and cache on the inode) the appended PKCS#7 signature over an
 * antirevfs file's container bytes, against the embedded vendor key.  Returns
 * true iff a valid signature is present.  `inode` must be an antirevfs regular
 * file inode.  The verdict (a file property) is cached in ii->authz_sig; only
 * transient errors (open/alloc/read) are left uncached for retry. */
static bool authz_exe_signed_ok(struct inode *inode)
{
#if defined(CONFIG_SYSTEM_DATA_VERIFICATION)
	struct antirevfs_inode_info *ii = ANTIREVFS_I(inode);
	struct file *lf;
	void *cbuf = NULL;
	char *sbuf = NULL;
	loff_t pos, csize, isize;
	u32 slen;
	ssize_t n;
	int vret;
	bool ok = false;

	if (!authz_keyring || !ii->has_sig)
		return false;
	if (ii->authz_sig)			/* cached verdict */
		return ii->authz_sig > 0;

	csize = ii->container_len;
	isize = i_size_read(antirevfs_lower_inode(inode));
	if (csize <= 0 || csize >= isize) { ii->authz_sig = -1; return false; }
	if ((loff_t)ANTREV_SIG_FOOTER_LEN + csize > isize) { ii->authz_sig = -1; return false; }
	slen = (u32)(isize - ANTREV_SIG_FOOTER_LEN - csize);
	if (slen == 0 || slen > ANTREV_SIG_MAX) { ii->authz_sig = -1; return false; }

	lf = dentry_open(&ii->lower_path, O_RDONLY, current_cred());
	if (IS_ERR(lf))
		return false;			/* transient — don't cache */

	cbuf = vmalloc(csize);
	sbuf = kmalloc(slen, GFP_KERNEL);
	if (!cbuf || !sbuf)
		goto out;			/* transient */

	pos = 0;
	n = arev_kernel_read(lf, cbuf, csize, &pos);
	if (n != (ssize_t)csize)
		goto out;			/* transient read error */
	pos = csize;
	n = arev_kernel_read(lf, sbuf, slen, &pos);
	if (n != (ssize_t)slen)
		goto out;

	vret = verify_pkcs7_signature(cbuf, (size_t)csize, sbuf, slen,
				      authz_keyring,
				      VERIFYING_UNSPECIFIED_SIGNATURE, NULL, NULL);
	ok = (vret == 0);
	ii->authz_sig = ok ? 1 : -1;		/* definitive: cache it */
	if (!ok)
		pr_warn_ratelimited("antirevfs: per-exe signature invalid (%d)\n", vret);
out:
	fput(lf);
	vfree(cbuf);
	kfree(sbuf);
	return ok;
#else
	(void)inode;
	return false;
#endif
}

/* Combined predicate: an exe passes if its basename is whitelisted OR (it is an
 * antirevfs file and) it carries a valid per-exe signature. */
static bool authz_ok(struct inode *inode, const char *name)
{
	if (authz_whitelisted(name))
		return true;
	if (inode && inode->i_op == &antirevfs_file_iops &&
	    authz_exe_signed_ok(inode))
		return true;
	return false;
}

/* Legacy allow-list fallback: resolve `f`'s canonical path and match the
 * (optionally signature-required) list at authz_path.  Deny on any error / no
 * list.  Inert when no list is deployed — the two pass-types above are primary. */
static bool authz_list_fallback(struct file *f)
{
	char *pathbuf, *p;
	bool ok = false;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return false;
	p = d_path(&f->f_path, pathbuf, PATH_MAX);
	if (!IS_ERR(p))
		ok = authz_path_listed(p);
	kfree(pathbuf);
	return ok;
}

/*
 * Data-read gate (libraries, cp, source, ...).  antirevfs_file_open() calls
 * this for every NON-exec open of an encrypted file; returns true if the
 * calling process may read decrypted content.  Gates on the calling process's
 * executable identity, which is what keeps cp/backups on ciphertext.
 *
 * A process passes if its exe is (1) in the hard-coded whitelist, or (2) an
 * antirevfs file carrying a valid per-exe signature — else the legacy allow-list
 * (if any is deployed).
 */
bool antirevfs_task_authorized(void)
{
	struct file *exe;
	bool ok;

	if (!gate_enforce)
		return true;		/* gating off: behave exactly as before */
	if (!current->mm)		/* kernel thread: never authorized */
		return false;
	exe = arev_get_mm_exe_file(current->mm);
	if (!exe)
		return false;

	ok = authz_ok(file_inode(exe), exe->f_path.dentry->d_name.name);
	if (!ok)
		ok = authz_list_fallback(exe);
	fput(exe);
	return ok;
}

/*
 * Exec-load gate.  At execve the kernel opens the program BEFORE
 * current->mm->exe_file becomes this program (it is still the caller, e.g. the
 * shell), so the task gate above would wrongly deny a perfectly authorized
 * binary and make every encrypted executable un-runnable.  For an exec-load we
 * therefore gate on the program's OWN identity: whitelist, or the file's own
 * per-exe signature, else the legacy list.  Running a program is not a
 * plaintext-FILE exfiltration vector — the bytes land only in the new process's
 * executable mapping.
 */
bool antirevfs_file_authorized(struct file *file)
{
	if (!gate_enforce)
		return true;
	if (authz_ok(file_inode(file), file->f_path.dentry->d_name.name))
		return true;
	return authz_list_fallback(file);
}
