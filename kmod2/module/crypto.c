// SPDX-License-Identifier: GPL-2.0
/*
 * vcachefs crypto: ANTREV01 trailer detection and AES-256-GCM decrypt of a
 * whole file into a caller-provided plaintext buffer.
 *
 * The container is [magic:8][iv:12][tag:16][ct...].  The kernel's gcm(aes)
 * AEAD expects the input as [ct][tag] (tag trailing) with the 12-byte IV
 * passed separately and no associated data, which is exactly what the Python
 * encryptor produces (AESGCM(key).encrypt(iv, data, None)).
 */
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/completion.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <crypto/aead.h>

#include "compat.h"
#include "vcachefs.h"
#include "aesgcm_sw.h"

/* Log a per-file decrypt timing line (bytes / microseconds / MB-s / backend).
 * On by default for bring-up; set decrypt_log=0 to silence in production. */
static bool decrypt_log = true;
module_param(decrypt_log, bool, 0644);
MODULE_PARM_DESC(decrypt_log,
		 "log per-file decrypt timing + backend (default on)");

/*
 * crypto async-wait helper.  The DECLARE_CRYPTO_WAIT / crypto_req_done /
 * crypto_wait_req trio arrived in 4.16; on older kernels (SLES 12 / 4.12) roll
 * the equivalent completion ourselves.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)

typedef struct crypto_wait vcf_crypto_wait_t;
#define AREV_DECLARE_WAIT(name)		DECLARE_CRYPTO_WAIT(name)
#define vcf_aead_done			crypto_req_done
static inline int vcf_aead_wait(int err, vcf_crypto_wait_t *w)
{
	return crypto_wait_req(err, w);
}

#else

typedef struct {
	struct completion completion;
	int err;
} vcf_crypto_wait_t;
#define AREV_DECLARE_WAIT(name)						\
	vcf_crypto_wait_t name = {					\
		COMPLETION_INITIALIZER_ONSTACK((name).completion), 0	\
	}
static void vcf_aead_done(struct crypto_async_request *req, int err)
{
	vcf_crypto_wait_t *w = req->data;

	if (err == -EINPROGRESS)
		return;
	w->err = err;
	complete(&w->completion);
}
static int vcf_aead_wait(int err, vcf_crypto_wait_t *w)
{
	if (err == -EINPROGRESS || err == -EBUSY) {
		wait_for_completion(&w->completion);
		err = w->err;
	}
	return err;
}

#endif

int vcachefs_has_magic(struct file *lower_file)
{
	char buf[ANTREV_MAGIC_LEN];
	loff_t pos = 0;
	ssize_t n;

	n = vcf_kernel_read(lower_file, buf, sizeof(buf), &pos);
	if (n < 0)
		return n;
	if (n < ANTREV_MAGIC_LEN)
		return 0;
	return memcmp(buf, ANTREV_MAGIC, ANTREV_MAGIC_LEN) == 0 ? 1 : 0;
}

/* True if the file's last 8 bytes are the ANTREV magic — i.e. it carries the
 * embedded-key trailer (key + trailing magic).  Used to confirm a header-magic
 * file is a complete vcachefs container before computing the plaintext size. */
int vcachefs_has_trailer(struct file *lower_file, loff_t size)
{
	char buf[ANTREV_MAGIC_LEN];
	loff_t pos;
	ssize_t n;

	if (size < ANTREV_HDR_LEN + ANTREV_TRAILER_LEN)
		return 0;
	pos = size - ANTREV_MAGIC_LEN;
	n = vcf_kernel_read(lower_file, buf, sizeof(buf), &pos);
	if (n < 0)
		return n;
	if (n < ANTREV_MAGIC_LEN)
		return 0;
	return memcmp(buf, ANTREV_MAGIC, ANTREV_MAGIC_LEN) == 0 ? 1 : 0;
}

/* Detect an appended ANTRSIG1 signature section:
 *   [container...][sig:sig_len][sig_len:4 LE][ANTRSIG1:8]
 * On a signed file: *container_len = start of the sig section, *sig_off = start
 * of the sig blob, *sig_len = its length, returns 1.  On an unsigned file (ends
 * in the ANTREV01 key trailer): *container_len = file_size, returns 0.  <0 on
 * read error or a malformed section. */
int vcachefs_probe_sig(struct file *lower_file, loff_t file_size,
			loff_t *container_len, loff_t *sig_off, u32 *sig_len)
{
	u8 magic[ANTREV_SIG_MAGIC_LEN];
	u8 lenbuf[ANTREV_SIG_LENFIELD];
	loff_t pos;
	ssize_t n;
	u32 slen;

	*container_len = file_size;
	*sig_off = 0;
	*sig_len = 0;

	if (file_size < ANTREV_SIG_FOOTER_LEN)
		return 0;
	pos = file_size - ANTREV_SIG_MAGIC_LEN;
	n = vcf_kernel_read(lower_file, magic, ANTREV_SIG_MAGIC_LEN, &pos);
	if (n < 0)
		return (int)n;
	if (n < ANTREV_SIG_MAGIC_LEN ||
	    memcmp(magic, ANTREV_SIG_MAGIC, ANTREV_SIG_MAGIC_LEN) != 0)
		return 0;			/* no appended signature */

	pos = file_size - ANTREV_SIG_FOOTER_LEN;
	n = vcf_kernel_read(lower_file, lenbuf, ANTREV_SIG_LENFIELD, &pos);
	if (n < 0)
		return (int)n;
	if (n < ANTREV_SIG_LENFIELD)
		return -EIO;
	slen = (u32)lenbuf[0] | ((u32)lenbuf[1] << 8) |
	       ((u32)lenbuf[2] << 16) | ((u32)lenbuf[3] << 24);
	if (slen == 0 || slen > ANTREV_SIG_MAX ||
	    (loff_t)slen + ANTREV_SIG_FOOTER_LEN > file_size)
		return -EINVAL;			/* malformed */

	*sig_len = slen;
	*sig_off = file_size - ANTREV_SIG_FOOTER_LEN - (loff_t)slen;
	*container_len = *sig_off;
	return 1;
}

bool vcachefs_ext_whitelisted(struct vcachefs_sb_info *sbi, const char *name)
{
	const char *dot, *list = sbi->passthrough;
	size_t ext_len, tok_len;
	const char *p;

	if (!list)
		return false;
	dot = strrchr(name, '.');
	if (!dot || !dot[1])
		return false;
	dot++;				/* extension without the '.' */
	ext_len = strlen(dot);

	/* list is "json,md,txt" */
	p = list;
	while (*p) {
		const char *comma = strchr(p, ',');

		tok_len = comma ? (size_t)(comma - p) : strlen(p);
		if (tok_len == ext_len && strncasecmp(p, dot, ext_len) == 0)
			return true;
		if (!comma)
			break;
		p = comma + 1;
	}
	return false;
}

/* AES-GCM backend chosen once at module init (see vcachefs_crypto_init). */
enum { GCM_BACKEND_KERNEL, GCM_BACKEND_SW };
static int  g_gcm_backend = GCM_BACKEND_KERNEL;
static bool g_sw_gcm_ok;

/* Kernel gcm(aes) path (hardware-accelerated when the platform provides it).
 * buf is [ct||tag] and is decrypted in place; on success ct_len plaintext
 * bytes are copied to out.  Returns 0 or a negative errno. */
static int vcf_kernel_gcm_decrypt(const u8 *key, const u8 *iv,
				  u8 *buf, size_t buf_len, size_t ct_len,
				  void *out)
{
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg;
	AREV_DECLARE_WAIT(wait);
	int ret;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	ret = crypto_aead_setkey(tfm, key, ANTREV_KEY_LEN);
	if (ret)
		goto out_tfm;
	ret = crypto_aead_setauthsize(tfm, ANTREV_TAG_LEN);
	if (ret)
		goto out_tfm;
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_tfm;
	}
	/* In-place: src/dst is the same [ct||tag] buffer; on success the first
	 * ct_len bytes hold plaintext.  assoclen = 0 (no AAD). */
	sg_init_one(&sg, buf, buf_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				  CRYPTO_TFM_REQ_MAY_SLEEP, vcf_aead_done, &wait);
	aead_request_set_crypt(req, &sg, &sg, buf_len, (u8 *)iv);
	aead_request_set_ad(req, 0);
	ret = vcf_aead_wait(crypto_aead_decrypt(req), &wait);
	if (ret == 0)
		memcpy(out, buf, ct_len);	/* tag verified */
	aead_request_free(req);
out_tfm:
	crypto_free_aead(tfm);
	return ret;
}

/*
 * Decide the AES-GCM backend once at module load.  Prefer the kernel's
 * gcm(aes) (picks up ARMv8 CE / AES-NI acceleration); fall back to our
 * self-contained software implementation when the kernel was built without
 * the GCM stack (common on locked-down / diskless targets).  Fails only if
 * NEITHER is usable.  Called from vcachefs_init().
 */
int vcachefs_crypto_init(void)
{
	struct crypto_aead *tfm;

	g_sw_gcm_ok = (vcf_sw_gcm_init() == 0);

	/* Probe by actually allocating the transform (crypto_has_aead() is not
	 * present on older kernels, e.g. 5.10).  Success => kernel path. */
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (!IS_ERR(tfm)) {
		crypto_free_aead(tfm);
		g_gcm_backend = GCM_BACKEND_KERNEL;
		pr_info("vcachefs: AES-256-GCM via kernel gcm(aes); software fallback %s\n",
			g_sw_gcm_ok ? "ready" : "UNAVAILABLE");
		return 0;
	}
	if (g_sw_gcm_ok) {
		g_gcm_backend = GCM_BACKEND_SW;
		pr_info("vcachefs: kernel gcm(aes) absent (%ld); using built-in software AES-256-GCM (self-test OK)\n",
			PTR_ERR(tfm));
		return 0;
	}
	pr_err("vcachefs: no gcm(aes) and software AES-GCM self-test failed; cannot decrypt\n");
	return -ENODEV;
}

int vcachefs_decrypt_file(struct super_block *sb, struct file *lower_file,
			   loff_t lower_size, void *out, size_t out_len)
{
	u8 iv[ANTREV_IV_LEN];
	u8 key[ANTREV_KEY_LEN];		/* read fresh from this file's trailer */
	u8 *buf = NULL;			/* [ct||tag], decrypted in place */
	size_t ct_len = out_len;
	size_t buf_len = ct_len + ANTREV_TAG_LEN;
	ktime_t t_start;
	loff_t pos;
	ssize_t n;
	int ret;

	/* No mount key: the AES key lives in this file's trailer.  Layout is
	 * [hdr:36][ct:ct_len][key:32][magic:8], so out_len (plaintext) ==
	 * lower_size - HDR - TRAILER. */
	if (lower_size < ANTREV_HDR_LEN + ANTREV_TRAILER_LEN ||
	    (size_t)(lower_size - ANTREV_HDR_LEN - ANTREV_TRAILER_LEN) != ct_len) {
		pr_err("vcachefs: decrypt EINVAL lower_size=%lld ct_len=%zu\n",
		       (long long)lower_size, ct_len);
		return -EINVAL;
	}

	/* Read the embedded key from the trailer (just before the trailing
	 * magic).  Read it each decrypt; never cached in the inode/sb. */
	pos = lower_size - ANTREV_TRAILER_LEN;
	n = vcf_kernel_read(lower_file, key, ANTREV_KEY_LEN, &pos);
	if (n != ANTREV_KEY_LEN) {
		pr_err("vcachefs: key read short n=%zd want=%d pos=%lld\n",
		       n, ANTREV_KEY_LEN, (long long)(lower_size - ANTREV_TRAILER_LEN));
		return n < 0 ? n : -EIO;
	}

	/* Read IV (after the magic). */
	pos = ANTREV_MAGIC_LEN;
	n = vcf_kernel_read(lower_file, iv, ANTREV_IV_LEN, &pos);
	if (n != ANTREV_IV_LEN) {
		pr_err("vcachefs: iv read short n=%zd want=%d\n", n, ANTREV_IV_LEN);
		ret = n < 0 ? n : -EIO;
		goto out_key;
	}

	buf = vmalloc(buf_len);
	if (!buf) {
		ret = -ENOMEM;
		goto out_key;
	}

	/* tag first (file layout), then ciphertext after it: build [ct||tag]. */
	pos = ANTREV_MAGIC_LEN + ANTREV_IV_LEN;
	n = vcf_kernel_read(lower_file, buf + ct_len, ANTREV_TAG_LEN, &pos);
	if (n != ANTREV_TAG_LEN) {
		pr_err("vcachefs: tag read short n=%zd want=%d\n", n, ANTREV_TAG_LEN);
		ret = n < 0 ? n : -EIO;
		goto out_buf;
	}
	pos = ANTREV_HDR_LEN;
	n = vcf_kernel_read(lower_file, buf, ct_len, &pos);
	if (n != (ssize_t)ct_len) {
		pr_err("vcachefs: ct read short n=%zd want=%zu pos=%d\n",
		       n, ct_len, ANTREV_HDR_LEN);
		ret = n < 0 ? n : -EIO;
		goto out_buf;
	}

	/* Decrypt with the backend chosen at init: the kernel's gcm(aes)
	 * (hardware-accelerated where available), or our built-in software
	 * AES-256-GCM when the kernel lacks the cipher.  buf holds [ct||tag],
	 * so the software path reads ct=buf, tag=buf+ct_len. */
	t_start = ktime_get();
	if (g_gcm_backend == GCM_BACKEND_KERNEL) {
		ret = vcf_kernel_gcm_decrypt(key, iv, buf, buf_len, ct_len, out);
		if (ret == -ENOENT && g_sw_gcm_ok)	/* alg vanished post-probe */
			ret = vcf_sw_gcm_decrypt(key, iv, buf, ct_len,
						 buf + ct_len, out) ? -EBADMSG : 0;
	} else {
		ret = vcf_sw_gcm_decrypt(key, iv, buf, ct_len,
					 buf + ct_len, out) ? -EBADMSG : 0;
	}
	if (ret == 0 && decrypt_log) {
		s64 us = ktime_to_us(ktime_sub(ktime_get(), t_start));

		pr_info("vcachefs: decrypt %zu bytes in %lld us (~%lld MB/s, %s)\n",
			ct_len, us, us > 0 ? (long long)ct_len / us : 0,
			g_gcm_backend == GCM_BACKEND_KERNEL ? "kernel" : "software");
	} else if (ret) {
		pr_err("vcachefs: decrypt failed ret=%d (backend=%s, EBADMSG=%d)\n",
		       ret, g_gcm_backend == GCM_BACKEND_KERNEL ? "kernel" : "software",
		       -EBADMSG);
	}
out_buf:
	/* wipe transient ciphertext/plaintext copy */
	memzero_explicit(buf, buf_len);
	vfree(buf);
out_key:
	memzero_explicit(key, sizeof(key));	/* don't leave the key on the stack */
	return ret;
}
