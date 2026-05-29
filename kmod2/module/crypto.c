// SPDX-License-Identifier: GPL-2.0
/*
 * antirevfs crypto: ANTREV01 trailer detection and AES-256-GCM decrypt of a
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
#include <crypto/aead.h>

#include "compat.h"
#include "antirevfs.h"

/*
 * crypto async-wait helper.  The DECLARE_CRYPTO_WAIT / crypto_req_done /
 * crypto_wait_req trio arrived in 4.16; on older kernels (SLES 12 / 4.12) roll
 * the equivalent completion ourselves.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)

typedef struct crypto_wait arev_crypto_wait_t;
#define AREV_DECLARE_WAIT(name)		DECLARE_CRYPTO_WAIT(name)
#define arev_aead_done			crypto_req_done
static inline int arev_aead_wait(int err, arev_crypto_wait_t *w)
{
	return crypto_wait_req(err, w);
}

#else

typedef struct {
	struct completion completion;
	int err;
} arev_crypto_wait_t;
#define AREV_DECLARE_WAIT(name)						\
	arev_crypto_wait_t name = {					\
		COMPLETION_INITIALIZER_ONSTACK((name).completion), 0	\
	}
static void arev_aead_done(struct crypto_async_request *req, int err)
{
	arev_crypto_wait_t *w = req->data;

	if (err == -EINPROGRESS)
		return;
	w->err = err;
	complete(&w->completion);
}
static int arev_aead_wait(int err, arev_crypto_wait_t *w)
{
	if (err == -EINPROGRESS || err == -EBUSY) {
		wait_for_completion(&w->completion);
		err = w->err;
	}
	return err;
}

#endif

int antirevfs_has_magic(struct file *lower_file)
{
	char buf[ANTREV_MAGIC_LEN];
	loff_t pos = 0;
	ssize_t n;

	n = arev_kernel_read(lower_file, buf, sizeof(buf), &pos);
	if (n < 0)
		return n;
	if (n < ANTREV_MAGIC_LEN)
		return 0;
	return memcmp(buf, ANTREV_MAGIC, ANTREV_MAGIC_LEN) == 0 ? 1 : 0;
}

bool antirevfs_ext_whitelisted(struct antirevfs_sb_info *sbi, const char *name)
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

int antirevfs_decrypt_file(struct super_block *sb, struct file *lower_file,
			   loff_t lower_size, void *out, size_t out_len)
{
	struct antirevfs_sb_info *sbi = ANTIREVFS_SB(sb);
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg;
	AREV_DECLARE_WAIT(wait);
	u8 iv[ANTREV_IV_LEN];
	u8 *buf = NULL;			/* [ct||tag], decrypted in place */
	size_t ct_len = out_len;
	size_t buf_len = ct_len + ANTREV_TAG_LEN;
	loff_t pos;
	ssize_t n;
	int ret;

	if (!sbi->have_key)
		return -ENOKEY;
	if (lower_size < ANTREV_HDR_LEN ||
	    (size_t)(lower_size - ANTREV_HDR_LEN) != ct_len)
		return -EINVAL;

	/* Read IV (after the magic). */
	pos = ANTREV_MAGIC_LEN;
	n = arev_kernel_read(lower_file, iv, ANTREV_IV_LEN, &pos);
	if (n != ANTREV_IV_LEN)
		return n < 0 ? n : -EIO;

	buf = vmalloc(buf_len);
	if (!buf)
		return -ENOMEM;

	/* tag first (file layout), then ciphertext after it: build [ct||tag]. */
	pos = ANTREV_MAGIC_LEN + ANTREV_IV_LEN;
	n = arev_kernel_read(lower_file, buf + ct_len, ANTREV_TAG_LEN, &pos);
	if (n != ANTREV_TAG_LEN) {
		ret = n < 0 ? n : -EIO;
		goto out_buf;
	}
	pos = ANTREV_HDR_LEN;
	n = arev_kernel_read(lower_file, buf, ct_len, &pos);
	if (n != (ssize_t)ct_len) {
		ret = n < 0 ? n : -EIO;
		goto out_buf;
	}

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		goto out_buf;
	}
	ret = crypto_aead_setkey(tfm, sbi->key, ANTREV_KEY_LEN);
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
	 * ct_len bytes hold plaintext.  assoclen = 0 (no AAD).
	 */
	sg_init_one(&sg, buf, buf_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				  CRYPTO_TFM_REQ_MAY_SLEEP,
				  arev_aead_done, &wait);
	aead_request_set_crypt(req, &sg, &sg, buf_len, iv);
	aead_request_set_ad(req, 0);

	ret = arev_aead_wait(crypto_aead_decrypt(req), &wait);
	if (ret == 0)
		memcpy(out, buf, ct_len);	/* tag verified */

	aead_request_free(req);
out_tfm:
	crypto_free_aead(tfm);
out_buf:
	/* wipe transient ciphertext/plaintext copy */
	memzero_explicit(buf, buf_len);
	vfree(buf);
	return ret;
}
