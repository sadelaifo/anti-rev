/*
 * crypto.c — AES-256-GCM whole-file decrypt via OpenSSL EVP.
 *
 * Container layout (see container.h):
 *   [ MAGIC:8 ][ IV:12 ][ TAG:16 ][ CT:n ][ KEY:32 ][ MAGIC:8 ]
 * The GCM tag is stored BEFORE the ciphertext in the file; OpenSSL takes the
 * tag via EVP_CTRL_GCM_SET_TAG before the final block, and the IV separately,
 * with no AAD — matching the Python encryptor (AESGCM(key).encrypt(iv,data,None)).
 */
#include "crypto.h"
#include "container.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

static int pread_exact(int fd, void *buf, size_t len, off_t off)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = pread(fd, (char *)buf + done, len - done, off + done);
		if (n < 0)
			return -errno;
		if (n == 0)
			return -EIO;
		done += (size_t)n;
	}
	return 0;
}

int ar_decrypt(int fd, off_t container_len, unsigned char *out, size_t out_len)
{
	unsigned char key[AR_KEY_LEN];
	unsigned char iv[AR_IV_LEN];
	unsigned char tag[AR_TAG_LEN];
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, ret = -EIO;

	if (container_len < AR_HDR_LEN + AR_TRAILER_LEN)
		return -EINVAL;
	if ((off_t)out_len != container_len - AR_HDR_LEN - AR_TRAILER_LEN)
		return -EINVAL;

	/* key: just before the trailing magic */
	ret = pread_exact(fd, key, AR_KEY_LEN, container_len - AR_TRAILER_LEN);
	if (ret < 0)
		goto out;
	/* iv: right after the header magic */
	ret = pread_exact(fd, iv, AR_IV_LEN, AR_MAGIC_LEN);
	if (ret < 0)
		goto out;
	/* tag: after the iv */
	ret = pread_exact(fd, tag, AR_TAG_LEN, AR_MAGIC_LEN + AR_IV_LEN);
	if (ret < 0)
		goto out;
	/* ciphertext: after the 36-byte header */
	ret = pread_exact(fd, out, out_len, AR_HDR_LEN);
	if (ret < 0)
		goto out;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		ret = -ENOMEM;
		goto out;
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AR_IV_LEN, NULL) != 1 ||
	    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
		ret = -EIO;
		goto out;
	}
	/* decrypt in place (out holds ciphertext, becomes plaintext) */
	if (out_len > 0 &&
	    EVP_DecryptUpdate(ctx, out, &len, out, (int)out_len) != 1) {
		ret = -EIO;
		goto out;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AR_TAG_LEN, tag) != 1) {
		ret = -EIO;
		goto out;
	}
	/* finalize: returns >0 only if the tag verifies */
	if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) {
		ret = -EBADMSG;		/* tag mismatch / corrupt */
		goto out;
	}
	ret = 0;
out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	/* never leave key material lying around */
	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(iv, sizeof(iv));
	OPENSSL_cleanse(tag, sizeof(tag));
	if (ret != 0 && out_len)
		OPENSSL_cleanse(out, out_len);	/* don't expose partial/garbage */
	return ret;
}
