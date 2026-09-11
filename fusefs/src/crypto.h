/*
 * crypto.h — AES-256-GCM whole-file decrypt of an embedded-key container, via
 * OpenSSL EVP.  The AES key is read fresh from the file's trailer each call and
 * zeroed after use; there is no mount-time key.  See ../DESIGN.md.
 */
#ifndef FUSEFS_CRYPTO_H
#define FUSEFS_CRYPTO_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Decrypt the whole container at fd into out[0..out_len).  container_len is the
 * sig-stripped container length (from ar_container_len); out_len must equal
 * ar_plain_len(container_len).  The GCM tag is verified (the whole plaintext is
 * one message); on tag-mismatch returns -EBADMSG and out is not trusted.
 * Returns 0 on success, <0 = -errno.
 */
int ar_decrypt(int fd, off_t container_len, unsigned char *out, size_t out_len);

#endif /* FUSEFS_CRYPTO_H */
