#pragma once
#include <stdint.h>
#include <stddef.h>

/*
 * AES-256-GCM decrypt.
 *
 * key    : 32 bytes
 * iv     : 12 bytes (96-bit nonce)
 * tag    : 16 bytes (GCM authentication tag)
 * ct     : ciphertext
 * ct_len : length of ciphertext in bytes
 * pt     : output buffer (caller must provide, at least ct_len bytes)
 *
 * Returns  0 on success (tag verified, pt filled).
 * Returns -1 if authentication fails (pt contents undefined).
 */
int aes256gcm_decrypt(
    const uint8_t  key[32],
    const uint8_t  iv[12],
    const uint8_t  tag[16],
    const uint8_t *ct, size_t ct_len,
    uint8_t       *pt);
