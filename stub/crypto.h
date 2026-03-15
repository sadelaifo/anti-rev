#pragma once
#include <stdint.h>
#include <stddef.h>

/*
 * Streaming AES-256-GCM context.
 *
 * Two-pass usage (verify tag before releasing plaintext):
 *
 *   aes256gcm_ctx ctx;
 *
 *   // Pass 1: feed ciphertext chunks into GHASH accumulator
 *   aes256gcm_init(&ctx, key, iv);
 *   while (have_data)
 *       aes256gcm_ghash_update(&ctx, ct_chunk, chunk_len);
 *   if (aes256gcm_ghash_verify(&ctx, tag) != 0)
 *       // tampered — abort
 *
 *   // Pass 2: CTR-decrypt the same ciphertext sequentially
 *   aes256gcm_init(&ctx, key, iv);   // resets counter
 *   while (have_data)
 *       aes256gcm_ctr_decrypt(&ctx, ct_chunk, pt_chunk, chunk_len);
 *
 * In-place decryption (ct == pt) is supported.
 * Chunks may be any size and do not need to be block-aligned.
 */
typedef struct {
    uint8_t rk[240];        /* AES-256 round keys                        */
    uint8_t H[16];          /* GHASH subkey = AES_K(0^128)               */
    uint8_t J0[16];         /* initial counter = IV || 0x00000001        */
    /* GHASH state */
    uint8_t ghash[16];      /* running GHASH accumulator                 */
    size_t  ghash_bytes;    /* total ciphertext bytes fed so far         */
    uint8_t ghash_buf[16];  /* buffered incomplete block                 */
    size_t  ghash_buf_len;  /* valid bytes in ghash_buf                  */
    /* CTR state */
    uint8_t ctr[16];        /* next counter block to encrypt             */
    uint8_t ks[16];         /* buffered keystream block                  */
    size_t  ks_used;        /* bytes consumed from ks[]                  */
} aes256gcm_ctx;

/* Initialise (or re-initialise) context for a new pass. */
void aes256gcm_init(aes256gcm_ctx *ctx,
                    const uint8_t key[32], const uint8_t iv[12]);

/* Pass 1 — feed an arbitrary-length ciphertext chunk into GHASH. */
void aes256gcm_ghash_update(aes256gcm_ctx *ctx,
                             const uint8_t *ct, size_t len);

/* Pass 1 — finalise GHASH and compare with expected tag.
 * Returns 0 if tag matches, -1 if authentication fails. */
int aes256gcm_ghash_verify(const aes256gcm_ctx *ctx, const uint8_t tag[16]);

/* Pass 2 — CTR-decrypt one chunk (sequential, any size).
 * In-place (ct == pt) is safe. */
void aes256gcm_ctr_decrypt(aes256gcm_ctx *ctx,
                            const uint8_t *ct, uint8_t *pt, size_t len);
