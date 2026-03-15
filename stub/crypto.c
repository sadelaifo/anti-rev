/*
 * Self-contained AES-256-GCM implementation.
 * No external dependencies — compiles cleanly for x86-64 and aarch64.
 *
 * Spec references:
 *   FIPS 197  (AES)
 *   NIST SP 800-38D  (GCM)
 */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  AES                                                                */
/* ------------------------------------------------------------------ */

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/* Round constants: rcon[i] = 2^(i-1) in GF(2^8), index 1..7 used for AES-256 */
static const uint8_t rcon[8] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40 };

/* AES-256 key expansion: produces 15 round keys × 16 bytes = 240 bytes */
static void key_expand(const uint8_t key[32], uint8_t rk[240])
{
    memcpy(rk, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t tmp = t[0];
            t[0] = sbox[t[1]] ^ rcon[i / 8];
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[tmp];
        } else if (i % 8 == 4) {
            /* SubWord only */
            t[0] = sbox[t[0]]; t[1] = sbox[t[1]];
            t[2] = sbox[t[2]]; t[3] = sbox[t[3]];
        }
        rk[i*4+0] = rk[(i-8)*4+0] ^ t[0];
        rk[i*4+1] = rk[(i-8)*4+1] ^ t[1];
        rk[i*4+2] = rk[(i-8)*4+2] ^ t[2];
        rk[i*4+3] = rk[(i-8)*4+3] ^ t[3];
    }
}

/*
 * AES state uses standard column-major layout (per FIPS 197):
 *   byte k of the 16-byte block → state[row = k%4][col = k/4]
 *   flat index: block[row + 4*col]
 *
 * So bytes 0-3 form column 0, bytes 4-7 form column 1, etc.
 */
#define B(r,c) block[(r) + 4*(c)]

static void sub_bytes(uint8_t block[16])
{
    for (int i = 0; i < 16; i++) block[i] = sbox[block[i]];
}

static void shift_rows(uint8_t block[16])
{
    /*
     * Row r consists of elements B(r,0..3) = block[r], block[r+4], block[r+8], block[r+12].
     * Row 1 left-rotated by 1: positions 1,5,9,13
     * Row 2 left-rotated by 2: positions 2,6,10,14
     * Row 3 left-rotated by 3: positions 3,7,11,15
     */
    uint8_t t;
    /* row 1 */
    t=block[1]; block[1]=block[5]; block[5]=block[9]; block[9]=block[13]; block[13]=t;
    /* row 2 */
    t=block[2]; block[2]=block[10]; block[10]=t;
    t=block[6]; block[6]=block[14]; block[14]=t;
    /* row 3 (left-3 = right-1) */
    t=block[15]; block[15]=block[11]; block[11]=block[7]; block[7]=block[3]; block[3]=t;
}

/* GF(2^8) multiply */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        int hi = a >> 7;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void mix_columns(uint8_t block[16])
{
    /*
     * Column c occupies block[4*c .. 4*c+3] = B(0..3, c).
     */
    for (int c = 0; c < 4; c++) {
        uint8_t s0=block[4*c], s1=block[4*c+1], s2=block[4*c+2], s3=block[4*c+3];
        block[4*c+0] = gf_mul(2,s0)^gf_mul(3,s1)^       s2       ^       s3;
        block[4*c+1] =       s0      ^gf_mul(2,s1)^gf_mul(3,s2)^       s3;
        block[4*c+2] =       s0      ^       s1      ^gf_mul(2,s2)^gf_mul(3,s3);
        block[4*c+3] = gf_mul(3,s0)^       s1      ^       s2      ^gf_mul(2,s3);
    }
}

static void add_round_key(uint8_t block[16], const uint8_t rk[16])
{
    for (int i = 0; i < 16; i++) block[i] ^= rk[i];
}

/* Encrypt one 16-byte block in-place using pre-expanded round keys */
static void aes256_enc(const uint8_t rk[240], uint8_t block[16])
{
    add_round_key(block, rk);
    for (int r = 1; r <= 13; r++) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, rk + r * 16);
    }
    /* Final round: no MixColumns */
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, rk + 14 * 16);
}

/* ------------------------------------------------------------------ */
/*  GCM                                                                */
/* ------------------------------------------------------------------ */

/*
 * GF(2^128) multiply: Z = X * Y
 *
 * Both operands are 16-byte big-endian bit strings where bit 0 of byte 0
 * is the coefficient of x^0 (NIST GCM convention).
 * Reduction polynomial: x^128 + x^7 + x^2 + x + 1  →  0xe1 in byte 0.
 */
static void gcm_mult(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16])
{
    uint8_t V[16];
    memset(Z, 0, 16);
    memcpy(V, Y, 16);

    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            if ((X[i] >> j) & 1) {
                for (int k = 0; k < 16; k++) Z[k] ^= V[k];
            }
            /* V = V * x^{-1}: right-shift; if lsb was 1, XOR reduction */
            int lsb = V[15] & 1;
            for (int k = 15; k > 0; k--)
                V[k] = (uint8_t)((V[k] >> 1) | (V[k-1] << 7));
            V[0] >>= 1;
            if (lsb) V[0] ^= 0xe1;
        }
    }
}

/* Increment the rightmost 32 bits of a 128-bit counter block (big-endian) */
static void inc32(uint8_t cb[16])
{
    uint32_t ctr = ((uint32_t)cb[12] << 24) | ((uint32_t)cb[13] << 16)
                 | ((uint32_t)cb[14] <<  8) |  (uint32_t)cb[15];
    ctr++;
    cb[12] = (uint8_t)(ctr >> 24);
    cb[13] = (uint8_t)(ctr >> 16);
    cb[14] = (uint8_t)(ctr >>  8);
    cb[15] = (uint8_t) ctr;
}

/* Feed one 16-byte block into the running GHASH state */
static void ghash_update(uint8_t state[16], const uint8_t H[16],
                         const uint8_t block[16])
{
    uint8_t tmp[16], result[16];
    for (int i = 0; i < 16; i++) tmp[i] = state[i] ^ block[i];
    gcm_mult(tmp, H, result);
    memcpy(state, result, 16);
}

/* ------------------------------------------------------------------ */
/*  Public streaming API                                               */
/* ------------------------------------------------------------------ */

void aes256gcm_init(aes256gcm_ctx *ctx,
                    const uint8_t key[32], const uint8_t iv[12])
{
    key_expand(key, ctx->rk);

    /* H = AES_K(0^128) */
    memset(ctx->H, 0, 16);
    aes256_enc(ctx->rk, ctx->H);

    /* J0 = IV || 0x00000001 */
    memset(ctx->J0, 0, 16);
    memcpy(ctx->J0, iv, 12);
    ctx->J0[15] = 0x01;

    /* GHASH state */
    memset(ctx->ghash,     0, 16);
    memset(ctx->ghash_buf, 0, 16);
    ctx->ghash_bytes   = 0;
    ctx->ghash_buf_len = 0;

    /* CTR starts at inc32(J0) = IV || 0x00000002 */
    memcpy(ctx->ctr, ctx->J0, 16);
    inc32(ctx->ctr);
    ctx->ks_used = 16; /* no buffered keystream yet */
}

void aes256gcm_ghash_update(aes256gcm_ctx *ctx,
                             const uint8_t *ct, size_t len)
{
    size_t pos = 0;

    /* Fill any existing partial block */
    if (ctx->ghash_buf_len > 0) {
        size_t need = 16 - ctx->ghash_buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(ctx->ghash_buf + ctx->ghash_buf_len, ct, take);
        ctx->ghash_buf_len += take;
        pos += take;
        if (ctx->ghash_buf_len == 16) {
            ghash_update(ctx->ghash, ctx->H, ctx->ghash_buf);
            ctx->ghash_buf_len = 0;
        }
    }

    /* Process full 16-byte blocks directly */
    while (pos + 16 <= len) {
        ghash_update(ctx->ghash, ctx->H, ct + pos);
        pos += 16;
    }

    /* Buffer trailing partial block */
    size_t rem = len - pos;
    if (rem > 0) {
        memcpy(ctx->ghash_buf, ct + pos, rem);
        ctx->ghash_buf_len = rem;
    }

    ctx->ghash_bytes += len;
}

int aes256gcm_ghash_verify(const aes256gcm_ctx *ctx, const uint8_t tag[16])
{
    uint8_t ghash[16];
    memcpy(ghash, ctx->ghash, 16);

    /* Flush any remaining partial block */
    if (ctx->ghash_buf_len > 0) {
        uint8_t padded[16] = {0};
        memcpy(padded, ctx->ghash_buf, ctx->ghash_buf_len);
        ghash_update(ghash, ctx->H, padded);
    }

    /* Final GHASH block: len(A=0) || len(C) as big-endian 64-bit values */
    uint8_t len_block[16] = {0};
    uint64_t ct_bits = (uint64_t)ctx->ghash_bytes * 8;
    len_block[ 8] = (uint8_t)(ct_bits >> 56);
    len_block[ 9] = (uint8_t)(ct_bits >> 48);
    len_block[10] = (uint8_t)(ct_bits >> 40);
    len_block[11] = (uint8_t)(ct_bits >> 32);
    len_block[12] = (uint8_t)(ct_bits >> 24);
    len_block[13] = (uint8_t)(ct_bits >> 16);
    len_block[14] = (uint8_t)(ct_bits >>  8);
    len_block[15] = (uint8_t) ct_bits;
    ghash_update(ghash, ctx->H, len_block);

    /* T = AES_K(J0) XOR ghash */
    uint8_t T[16];
    memcpy(T, ctx->J0, 16);
    aes256_enc(ctx->rk, T);
    for (int i = 0; i < 16; i++) T[i] ^= ghash[i];

    /* Constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= T[i] ^ tag[i];
    return (diff == 0) ? 0 : -1;
}

void aes256gcm_ctr_decrypt(aes256gcm_ctx *ctx,
                            const uint8_t *ct, uint8_t *pt, size_t len)
{
    size_t done = 0;

    /* Consume any buffered partial keystream block first */
    while (done < len && ctx->ks_used < 16) {
        pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
        done++;
    }

    /* Process full 16-byte blocks */
    while (done + 16 <= len) {
        memcpy(ctx->ks, ctx->ctr, 16);
        aes256_enc(ctx->rk, ctx->ks);
        inc32(ctx->ctr);
        for (int j = 0; j < 16; j++)
            pt[done + j] = ct[done + j] ^ ctx->ks[j];
        ctx->ks_used = 16;
        done += 16;
    }

    /* Handle final partial block */
    if (done < len) {
        memcpy(ctx->ks, ctx->ctr, 16);
        aes256_enc(ctx->rk, ctx->ks);
        inc32(ctx->ctr);
        ctx->ks_used = 0;
        while (done < len) {
            pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
            done++;
        }
    }
}
