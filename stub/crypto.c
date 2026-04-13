/*
 * Self-contained AES-256-GCM implementation.
 * No external dependencies — compiles cleanly for x86-64 and aarch64.
 *
 * x86-64: uses AES-NI + PCLMULQDQ when available (runtime detect),
 *         falls back to portable C otherwise.
 *
 * Spec references:
 *   FIPS 197  (AES)
 *   NIST SP 800-38D  (GCM)
 */

#include "crypto.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* ================================================================== */
/*  AES-NI + PCLMULQDQ (x86-64 only)                                  */
/* ================================================================== */

/* Forward declaration — defined in software section below */
static void inc32_impl(uint8_t cb[16]);

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#include <wmmintrin.h>   /* AES-NI + PCLMULQDQ */
#include <emmintrin.h>   /* SSE2   */
#include <tmmintrin.h>   /* SSSE3 (PSHUFB)     */

/* Set at startup by _detect_hw() */
static int hw_aesni  = 0;
static int hw_pclmul = 0;

__attribute__((constructor))
static void _detect_hw(void)
{
    unsigned a, b, c, d;
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        hw_aesni  = !!(c & (1u << 25));   /* AES-NI    */
        hw_pclmul = !!(c & (1u <<  1));   /* PCLMULQDQ */
    }
}

/* ---- AES-256 key expansion (AES-NI) ---- */

__attribute__((target("aes")))
static inline __m128i _aes_key_assist(__m128i k, __m128i g)
{
    g = _mm_shuffle_epi32(g, 0xFF);
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    return _mm_xor_si128(k, g);
}

__attribute__((target("aes")))
static inline __m128i _aes_key_assist2(__m128i k1, __m128i k2)
{
    __m128i t = _mm_aeskeygenassist_si128(k2, 0);
    t = _mm_shuffle_epi32(t, 0xAA);
    k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));
    k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));
    k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));
    return _mm_xor_si128(k1, t);
}

__attribute__((target("aes,sse4.1")))
static void ni_key_expand(const uint8_t key[32], __m128i rk[15])
{
    rk[0]  = _mm_loadu_si128((const __m128i *)key);
    rk[1]  = _mm_loadu_si128((const __m128i *)(key + 16));
    rk[2]  = _aes_key_assist(rk[0], _mm_aeskeygenassist_si128(rk[1], 0x01));
    rk[3]  = _aes_key_assist2(rk[1], rk[2]);
    rk[4]  = _aes_key_assist(rk[2], _mm_aeskeygenassist_si128(rk[3], 0x02));
    rk[5]  = _aes_key_assist2(rk[3], rk[4]);
    rk[6]  = _aes_key_assist(rk[4], _mm_aeskeygenassist_si128(rk[5], 0x04));
    rk[7]  = _aes_key_assist2(rk[5], rk[6]);
    rk[8]  = _aes_key_assist(rk[6], _mm_aeskeygenassist_si128(rk[7], 0x08));
    rk[9]  = _aes_key_assist2(rk[7], rk[8]);
    rk[10] = _aes_key_assist(rk[8], _mm_aeskeygenassist_si128(rk[9], 0x10));
    rk[11] = _aes_key_assist2(rk[9], rk[10]);
    rk[12] = _aes_key_assist(rk[10], _mm_aeskeygenassist_si128(rk[11], 0x20));
    rk[13] = _aes_key_assist2(rk[11], rk[12]);
    rk[14] = _aes_key_assist(rk[12], _mm_aeskeygenassist_si128(rk[13], 0x40));
}

__attribute__((target("aes")))
static inline __m128i ni_aes256_enc(__m128i block, const __m128i rk[15])
{
    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenc_si128(block, rk[10]);
    block = _mm_aesenc_si128(block, rk[11]);
    block = _mm_aesenc_si128(block, rk[12]);
    block = _mm_aesenc_si128(block, rk[13]);
    return _mm_aesenclast_si128(block, rk[14]);
}

/* 4-wide AES-256 encryption — lets the CPU pipeline interleave rounds */
__attribute__((target("aes")))
static inline void ni_aes256_enc4(__m128i *b0, __m128i *b1,
                                  __m128i *b2, __m128i *b3,
                                  const __m128i rk[15])
{
    *b0 = _mm_xor_si128(*b0, rk[0]);
    *b1 = _mm_xor_si128(*b1, rk[0]);
    *b2 = _mm_xor_si128(*b2, rk[0]);
    *b3 = _mm_xor_si128(*b3, rk[0]);
    for (int r = 1; r < 14; r++) {
        *b0 = _mm_aesenc_si128(*b0, rk[r]);
        *b1 = _mm_aesenc_si128(*b1, rk[r]);
        *b2 = _mm_aesenc_si128(*b2, rk[r]);
        *b3 = _mm_aesenc_si128(*b3, rk[r]);
    }
    *b0 = _mm_aesenclast_si128(*b0, rk[14]);
    *b1 = _mm_aesenclast_si128(*b1, rk[14]);
    *b2 = _mm_aesenclast_si128(*b2, rk[14]);
    *b3 = _mm_aesenclast_si128(*b3, rk[14]);
}

/* ---- AES-NI init / ctr_decrypt ---- */

__attribute__((target("aes")))
static void ni_init(aes256gcm_ctx *ctx,
                    const uint8_t key[32], const uint8_t iv[12])
{
    ni_key_expand(key, (__m128i *)ctx->rk);

    /* H = AES_K(0^128) — stored in NIST byte order for software GHASH */
    memset(ctx->H, 0, 16);
    __m128i H = _mm_setzero_si128();
    H = ni_aes256_enc(H, (const __m128i *)ctx->rk);
    _mm_storeu_si128((__m128i *)ctx->H, H);

    /* J0 = IV || 0x00000001 */
    memset(ctx->J0, 0, 16);
    memcpy(ctx->J0, iv, 12);
    ctx->J0[15] = 0x01;

    memset(ctx->ghash,     0, 16);
    memset(ctx->ghash_buf, 0, 16);
    ctx->ghash_bytes   = 0;
    ctx->ghash_buf_len = 0;

    memcpy(ctx->ctr, ctx->J0, 16);
    inc32_impl(ctx->ctr);
    ctx->ks_used = 16;
}

__attribute__((target("aes")))
static void ni_ctr_decrypt(aes256gcm_ctx *ctx,
                            const uint8_t *ct, uint8_t *pt, size_t len)
{
    const __m128i *rk = (const __m128i *)ctx->rk;
    size_t done = 0;

    /* Drain partial keystream */
    while (done < len && ctx->ks_used < 16) {
        pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
        done++;
    }

    /* 4-wide blocks (AES pipeline interleaving) */
    while (done + 64 <= len) {
        __m128i c0 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
        __m128i c1 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
        __m128i c2 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
        __m128i c3 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
        ni_aes256_enc4(&c0, &c1, &c2, &c3, rk);
        __m128i d0 = _mm_loadu_si128((const __m128i *)(ct + done));
        __m128i d1 = _mm_loadu_si128((const __m128i *)(ct + done + 16));
        __m128i d2 = _mm_loadu_si128((const __m128i *)(ct + done + 32));
        __m128i d3 = _mm_loadu_si128((const __m128i *)(ct + done + 48));
        _mm_storeu_si128((__m128i *)(pt + done),      _mm_xor_si128(d0, c0));
        _mm_storeu_si128((__m128i *)(pt + done + 16), _mm_xor_si128(d1, c1));
        _mm_storeu_si128((__m128i *)(pt + done + 32), _mm_xor_si128(d2, c2));
        _mm_storeu_si128((__m128i *)(pt + done + 48), _mm_xor_si128(d3, c3));
        done += 64;
    }
    /* Remaining 1-3 full blocks */
    while (done + 16 <= len) {
        __m128i ctr = _mm_loadu_si128((const __m128i *)ctx->ctr);
        __m128i ks  = ni_aes256_enc(ctr, rk);
        inc32_impl(ctx->ctr);
        __m128i c = _mm_loadu_si128((const __m128i *)(ct + done));
        _mm_storeu_si128((__m128i *)(pt + done), _mm_xor_si128(c, ks));
        done += 16;
    }
    ctx->ks_used = 16;

    /* Trailing partial */
    if (done < len) {
        __m128i ctr = _mm_loadu_si128((const __m128i *)ctx->ctr);
        __m128i ks  = ni_aes256_enc(ctr, rk);
        inc32_impl(ctx->ctr);
        _mm_storeu_si128((__m128i *)ctx->ks, ks);
        ctx->ks_used = 0;
        while (done < len) {
            pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
            done++;
        }
    }
}

/* ---- PCLMULQDQ GHASH (carryless multiply + shift-XOR reduction) ---- */

static const uint8_t _ghash_bswap[16] __attribute__((aligned(16))) =
    {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};

/* Byte-swap H and multiply by x (left-shift 1 bit with reduction) to
 * compensate for the reflected-domain CLMUL convention.  Without this
 * shift, the result is off by a factor of x. */
__attribute__((target("pclmul,ssse3")))
static inline __m128i _ghash_prep_h(const uint8_t H[16], __m128i bswap)
{
    __m128i h = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)H), bswap);
    /* Save bit 127 before shift */
    __m128i top = _mm_srli_si128(_mm_srli_epi64(h, 63), 8);
    /* Left-shift h by 1, carry from low lane to high lane */
    __m128i lo_carry = _mm_slli_si128(_mm_srli_epi64(h, 63), 8);
    h = _mm_or_si128(_mm_slli_epi64(h, 1), lo_carry);
    /* If bit 127 was set, reduce: XOR with reflected polynomial constant
     * x^127 + x^126 + x^121 + 1 = 0xC200000000000000_0000000000000001 */
    __m128i mask = _mm_shuffle_epi32(
        _mm_sub_epi64(_mm_setzero_si128(), top), 0x44);
    return _mm_xor_si128(h, _mm_and_si128(
        _mm_set_epi64x((long long)0xC200000000000000ULL, 1LL), mask));
}

/* Single-block GHASH: state = (state ^ block) * H   in GF(2^128) */
__attribute__((target("pclmul,ssse3")))
static void ni_ghash_update_blk(uint8_t state[16], const uint8_t H[16],
                                const uint8_t block[16])
{
    __m128i bswap = _mm_load_si128((const __m128i *)_ghash_bswap);
    __m128i S = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)state), bswap);
    __m128i B = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)block), bswap);
    __m128i h = _ghash_prep_h(H, bswap);

    S = _mm_xor_si128(S, B);

    /* Karatsuba multiply: S * h  → 256-bit (T1 : T0) */
    __m128i T0 = _mm_clmulepi64_si128(S, h, 0x00);
    __m128i T1 = _mm_clmulepi64_si128(S, h, 0x11);
    __m128i T2 = _mm_xor_si128(_mm_clmulepi64_si128(S, h, 0x01),
                                _mm_clmulepi64_si128(S, h, 0x10));
    T0 = _mm_xor_si128(T0, _mm_slli_si128(T2, 8));
    T1 = _mm_xor_si128(T1, _mm_srli_si128(T2, 8));

    /* Reduce mod x^128 + x^127 + x^126 + x^121 + 1  (reflected poly).
     * Two-phase shift-XOR from Intel CLMUL whitepaper. */
    __m128i D = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(T0, 63),
                                             _mm_slli_epi64(T0, 62)),
                              _mm_slli_epi64(T0, 57));
    T0 = _mm_xor_si128(T0, _mm_slli_si128(D, 8));
    T1 = _mm_xor_si128(T1, _mm_srli_si128(D, 8));

    T1 = _mm_xor_si128(T1, _mm_xor_si128(T0,
            _mm_xor_si128(_mm_srli_epi64(T0, 1),
            _mm_xor_si128(_mm_srli_epi64(T0, 2),
                          _mm_srli_epi64(T0, 7)))));

    _mm_storeu_si128((__m128i *)state, _mm_shuffle_epi8(T1, bswap));
}

/* Multi-block GHASH: keeps state in reflected form across blocks to
 * avoid per-block byte-swap overhead (2 swaps saved per block). */
__attribute__((target("pclmul,ssse3")))
static void ni_ghash_update_bulk(uint8_t state[16], const uint8_t H[16],
                                 const uint8_t *data, size_t nblocks)
{
    __m128i bswap = _mm_load_si128((const __m128i *)_ghash_bswap);
    __m128i h = _ghash_prep_h(H, bswap);
    __m128i S = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)state), bswap);

    for (size_t i = 0; i < nblocks; i++) {
        __m128i B = _mm_shuffle_epi8(
            _mm_loadu_si128((const __m128i *)(data + i * 16)), bswap);
        S = _mm_xor_si128(S, B);

        __m128i T0 = _mm_clmulepi64_si128(S, h, 0x00);
        __m128i T1 = _mm_clmulepi64_si128(S, h, 0x11);
        __m128i T2 = _mm_xor_si128(_mm_clmulepi64_si128(S, h, 0x01),
                                    _mm_clmulepi64_si128(S, h, 0x10));
        T0 = _mm_xor_si128(T0, _mm_slli_si128(T2, 8));
        T1 = _mm_xor_si128(T1, _mm_srli_si128(T2, 8));

        __m128i D = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(T0, 63),
                                                 _mm_slli_epi64(T0, 62)),
                                  _mm_slli_epi64(T0, 57));
        T0 = _mm_xor_si128(T0, _mm_slli_si128(D, 8));
        T1 = _mm_xor_si128(T1, _mm_srli_si128(D, 8));

        S = _mm_xor_si128(T1, _mm_xor_si128(T0,
                _mm_xor_si128(_mm_srli_epi64(T0, 1),
                _mm_xor_si128(_mm_srli_epi64(T0, 2),
                              _mm_srli_epi64(T0, 7)))));
    }

    _mm_storeu_si128((__m128i *)state, _mm_shuffle_epi8(S, bswap));
}

#endif /* x86-64 */

/* ================================================================== */
/*  ARM Crypto Extensions (aarch64 only)                               */
/* ================================================================== */

#if defined(__aarch64__)
#include <arm_neon.h>

/* Set at startup by _detect_hw_arm() */
static int hw_aes  = 0;
static int hw_pmull = 0;

/* AT_HWCAP = 16, HWCAP_AES = 1<<3, HWCAP_PMULL = 1<<4 */
__attribute__((constructor))
static void _detect_hw_arm(void)
{
    /* Read /proc/self/auxv to detect ARM crypto capabilities */
    unsigned long type, val;
    int fd = -1;
    /* Use raw syscall-style open to avoid pulling in <fcntl.h> */
    extern int open(const char *, int, ...);
    extern long read(int, void *, unsigned long);
    extern int close(int);
    fd = open("/proc/self/auxv", 0 /* O_RDONLY */, 0);
    if (fd < 0) return;
    unsigned long buf[2];
    while (read(fd, buf, sizeof(buf)) == (long)sizeof(buf)) {
        type = buf[0]; val = buf[1];
        if (type == 0) break;  /* AT_NULL */
        if (type == 16) {      /* AT_HWCAP */
            hw_aes  = !!(val & (1UL << 3));   /* HWCAP_AES  */
            hw_pmull = !!(val & (1UL << 4));   /* HWCAP_PMULL */
            fprintf(stderr, "[antirev] ARM CE detect: hwcap=0x%lx aes=%d pmull=%d\n",
                    val, hw_aes, hw_pmull);
            break;
        }
    }
    close(fd);
    if (!hw_aes)
        fprintf(stderr, "[antirev] ARM CE: AT_HWCAP not found, using software AES\n");
}

/* Forward declaration of software key expansion (defined below) */
static void sw_key_expand(const uint8_t key[32], uint8_t rk[240]);

/* ---- ARM CE AES-256 single block encryption ---- */

__attribute__((target("arch=armv8-a+crypto")))
static inline uint8x16_t ce_aes256_enc(uint8x16_t block, const uint8x16_t rk[15])
{
    /* ARM vaeseq_u8 does: AddRoundKey(data, key) then SubBytes then ShiftRows.
     * So the pattern is: AESE(block, rk[i]) -> AESMC(block) for rounds 0..12,
     * then AESE(block, rk[13]) -> XOR with rk[14] for the last round. */
    block = vaesmcq_u8(vaeseq_u8(block, rk[0]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[1]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[2]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[3]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[4]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[5]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[6]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[7]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[8]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[9]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[10]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[11]));
    block = vaesmcq_u8(vaeseq_u8(block, rk[12]));
    /* Last round: AESE (no MixColumns) + XOR final key */
    block = vaeseq_u8(block, rk[13]);
    return veorq_u8(block, rk[14]);
}

/* 4-wide AES-256 encryption — pipeline interleaving for throughput */
__attribute__((target("arch=armv8-a+crypto")))
static inline void ce_aes256_enc4(uint8x16_t *b0, uint8x16_t *b1,
                                  uint8x16_t *b2, uint8x16_t *b3,
                                  const uint8x16_t rk[15])
{
    for (int r = 0; r < 13; r++) {
        *b0 = vaesmcq_u8(vaeseq_u8(*b0, rk[r]));
        *b1 = vaesmcq_u8(vaeseq_u8(*b1, rk[r]));
        *b2 = vaesmcq_u8(vaeseq_u8(*b2, rk[r]));
        *b3 = vaesmcq_u8(vaeseq_u8(*b3, rk[r]));
    }
    *b0 = veorq_u8(vaeseq_u8(*b0, rk[13]), rk[14]);
    *b1 = veorq_u8(vaeseq_u8(*b1, rk[13]), rk[14]);
    *b2 = veorq_u8(vaeseq_u8(*b2, rk[13]), rk[14]);
    *b3 = veorq_u8(vaeseq_u8(*b3, rk[13]), rk[14]);
}

/* ---- ARM CE init / ctr_decrypt ---- */

__attribute__((target("arch=armv8-a+crypto")))
static void ce_init(aes256gcm_ctx *ctx,
                    const uint8_t key[32], const uint8_t iv[12])
{
    /* Use software key expansion, then load round keys as uint8x16_t */
    sw_key_expand(key, ctx->rk);

    /* H = AES_K(0^128) */
    memset(ctx->H, 0, 16);
    uint8x16_t H = vdupq_n_u8(0);
    const uint8x16_t *rk = (const uint8x16_t *)ctx->rk;
    H = ce_aes256_enc(H, rk);
    vst1q_u8(ctx->H, H);

    /* J0 = IV || 0x00000001 */
    memset(ctx->J0, 0, 16);
    memcpy(ctx->J0, iv, 12);
    ctx->J0[15] = 0x01;

    memset(ctx->ghash,     0, 16);
    memset(ctx->ghash_buf, 0, 16);
    ctx->ghash_bytes   = 0;
    ctx->ghash_buf_len = 0;

    memcpy(ctx->ctr, ctx->J0, 16);
    inc32_impl(ctx->ctr);
    ctx->ks_used = 16;
}

__attribute__((target("arch=armv8-a+crypto")))
static void ce_ctr_decrypt(aes256gcm_ctx *ctx,
                           const uint8_t *ct, uint8_t *pt, size_t len)
{
    const uint8x16_t *rk = (const uint8x16_t *)ctx->rk;
    size_t done = 0;

    /* Drain partial keystream */
    while (done < len && ctx->ks_used < 16) {
        pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
        done++;
    }

    /* 4-wide blocks (AES pipeline interleaving) */
    while (done + 64 <= len) {
        uint8x16_t c0 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
        uint8x16_t c1 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
        uint8x16_t c2 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
        uint8x16_t c3 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
        ce_aes256_enc4(&c0, &c1, &c2, &c3, rk);
        uint8x16_t d0 = vld1q_u8(ct + done);
        uint8x16_t d1 = vld1q_u8(ct + done + 16);
        uint8x16_t d2 = vld1q_u8(ct + done + 32);
        uint8x16_t d3 = vld1q_u8(ct + done + 48);
        vst1q_u8(pt + done,      veorq_u8(d0, c0));
        vst1q_u8(pt + done + 16, veorq_u8(d1, c1));
        vst1q_u8(pt + done + 32, veorq_u8(d2, c2));
        vst1q_u8(pt + done + 48, veorq_u8(d3, c3));
        done += 64;
    }
    /* Remaining 1-3 full blocks */
    while (done + 16 <= len) {
        uint8x16_t ctr = vld1q_u8(ctx->ctr);
        uint8x16_t ks  = ce_aes256_enc(ctr, rk);
        inc32_impl(ctx->ctr);
        uint8x16_t c = vld1q_u8(ct + done);
        vst1q_u8(pt + done, veorq_u8(c, ks));
        done += 16;
    }
    ctx->ks_used = 16;

    /* Trailing partial */
    if (done < len) {
        uint8x16_t ctr = vld1q_u8(ctx->ctr);
        uint8x16_t ks  = ce_aes256_enc(ctr, rk);
        inc32_impl(ctx->ctr);
        vst1q_u8(ctx->ks, ks);
        ctx->ks_used = 0;
        while (done < len) {
            pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
            done++;
        }
    }
}

/* ---- PMULL GHASH (carryless multiply + reduction) ---- */

/* Byte-reverse a 128-bit vector */
static inline uint8x16_t ce_bswap128(uint8x16_t v)
{
    static const uint8_t idx[16] = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
    return vqtbl1q_u8(v, vld1q_u8(idx));
}

/* Prepare H for PMULL: byte-swap and left-shift by 1 with reduction,
 * same adjustment as the x86 path for reflected-domain CLMUL. */
__attribute__((target("arch=armv8-a+crypto")))
static inline poly128_t ce_ghash_prep_h(const uint8_t H[16])
{
    uint8x16_t h = ce_bswap128(vld1q_u8(H));
    /* Left-shift h by 1 bit, with carry between 64-bit lanes */
    uint64x2_t h64 = vreinterpretq_u64_u8(h);
    uint64x2_t shifted = vshlq_n_u64(h64, 1);
    uint64x2_t carry   = vshrq_n_u64(h64, 63);
    /* carry from low lane goes to high lane bit 0 */
    uint64x2_t carry_up = vextq_u64(vdupq_n_u64(0), carry, 1);
    h64 = vorrq_u64(shifted, carry_up);
    /* If bit 127 was set (now in carry lane 1), reduce with polynomial */
    uint64_t top_bit = vgetq_lane_u64(carry, 1);
    if (top_bit) {
        uint64x2_t poly = vcombine_u64(vcreate_u64(1ULL),
                                        vcreate_u64(0xC200000000000000ULL));
        h64 = veorq_u64(h64, poly);
    }
    return vreinterpretq_p128_u64(h64);
}

/* PMULL-based GF(2^128) multiply and reduce */
__attribute__((target("arch=armv8-a+crypto")))
static inline uint8x16_t ce_gmul(uint8x16_t S, poly128_t h_p128)
{
    uint64x2_t h = vreinterpretq_u64_p128(h_p128);
    uint64x2_t s = vreinterpretq_u64_u8(S);

    /* Karatsuba multiplication: S * h -> 256-bit result (T1 : T0) */
    poly128_t r0 = vmull_p64((poly64_t)vgetq_lane_u64(s, 0),
                              (poly64_t)vgetq_lane_u64(h, 0));
    poly128_t r1 = vmull_p64((poly64_t)vgetq_lane_u64(s, 1),
                              (poly64_t)vgetq_lane_u64(h, 1));
    poly128_t rm0 = vmull_p64((poly64_t)vgetq_lane_u64(s, 0),
                               (poly64_t)vgetq_lane_u64(h, 1));
    poly128_t rm1 = vmull_p64((poly64_t)vgetq_lane_u64(s, 1),
                               (poly64_t)vgetq_lane_u64(h, 0));

    uint64x2_t T0 = vreinterpretq_u64_p128(r0);
    uint64x2_t T1 = vreinterpretq_u64_p128(r1);
    uint64x2_t T2 = veorq_u64(vreinterpretq_u64_p128(rm0),
                                vreinterpretq_u64_p128(rm1));

    /* Add middle product to T0 high and T1 low */
    T0 = veorq_u64(T0, vextq_u64(vdupq_n_u64(0), T2, 1));  /* T2_lo -> T0 high */
    T1 = veorq_u64(T1, vextq_u64(T2, vdupq_n_u64(0), 1));  /* T2_hi -> T1 low  */

    /* Reduce mod x^128 + x^127 + x^126 + x^121 + 1 (reflected poly).
     * Two-phase shift-XOR reduction (same algorithm as x86 path). */
    uint64x2_t D = veorq_u64(veorq_u64(vshlq_n_u64(T0, 63),
                                         vshlq_n_u64(T0, 62)),
                              vshlq_n_u64(T0, 57));
    T0 = veorq_u64(T0, vextq_u64(vdupq_n_u64(0), D, 1));
    T1 = veorq_u64(T1, vextq_u64(D, vdupq_n_u64(0), 1));

    T1 = veorq_u64(T1, veorq_u64(T0,
            veorq_u64(vshrq_n_u64(T0, 1),
            veorq_u64(vshrq_n_u64(T0, 2),
                      vshrq_n_u64(T0, 7)))));

    return vreinterpretq_u8_u64(T1);
}

/* Single-block GHASH: state = (state ^ block) * H   in GF(2^128) */
__attribute__((target("arch=armv8-a+crypto")))
static void ce_ghash_update_blk(uint8_t state[16], const uint8_t H[16],
                                const uint8_t block[16])
{
    uint8x16_t S = ce_bswap128(vld1q_u8(state));
    uint8x16_t B = ce_bswap128(vld1q_u8(block));
    poly128_t h = ce_ghash_prep_h(H);

    S = veorq_u8(S, B);
    S = ce_gmul(S, h);

    vst1q_u8(state, ce_bswap128(S));
}

/* Multi-block GHASH: keeps state in reflected form across blocks */
__attribute__((target("arch=armv8-a+crypto")))
static void ce_ghash_update_bulk(uint8_t state[16], const uint8_t H[16],
                                 const uint8_t *data, size_t nblocks)
{
    poly128_t h = ce_ghash_prep_h(H);
    uint8x16_t S = ce_bswap128(vld1q_u8(state));

    for (size_t i = 0; i < nblocks; i++) {
        uint8x16_t B = ce_bswap128(vld1q_u8(data + i * 16));
        S = veorq_u8(S, B);
        S = ce_gmul(S, h);
    }

    vst1q_u8(state, ce_bswap128(S));
}

#endif /* __aarch64__ */

/* ================================================================== */
/*  Portable software AES (always compiled)                            */
/* ================================================================== */

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

static const uint8_t rcon[8] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40 };

static void sw_key_expand(const uint8_t key[32], uint8_t rk[240])
{
    memcpy(rk, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 8 == 0) {
            uint8_t tmp = t[0];
            t[0] = sbox[t[1]] ^ rcon[i / 8];
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[tmp];
        } else if (i % 8 == 4) {
            t[0] = sbox[t[0]]; t[1] = sbox[t[1]];
            t[2] = sbox[t[2]]; t[3] = sbox[t[3]];
        }
        rk[i*4+0] = rk[(i-8)*4+0] ^ t[0];
        rk[i*4+1] = rk[(i-8)*4+1] ^ t[1];
        rk[i*4+2] = rk[(i-8)*4+2] ^ t[2];
        rk[i*4+3] = rk[(i-8)*4+3] ^ t[3];
    }
}

#define B(r,c) block[(r) + 4*(c)]

static void sub_bytes(uint8_t block[16])
{
    for (int i = 0; i < 16; i++) block[i] = sbox[block[i]];
}

static void shift_rows(uint8_t block[16])
{
    uint8_t t;
    t=block[1]; block[1]=block[5]; block[5]=block[9]; block[9]=block[13]; block[13]=t;
    t=block[2]; block[2]=block[10]; block[10]=t;
    t=block[6]; block[6]=block[14]; block[14]=t;
    t=block[15]; block[15]=block[11]; block[11]=block[7]; block[7]=block[3]; block[3]=t;
}

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

static void sw_aes256_enc(const uint8_t rk[240], uint8_t block[16])
{
    add_round_key(block, rk);
    for (int r = 1; r <= 13; r++) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, rk + r * 16);
    }
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, rk + 14 * 16);
}

/* GF(2^128) multiply (software) */
static void sw_gcm_mult(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16])
{
    uint8_t V[16];
    memset(Z, 0, 16);
    memcpy(V, Y, 16);

    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            if ((X[i] >> j) & 1) {
                for (int k = 0; k < 16; k++) Z[k] ^= V[k];
            }
            int lsb = V[15] & 1;
            for (int k = 15; k > 0; k--)
                V[k] = (uint8_t)((V[k] >> 1) | (V[k-1] << 7));
            V[0] >>= 1;
            if (lsb) V[0] ^= 0xe1;
        }
    }
}

static void inc32_impl(uint8_t cb[16])
{
    uint32_t ctr = ((uint32_t)cb[12] << 24) | ((uint32_t)cb[13] << 16)
                 | ((uint32_t)cb[14] <<  8) |  (uint32_t)cb[15];
    ctr++;
    cb[12] = (uint8_t)(ctr >> 24);
    cb[13] = (uint8_t)(ctr >> 16);
    cb[14] = (uint8_t)(ctr >>  8);
    cb[15] = (uint8_t) ctr;
}

static void sw_ghash_update_blk(uint8_t state[16], const uint8_t H[16],
                                const uint8_t block[16])
{
    uint8_t tmp[16], result[16];
    for (int i = 0; i < 16; i++) tmp[i] = state[i] ^ block[i];
    sw_gcm_mult(tmp, H, result);
    memcpy(state, result, 16);
}

/* Dispatch wrapper: use HW carryless multiply when available, else software */
static inline void ghash_blk(uint8_t state[16], const uint8_t H[16],
                              const uint8_t block[16])
{
#if defined(__x86_64__) || defined(_M_X64)
    if (hw_pclmul) { ni_ghash_update_blk(state, H, block); return; }
#elif defined(__aarch64__)
    if (hw_pmull) { ce_ghash_update_blk(state, H, block); return; }
#endif
    sw_ghash_update_blk(state, H, block);
}

/* ================================================================== */
/*  Public streaming API (dispatches to HW or SW)                      */
/* ================================================================== */

void aes256gcm_init(aes256gcm_ctx *ctx,
                    const uint8_t key[32], const uint8_t iv[12])
{
#if defined(__x86_64__) || defined(_M_X64)
    if (hw_aesni) {
        ni_init(ctx, key, iv);
        return;
    }
#elif defined(__aarch64__)
    if (hw_aes) {
        ce_init(ctx, key, iv);
        return;
    }
#endif

    sw_key_expand(key, ctx->rk);

    memset(ctx->H, 0, 16);
    sw_aes256_enc(ctx->rk, ctx->H);

    memset(ctx->J0, 0, 16);
    memcpy(ctx->J0, iv, 12);
    ctx->J0[15] = 0x01;

    memset(ctx->ghash,     0, 16);
    memset(ctx->ghash_buf, 0, 16);
    ctx->ghash_bytes   = 0;
    ctx->ghash_buf_len = 0;

    memcpy(ctx->ctr, ctx->J0, 16);
    inc32_impl(ctx->ctr);
    ctx->ks_used = 16;
}

void aes256gcm_ghash_update(aes256gcm_ctx *ctx,
                             const uint8_t *ct, size_t len)
{
    size_t pos = 0;
    if (ctx->ghash_buf_len > 0) {
        size_t need = 16 - ctx->ghash_buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(ctx->ghash_buf + ctx->ghash_buf_len, ct, take);
        ctx->ghash_buf_len += take;
        pos += take;
        if (ctx->ghash_buf_len == 16) {
            ghash_blk(ctx->ghash, ctx->H, ctx->ghash_buf);
            ctx->ghash_buf_len = 0;
        }
    }
#if defined(__x86_64__) || defined(_M_X64)
    if (hw_pclmul) {
        size_t nblocks = (len - pos) / 16;
        if (nblocks > 0) {
            ni_ghash_update_bulk(ctx->ghash, ctx->H, ct + pos, nblocks);
            pos += nblocks * 16;
        }
    } else
#elif defined(__aarch64__)
    if (hw_pmull) {
        size_t nblocks = (len - pos) / 16;
        if (nblocks > 0) {
            ce_ghash_update_bulk(ctx->ghash, ctx->H, ct + pos, nblocks);
            pos += nblocks * 16;
        }
    } else
#endif
    {
        while (pos + 16 <= len) {
            sw_ghash_update_blk(ctx->ghash, ctx->H, ct + pos);
            pos += 16;
        }
    }
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

    if (ctx->ghash_buf_len > 0) {
        uint8_t padded[16] = {0};
        memcpy(padded, ctx->ghash_buf, ctx->ghash_buf_len);
        ghash_blk(ghash, ctx->H, padded);
    }

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
    ghash_blk(ghash, ctx->H, len_block);

    uint8_t T[16];
    memcpy(T, ctx->J0, 16);
#if defined(__x86_64__) || defined(_M_X64)
    if (hw_aesni) {
        __m128i t = _mm_loadu_si128((const __m128i *)T);
        t = ni_aes256_enc(t, (const __m128i *)ctx->rk);
        _mm_storeu_si128((__m128i *)T, t);
    } else
#elif defined(__aarch64__)
    if (hw_aes) {
        uint8x16_t t = vld1q_u8(T);
        t = ce_aes256_enc(t, (const uint8x16_t *)ctx->rk);
        vst1q_u8(T, t);
    } else
#endif
    sw_aes256_enc(ctx->rk, T);
    for (int i = 0; i < 16; i++) T[i] ^= ghash[i];

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= T[i] ^ tag[i];
    return (diff == 0) ? 0 : -1;
}

void aes256gcm_ctr_decrypt(aes256gcm_ctx *ctx,
                            const uint8_t *ct, uint8_t *pt, size_t len)
{
#if defined(__x86_64__) || defined(_M_X64)
    if (hw_aesni) { ni_ctr_decrypt(ctx, ct, pt, len); return; }
#elif defined(__aarch64__)
    if (hw_aes) { ce_ctr_decrypt(ctx, ct, pt, len); return; }
#endif

    size_t done = 0;
    while (done < len && ctx->ks_used < 16) {
        pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
        done++;
    }
    while (done + 16 <= len) {
        memcpy(ctx->ks, ctx->ctr, 16);
        sw_aes256_enc(ctx->rk, ctx->ks);
        inc32_impl(ctx->ctr);
        for (int j = 0; j < 16; j++)
            pt[done + j] = ct[done + j] ^ ctx->ks[j];
        ctx->ks_used = 16;
        done += 16;
    }
    if (done < len) {
        memcpy(ctx->ks, ctx->ctr, 16);
        sw_aes256_enc(ctx->rk, ctx->ks);
        inc32_impl(ctx->ctr);
        ctx->ks_used = 0;
        while (done < len) {
            pt[done] = ct[done] ^ ctx->ks[ctx->ks_used++];
            done++;
        }
    }
}

/* Single-pass: GHASH + CTR simultaneously (one read of ciphertext).
 * GHASH must read each block before CTR decryption overwrites it,
 * so ct == pt (in-place) is safe.  Uses 4-wide CTR pipelining. */
void aes256gcm_onepass(aes256gcm_ctx *ctx,
                       const uint8_t *ct, uint8_t *pt, size_t len)
{
    size_t pos = 0;

#if defined(__x86_64__) || defined(_M_X64)
    if (hw_aesni) {
        const __m128i *rk = (const __m128i *)ctx->rk;

        /* 4-wide blocks: GHASH 4 blocks, then CTR decrypt 4-wide */
        while (pos + 64 <= len) {
            if (hw_pclmul)
                ni_ghash_update_bulk(ctx->ghash, ctx->H, ct + pos, 4);
            else
                for (int k = 0; k < 4; k++)
                    sw_ghash_update_blk(ctx->ghash, ctx->H, ct + pos + k * 16);

            __m128i c0 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
            __m128i c1 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
            __m128i c2 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
            __m128i c3 = _mm_loadu_si128((const __m128i *)ctx->ctr); inc32_impl(ctx->ctr);
            ni_aes256_enc4(&c0, &c1, &c2, &c3, rk);
            __m128i d0 = _mm_loadu_si128((const __m128i *)(ct + pos));
            __m128i d1 = _mm_loadu_si128((const __m128i *)(ct + pos + 16));
            __m128i d2 = _mm_loadu_si128((const __m128i *)(ct + pos + 32));
            __m128i d3 = _mm_loadu_si128((const __m128i *)(ct + pos + 48));
            _mm_storeu_si128((__m128i *)(pt + pos),      _mm_xor_si128(d0, c0));
            _mm_storeu_si128((__m128i *)(pt + pos + 16), _mm_xor_si128(d1, c1));
            _mm_storeu_si128((__m128i *)(pt + pos + 32), _mm_xor_si128(d2, c2));
            _mm_storeu_si128((__m128i *)(pt + pos + 48), _mm_xor_si128(d3, c3));
            pos += 64;
        }

        /* Remaining full blocks (1-3) */
        while (pos + 16 <= len) {
            ghash_blk(ctx->ghash, ctx->H, ct + pos);
            __m128i ctr = _mm_loadu_si128((const __m128i *)ctx->ctr);
            __m128i ks = ni_aes256_enc(ctr, rk);
            inc32_impl(ctx->ctr);
            __m128i c = _mm_loadu_si128((const __m128i *)(ct + pos));
            _mm_storeu_si128((__m128i *)(pt + pos), _mm_xor_si128(c, ks));
            pos += 16;
        }

        /* Trailing partial block */
        if (pos < len) {
            uint8_t padded[16] = {0};
            memcpy(padded, ct + pos, len - pos);
            ghash_blk(ctx->ghash, ctx->H, padded);
            __m128i ctr = _mm_loadu_si128((const __m128i *)ctx->ctr);
            __m128i ks = ni_aes256_enc(ctr, rk);
            inc32_impl(ctx->ctr);
            _mm_storeu_si128((__m128i *)ctx->ks, ks);
            ctx->ks_used = 0;
            while (pos < len) {
                pt[pos] = ct[pos] ^ ctx->ks[ctx->ks_used++];
                pos++;
            }
        }

        ctx->ghash_bytes += len;
        return;
    }
#elif defined(__aarch64__)
    if (hw_aes) {
        const uint8x16_t *rk = (const uint8x16_t *)ctx->rk;

        /* 4-wide blocks: GHASH 4 blocks, then CTR decrypt 4-wide */
        while (pos + 64 <= len) {
            if (hw_pmull)
                ce_ghash_update_bulk(ctx->ghash, ctx->H, ct + pos, 4);
            else
                for (int k = 0; k < 4; k++)
                    sw_ghash_update_blk(ctx->ghash, ctx->H, ct + pos + k * 16);

            uint8x16_t c0 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
            uint8x16_t c1 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
            uint8x16_t c2 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
            uint8x16_t c3 = vld1q_u8(ctx->ctr); inc32_impl(ctx->ctr);
            ce_aes256_enc4(&c0, &c1, &c2, &c3, rk);
            uint8x16_t d0 = vld1q_u8(ct + pos);
            uint8x16_t d1 = vld1q_u8(ct + pos + 16);
            uint8x16_t d2 = vld1q_u8(ct + pos + 32);
            uint8x16_t d3 = vld1q_u8(ct + pos + 48);
            vst1q_u8(pt + pos,      veorq_u8(d0, c0));
            vst1q_u8(pt + pos + 16, veorq_u8(d1, c1));
            vst1q_u8(pt + pos + 32, veorq_u8(d2, c2));
            vst1q_u8(pt + pos + 48, veorq_u8(d3, c3));
            pos += 64;
        }

        /* Remaining full blocks (1-3) */
        while (pos + 16 <= len) {
            ghash_blk(ctx->ghash, ctx->H, ct + pos);
            uint8x16_t ctr = vld1q_u8(ctx->ctr);
            uint8x16_t ks = ce_aes256_enc(ctr, rk);
            inc32_impl(ctx->ctr);
            uint8x16_t c = vld1q_u8(ct + pos);
            vst1q_u8(pt + pos, veorq_u8(c, ks));
            pos += 16;
        }

        /* Trailing partial block */
        if (pos < len) {
            uint8_t padded[16] = {0};
            memcpy(padded, ct + pos, len - pos);
            ghash_blk(ctx->ghash, ctx->H, padded);
            uint8x16_t ctr = vld1q_u8(ctx->ctr);
            uint8x16_t ks = ce_aes256_enc(ctr, rk);
            inc32_impl(ctx->ctr);
            vst1q_u8(ctx->ks, ks);
            ctx->ks_used = 0;
            while (pos < len) {
                pt[pos] = ct[pos] ^ ctx->ks[ctx->ks_used++];
                pos++;
            }
        }

        ctx->ghash_bytes += len;
        return;
    }
#endif

    /* Software fallback */
    while (pos + 16 <= len) {
        sw_ghash_update_blk(ctx->ghash, ctx->H, ct + pos);
        memcpy(ctx->ks, ctx->ctr, 16);
        sw_aes256_enc(ctx->rk, ctx->ks);
        inc32_impl(ctx->ctr);
        for (int j = 0; j < 16; j++)
            pt[pos + j] = ct[pos + j] ^ ctx->ks[j];
        pos += 16;
    }
    if (pos < len) {
        uint8_t padded[16] = {0};
        memcpy(padded, ct + pos, len - pos);
        sw_ghash_update_blk(ctx->ghash, ctx->H, padded);
        memcpy(ctx->ks, ctx->ctr, 16);
        sw_aes256_enc(ctx->rk, ctx->ks);
        inc32_impl(ctx->ctr);
        ctx->ks_used = 0;
        while (pos < len) {
            pt[pos] = ct[pos] ^ ctx->ks[ctx->ks_used++];
            pos++;
        }
    }
    ctx->ghash_bytes += len;
}
