// SPDX-License-Identifier: GPL-2.0
/*
 * aesgcm_sw.c — self-contained software AES-256-GCM decrypt for vcachefs.
 *
 * WHY THIS EXISTS: the shipping target is a diskless ARM64 appliance whose
 * vendor kernel is built WITHOUT the GCM stack (CONFIG_CRYPTO_GCM/GHASH not
 * set) and has no modprobe, so crypto_alloc_aead("gcm(aes)") returns -ENOENT
 * and decrypt cannot run.  This module provides AES-256-GCM entirely in its
 * own code — no kernel crypto API, no CONFIG_CRYPTO_* dependency — so vcachefs
 * decrypts on any kernel.  crypto.c uses the kernel's (possibly CE-accelerated)
 * gcm(aes) when present and falls back to this only when it is absent.
 *
 * Scope: DECRYPT only (that is all vcachefs does).  GCM decrypt needs AES only
 * in the ENCRYPT direction (CTR keystream + H = E_K(0) + E_K(J0)), so there is
 * no inverse S-box / decrypt round here.  96-bit IV, 128-bit tag, no AAD —
 * matching protect.make_container()/`cryptography`'s AESGCM(key).encrypt(iv,pt,
 * None).  Whole-file one-shot; the caller decrypts once per file into a buffer.
 *
 * Correctness: the T-table AES + Shoup 4-bit-table GHASH were validated in
 * userspace against python-`cryptography` for lengths 0/16/32/61/4096, and
 * vcf_sw_gcm_selftest() re-runs baked known-answer vectors at module init on
 * the real kernel (refuses to arm the software path if they fail) so a
 * mis-build can never silently produce wrong plaintext.
 *
 * Side-channel note: this is a table-based (cache-timing-observable) AES.  Per
 * the project threat model the capable adversary never touches the live box, so
 * timing leakage is out of scope; if that ever changes, swap in a constant-time
 * core.  The value here is portability, not resistance to a co-resident attacker.
 */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#include <linux/printk.h>
#include "aesgcm_sw.h"
#else
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;
int vcf_sw_gcm_init(void);
int vcf_sw_gcm_selftest(void);
int vcf_sw_gcm_decrypt(const u8 *key, const u8 *iv,
		       const u8 *ct, unsigned long ct_len,
		       const u8 *tag, u8 *out);
#endif

#define AES256_RK_WORDS 60	/* 4 * (Nr+1), Nr=14 */

/* ── byte-order helpers (endian-independent) ─────────────────────────── */
static inline u32 get_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	       ((u32)p[2] << 8) | (u32)p[3];
}
static inline void put_be32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);  p[3] = (u8)v;
}

/* ── AES S-box + round constants ─────────────────────────────────────── */
static const u8 sbox[256] = {
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
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const u32 rcon[10] = {
	0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
	0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
};

/* ── T-tables (built once from the S-box at init) ────────────────────── */
static u32 Te0[256], Te1[256], Te2[256], Te3[256];
static int aes_tables_ready;

static u8 gmul(u8 a, u8 b)
{
	u8 r = 0;
	int i;
	for (i = 0; i < 8; i++) {
		if (b & 1)
			r ^= a;
		{
			u8 hi = a & 0x80;
			a = (u8)(a << 1);
			if (hi)
				a ^= 0x1b;
		}
		b >>= 1;
	}
	return r;
}

static void aes_build_tables(void)
{
	int x;
	if (aes_tables_ready)
		return;
	for (x = 0; x < 256; x++) {
		u8 s = sbox[x], s2 = gmul(s, 2), s3 = gmul(s, 3);
		u32 t = ((u32)s2 << 24) | ((u32)s << 16) | ((u32)s << 8) | s3;
		Te0[x] = t;
		Te1[x] = (t >> 8)  | (t << 24);
		Te2[x] = (t >> 16) | (t << 16);
		Te3[x] = (t >> 24) | (t << 8);
	}
	aes_tables_ready = 1;
}

/* ── AES-256 key schedule (encrypt) ──────────────────────────────────── */
static void aes256_key_expand(const u8 key[32], u32 rk[AES256_RK_WORDS])
{
	const int Nk = 8, Nr = 14;
	int i;
	for (i = 0; i < Nk; i++)
		rk[i] = get_be32(key + 4 * i);
	for (i = Nk; i < 4 * (Nr + 1); i++) {
		u32 t = rk[i - 1];
		if (i % Nk == 0) {
			t = (t << 8) | (t >> 24);	/* RotWord */
			t = ((u32)sbox[(t >> 24) & 0xff] << 24) |
			    ((u32)sbox[(t >> 16) & 0xff] << 16) |
			    ((u32)sbox[(t >> 8) & 0xff] << 8) |
			    (u32)sbox[t & 0xff];	/* SubWord */
			t ^= rcon[i / Nk - 1];
		} else if (i % Nk == 4) {
			t = ((u32)sbox[(t >> 24) & 0xff] << 24) |
			    ((u32)sbox[(t >> 16) & 0xff] << 16) |
			    ((u32)sbox[(t >> 8) & 0xff] << 8) |
			    (u32)sbox[t & 0xff];	/* SubWord (no rot) */
		}
		rk[i] = rk[i - Nk] ^ t;
	}
}

/* ── AES-256 encrypt one 16-byte block ───────────────────────────────── */
static void aes256_encrypt_block(const u32 rk[AES256_RK_WORDS],
				 const u8 in[16], u8 out[16])
{
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
	int r;

	s0 = get_be32(in +  0) ^ rk[0];
	s1 = get_be32(in +  4) ^ rk[1];
	s2 = get_be32(in +  8) ^ rk[2];
	s3 = get_be32(in + 12) ^ rk[3];

	for (r = 1; r < 14; r++) {
		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^
		     Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[4 * r + 0];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^
		     Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[4 * r + 1];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^
		     Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[4 * r + 2];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^
		     Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[4 * r + 3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}
	/* final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
	t0 = ((u32)sbox[(s0 >> 24) & 0xff] << 24) | ((u32)sbox[(s1 >> 16) & 0xff] << 16) |
	     ((u32)sbox[(s2 >> 8) & 0xff] << 8) | (u32)sbox[s3 & 0xff];
	t1 = ((u32)sbox[(s1 >> 24) & 0xff] << 24) | ((u32)sbox[(s2 >> 16) & 0xff] << 16) |
	     ((u32)sbox[(s3 >> 8) & 0xff] << 8) | (u32)sbox[s0 & 0xff];
	t2 = ((u32)sbox[(s2 >> 24) & 0xff] << 24) | ((u32)sbox[(s3 >> 16) & 0xff] << 16) |
	     ((u32)sbox[(s0 >> 8) & 0xff] << 8) | (u32)sbox[s1 & 0xff];
	t3 = ((u32)sbox[(s3 >> 24) & 0xff] << 24) | ((u32)sbox[(s0 >> 16) & 0xff] << 16) |
	     ((u32)sbox[(s1 >> 8) & 0xff] << 8) | (u32)sbox[s2 & 0xff];
	put_be32(out +  0, t0 ^ rk[56]);
	put_be32(out +  4, t1 ^ rk[57]);
	put_be32(out +  8, t2 ^ rk[58]);
	put_be32(out + 12, t3 ^ rk[59]);
}

/* ── GHASH over GF(2^128), Shoup 4-bit table (mbedTLS-style) ──────────── */
struct ghash_ctx {
	u64 HL[16];
	u64 HH[16];
};
static const u64 ghash_last4[16] = {
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

static void ghash_setup(struct ghash_ctx *g, const u8 H[16])
{
	u64 vh = ((u64)get_be32(H + 0) << 32) | get_be32(H + 4);
	u64 vl = ((u64)get_be32(H + 8) << 32) | get_be32(H + 12);
	int i, j;

	g->HL[8] = vl; g->HH[8] = vh;
	g->HL[0] = 0;  g->HH[0] = 0;
	for (i = 4; i > 0; i >>= 1) {
		u32 T = (u32)(vl & 1) * 0xe1000000U;
		vl = (vh << 63) | (vl >> 1);
		vh = (vh >> 1) ^ ((u64)T << 32);
		g->HL[i] = vl;
		g->HH[i] = vh;
	}
	for (i = 2; i <= 8; i <<= 1) {
		u64 hl = g->HL[i], hh = g->HH[i];
		for (j = 1; j < i; j++) {
			g->HH[i + j] = hh ^ g->HH[j];
			g->HL[i + j] = hl ^ g->HL[j];
		}
	}
}

/* out = out * H  (out is the 16-byte accumulator, updated in place) */
static void ghash_mul(const struct ghash_ctx *g, u8 out[16])
{
	u8 lo, hi, rem;
	u64 zh, zl;
	int i;

	lo = out[15] & 0xf;
	zh = g->HH[lo];
	zl = g->HL[lo];
	for (i = 15; i >= 0; i--) {
		lo = out[i] & 0xf;
		hi = (out[i] >> 4) & 0xf;
		if (i != 15) {
			rem = (u8)(zl & 0xf);
			zl = (zh << 60) | (zl >> 4);
			zh = (zh >> 4);
			zh ^= ghash_last4[rem] << 48;
			zh ^= g->HH[lo];
			zl ^= g->HL[lo];
		}
		rem = (u8)(zl & 0xf);
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);
		zh ^= ghash_last4[rem] << 48;
		zh ^= g->HH[hi];
		zl ^= g->HL[hi];
	}
	put_be32(out + 0,  (u32)(zh >> 32));
	put_be32(out + 4,  (u32)zh);
	put_be32(out + 8,  (u32)(zl >> 32));
	put_be32(out + 12, (u32)zl);
}

/* acc ^= block[0..len), then acc *= H  (len<=16, zero-padded) */
static void ghash_block(const struct ghash_ctx *g, u8 acc[16],
			const u8 *block, unsigned len)
{
	unsigned k;
	for (k = 0; k < len; k++)
		acc[k] ^= block[k];
	ghash_mul(g, acc);
}

static inline void inc32(u8 ctr[16])
{
	u32 c = get_be32(ctr + 12) + 1;
	put_be32(ctr + 12, c);
}

/* constant-time 16-byte compare: 0 if equal, nonzero otherwise */
static int ct_neq16(const u8 *a, const u8 *b)
{
	u8 d = 0;
	int i;
	for (i = 0; i < 16; i++)
		d |= (u8)(a[i] ^ b[i]);
	return d;
}

/*
 * Decrypt an AES-256-GCM message.  key=32B, iv=12B, tag=16B, no AAD.
 * out must hold ct_len bytes.  Returns 0 on success (tag verified),
 * -1 on tag mismatch, -22 (-EINVAL analogue) on misuse.  On failure out
 * is not left with authenticated plaintext (we verify BEFORE decrypting).
 */
int vcf_sw_gcm_decrypt(const u8 *key, const u8 *iv,
		       const u8 *ct, unsigned long ct_len,
		       const u8 *tag, u8 *out)
{
	u32 rk[AES256_RK_WORDS];
	struct ghash_ctx g;
	u8 H[16], J0[16], EJ0[16], acc[16], ks[16], blk[16], lenblk[16];
	u64 bits;
	unsigned long off;
	int i;

	if (!aes_tables_ready)
		aes_build_tables();

	aes256_key_expand(key, rk);

	/* H = E_K(0^128) */
	memset(blk, 0, 16);
	aes256_encrypt_block(rk, blk, H);
	ghash_setup(&g, H);

	/* J0 = IV || 0x00000001  (96-bit IV) */
	memcpy(J0, iv, 12);
	J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

	/* GHASH over ciphertext (no AAD), then the length block */
	memset(acc, 0, 16);
	for (off = 0; off + 16 <= ct_len; off += 16)
		ghash_block(&g, acc, ct + off, 16);
	if (off < ct_len) {
		memset(blk, 0, 16);
		memcpy(blk, ct + off, (unsigned)(ct_len - off));
		ghash_block(&g, acc, blk, 16);
	}
	memset(lenblk, 0, 16);		/* AAD length = 0 (high 8 bytes) */
	bits = (u64)ct_len * 8;
	put_be32(lenblk + 8,  (u32)(bits >> 32));
	put_be32(lenblk + 12, (u32)bits);
	ghash_block(&g, acc, lenblk, 16);

	/* tag = GHASH ⊕ E_K(J0) */
	aes256_encrypt_block(rk, J0, EJ0);
	for (i = 0; i < 16; i++)
		acc[i] ^= EJ0[i];

	if (ct_neq16(acc, tag)) {
		memset(rk, 0, sizeof(rk));
		return -1;			/* authentication failed */
	}

	/* CTR decrypt from inc32(J0) */
	memcpy(blk, J0, 16);
	inc32(blk);
	for (off = 0; off < ct_len; off += 16) {
		unsigned n = (ct_len - off >= 16) ? 16 : (unsigned)(ct_len - off);
		unsigned k;
		aes256_encrypt_block(rk, blk, ks);
		for (k = 0; k < n; k++)
			out[off + k] = ct[off + k] ^ ks[k];
		inc32(blk);
	}

	memset(rk, 0, sizeof(rk));
	return 0;
}

/* ── known-answer self-test (vectors from python-`cryptography`) ──────── */
static const u8 kat_key[32] = {
	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
	16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
};
static const u8 kat_iv[12] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
};
/* 61-byte message */
static const u8 kat_pt[61] = {
	0x76,0x63,0x61,0x63,0x68,0x65,0x66,0x73,0x20,0x73,0x6f,0x66,0x74,0x77,0x61,0x72,
	0x65,0x20,0x41,0x45,0x53,0x2d,0x32,0x35,0x36,0x2d,0x47,0x43,0x4d,0x20,0x6b,0x6e,
	0x6f,0x77,0x6e,0x2d,0x61,0x6e,0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,
	0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x20,0x31,0x32,0x33,0x34,0x35
};
static const u8 kat_ct[61] = {
	0xa4,0x59,0xc7,0x13,0x04,0xfd,0x7c,0x7d,0x3a,0x0f,0x2d,0xa8,0xb5,0x6f,0x95,0x8b,
	0xb5,0x69,0xad,0xd9,0xd4,0xad,0x51,0xdb,0x5a,0xdb,0x2b,0x51,0x04,0xaa,0x35,0x67,
	0x1a,0xf9,0x8b,0x29,0xef,0x4b,0x46,0xad,0x71,0x8f,0x4e,0xe6,0x3d,0x7a,0x6b,0xe8,
	0x94,0x4f,0x8f,0xfa,0xf5,0x4e,0x0c,0x41,0xff,0x50,0x4c,0x29,0x79
};
static const u8 kat_tag[16] = {
	0x4f,0x94,0x37,0xb1,0x13,0xe7,0x1d,0xa6,0x89,0x6a,0xfb,0x89,0x32,0xbd,0x56,0x39
};
/* block-aligned 16-byte vector */
static const u8 kat2_pt[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const u8 kat2_ct[16] = {
	0xd2,0x3b,0xa4,0x73,0x68,0x9d,0x1c,0x09,0x12,0x75,0x48,0xc5,0xcd,0x15,0xfa,0xf6
};
static const u8 kat2_tag[16] = {
	0x22,0xbe,0x22,0x44,0x8f,0x3a,0xd7,0x84,0x31,0x1b,0x0f,0x54,0xd0,0xd9,0x5e,0xf6
};
/* empty message (tag-only) */
static const u8 kat0_tag[16] = {
	0x9e,0xa2,0xc4,0xd8,0x33,0xe6,0x35,0x6b,0xeb,0xf2,0x97,0x3f,0x7e,0x71,0x89,0xe2
};

int vcf_sw_gcm_selftest(void)
{
	u8 out[61];

	aes_build_tables();

	if (vcf_sw_gcm_decrypt(kat_key, kat_iv, kat_ct, sizeof(kat_ct),
			       kat_tag, out) != 0 ||
	    memcmp(out, kat_pt, sizeof(kat_pt)) != 0)
		return -1;

	if (vcf_sw_gcm_decrypt(kat_key, kat_iv, kat2_ct, sizeof(kat2_ct),
			       kat2_tag, out) != 0 ||
	    memcmp(out, kat2_pt, sizeof(kat2_pt)) != 0)
		return -2;

	if (vcf_sw_gcm_decrypt(kat_key, kat_iv, out, 0, kat0_tag, out) != 0)
		return -3;

	/* negative: a corrupted tag must be rejected */
	{
		u8 bad[16];
		memcpy(bad, kat_tag, 16);
		bad[0] ^= 0x01;
		if (vcf_sw_gcm_decrypt(kat_key, kat_iv, kat_ct, sizeof(kat_ct),
				       bad, out) == 0)
			return -4;
	}
	return 0;
}

int vcf_sw_gcm_init(void)
{
	aes_build_tables();
	return vcf_sw_gcm_selftest();
}
