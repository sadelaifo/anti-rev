/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aesgcm_sw.h — software AES-256-GCM decrypt fallback for vcachefs.
 * See aesgcm_sw.c.  All entry points are self-contained (no kernel crypto API).
 */
#ifndef _VCACHEFS_AESGCM_SW_H
#define _VCACHEFS_AESGCM_SW_H

#include <linux/types.h>

/* Build S-box T-tables and run the known-answer self-test.  Call once at
 * module init.  Returns 0 if the self-test passes, <0 otherwise (the caller
 * should then refuse to use the software path). */
int vcf_sw_gcm_init(void);

/* Re-run the known-answer vectors.  0 on pass, <0 on failure. */
int vcf_sw_gcm_selftest(void);

/* Decrypt an AES-256-GCM message (key=32B, iv=12B, tag=16B, no AAD).
 * `out` must hold ct_len bytes.  Returns 0 on success (tag verified),
 * -1 on tag mismatch.  The tag is verified BEFORE plaintext is produced. */
int vcf_sw_gcm_decrypt(const u8 *key, const u8 *iv,
		       const u8 *ct, unsigned long ct_len,
		       const u8 *tag, u8 *out);

#endif /* _VCACHEFS_AESGCM_SW_H */
