/* SPDX-License-Identifier: GPL-2.0 */
/*
 * obfstr_k.h — kernel-side string-literal obfuscation for vcachefs.
 *
 * The shipped release .ko is a client artifact; `strings vcachefs.ko` must not
 * reveal self-documenting literals (algorithm names, log text) that advertise
 * what the module does.  This is the in-kernel analogue of stub/obfstr.h — the
 * userspace header can't be used here (it pulls in stdio/dlfcn/string.h), and
 * pr_info(fmt) can't take a runtime format anyway (KERN_INFO fmt needs a
 * literal).  So this provides only what a module needs: decode an obfuscated
 * byte array into a caller-provided buffer, valid for that function's lifetime.
 *
 * The XOR key formula is IDENTICAL to obf_key() in shared/obfstr_gen.py, so byte
 * arrays produced by that tool (or the formula below) decode cleanly here.
 * Encode with, e.g.:
 *     python - <<'PY'
 *     def k(i): return 0x5a ^ (((i*7)+13)&0xff)
 *     s=b"gcm(aes)"; print(", ".join("0x%02x"%(c^k(i)) for i,c in enumerate(s)))
 *     PY
 *
 * Coverage: defeats offline `strings`/static analysis of the .ko.  It does NOT
 * hide the decoded string from a live root attacker snapshotting kernel memory
 * during the brief decode window — out of scope per the project threat model
 * (the capable adversary never touches the running box).
 */
#ifndef _VCACHEFS_OBFSTR_K_H
#define _VCACHEFS_OBFSTR_K_H

#include <linux/types.h>

/* Per-position key — KEEP IN SYNC with obf_key() in shared/obfstr_gen.py. */
#define _VCF_OBF_K(i) ((u8)(0x5a ^ (((((unsigned)(i)) * 7u) + 13u) & 0xffu)))

static inline const char *vcf_deobf(char *dst, const volatile u8 *e, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		dst[i] = (char)(e[i] ^ _VCF_OBF_K(i));
	dst[n] = '\0';
	return dst;
}

/*
 * Decode an obfuscated string (comma-separated encrypted bytes) into the
 * caller-provided buffer `dst` and return dst.  `dst` must hold at least
 * (#bytes + 1).  The ciphertext sits in .rodata as `volatile` so the compiler
 * cannot const-fold it back to cleartext — `strings` sees only noise.  Using a
 * caller buffer (not __builtin_alloca) keeps this kernel-idiomatic and gives
 * the decoded string the caller function's lifetime.
 */
#define VCF_OBF(dst, ...) ({						\
	static const volatile u8 _vcf_obf_e[] = { __VA_ARGS__ };	\
	vcf_deobf((dst), _vcf_obf_e, (unsigned)sizeof(_vcf_obf_e));	\
})

#endif /* _VCACHEFS_OBFSTR_K_H */
