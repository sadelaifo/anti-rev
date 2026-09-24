// SPDX-License-Identifier: GPL-2.0
/*
 * key_blob.c — the obfuscated AES-256 master key compiled into vcachefs.
 *
 * GENERATED from the project keyfile by shared/gen_key_blob.py; this checked-in
 * copy is a PLACEHOLDER (no key) so the module builds without a keyfile.  With
 * the placeholder, decrypt returns -ENOKEY (fail-safe: nothing decrypts).
 * Embed a real key:
 *   python3 shared/gen_key_blob.py <keyfile.hex> kmod2/module/key_blob.c
 * or via CMake:  cmake -S kmod2 -B build/kmod2 -DKMOD2_KEYFILE=/path/key.hex
 *
 * Its own translation unit so changing the key recompiles only this object and
 * relinks — the rest of the module stays cached.  The vcf_* symbol names are
 * scrubbed to opaque tokens in a release build (module/Makefile), so `nm` on the
 * shipped .ko reveals no "master_key" symbol; the bytes remain (obfuscated) in
 * .rodata — obscurity layered on the crypto, not a replacement for it.
 */
#ifdef __KERNEL__
#include <linux/types.h>
#endif

const int vcf_master_key_present = 0;			/* 0 = placeholder */
const unsigned char vcf_master_key_obf[32] = { 0 };
