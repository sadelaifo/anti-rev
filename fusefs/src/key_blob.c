// SPDX-License-Identifier: GPL-2.0
/*
 * key_blob.c — obfuscated AES-256 master key compiled into vcachefsd.
 *
 * GENERATED from the project keyfile by shared/gen_key_blob.py; this checked-in
 * copy is a PLACEHOLDER (no key) so the daemon builds without a keyfile (decrypt
 * then returns -ENOKEY: fail-safe).  Embed a real key:
 *   python3 shared/gen_key_blob.py <keyfile.hex> fusefs/src/key_blob.c
 * or via CMake:  cmake -S fusefs -B build/fusefs -DFUSEFS_KEYFILE=/path/key.hex
 *
 * key-in-binary: the AES key lives here, not in each ciphertext file's trailer,
 * so a raw copy of the .enc tree is undecryptable without this binary.
 */
const int vcf_master_key_present = 0;			/* 0 = placeholder */
const unsigned char vcf_master_key_obf[32] = { 0 };
