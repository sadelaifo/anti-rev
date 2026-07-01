#!/usr/bin/env python3
"""NIST AES-256-GCM known-answer test for protect._aes256_gcm_encrypt — the
ctypes->libcrypto replacement for the pip `cryptography` dependency.

Vectors are McGrew & Viega GCM-spec Test Cases 13 & 14 (AES-256, zero key/IV).
They pin ciphertext AND tag, so a passing run proves the ctypes GCM is
byte-identical to standard AES-256-GCM — hence produces containers the C stub /
kernel module decrypt unchanged.  Requires system libcrypto (OpenSSL); runs on
the Linux build host.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "encryptor"))
import protect  # noqa: E402


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


CASES = [
    # (key, iv, plaintext, expected_ct_hex, expected_tag_hex)
    (b"\x00" * 32, b"\x00" * 12, b"", "", "530f8afbc74536b9a963b4f1c4cb738b"),
    (b"\x00" * 32, b"\x00" * 12, b"\x00" * 16,
     "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"),
]


def main() -> int:
    ok = True
    for i, (k, iv, pt, exp_ct, exp_tag) in enumerate(CASES):
        ct, tag = protect._aes256_gcm_encrypt(k, iv, pt)
        cok, tok = ct == _h(exp_ct), tag == _h(exp_tag)
        print(f"KAT case {i}: ct {'OK' if cok else 'FAIL'}  tag {'OK' if tok else 'FAIL'}")
        if not (cok and tok):
            ok = False
            print(f"    got ct={ct.hex()!r} tag={tag.hex()!r}")

    # Container shape: encrypt_data must still return (iv12, tag16, ct=len(pt)).
    iv, tag, ct = protect.encrypt_data(b"hello antirev", b"\x11" * 32)
    if not (len(iv) == 12 and len(tag) == 16 and len(ct) == len(b"hello antirev")):
        ok = False
        print(f"    encrypt_data shape wrong: iv={len(iv)} tag={len(tag)} ct={len(ct)}")
    else:
        print("encrypt_data container shape OK (iv=12, tag=16, ct=len(pt))")

    print("test_gcm: PASS" if ok else "test_gcm: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
