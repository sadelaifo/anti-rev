#!/usr/bin/env python3
# pack.py — build a ciphertext lower tree at image-build time.
# key-in-binary: containers are KEYLESS (MAGIC+iv+tag+ct, no trailer); the AES
# key is compiled into vcachefsd (key_blob.c via shared/gen_key_blob.py), so the
# packer and the binary must share ONE fixed master key.  Pass it as argv[3]
# (64 hex chars); if omitted a random one is generated and printed so the caller
# can bake it in.
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FS_MAGIC = bytes.fromhex("a74c2e91d63b085f")
lower, expected = sys.argv[1], sys.argv[2]
KEY = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else os.urandom(32)
os.makedirs(lower, exist_ok=True)

def container(data: bytes) -> bytes:
    iv = os.urandom(12)
    ct_tag = AESGCM(KEY).encrypt(iv, data, None)
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return FS_MAGIC + iv + tag + ct			# keyless: key lives in the binary

plain = b"DOCKER-FUSEFS-SECRET-" + b"\x7fELF" + os.urandom(2048) + b"-END"
open(os.path.join(lower, "secret.so"), "wb").write(container(plain))
open(os.path.join(lower, "notes.txt"), "wb").write(b"third-party plaintext\n")
open(expected, "wb").write(plain)
print(f"[pack] wrote keyless ciphertext tree to {lower} (bake this key into vcachefsd: {KEY.hex()})")
