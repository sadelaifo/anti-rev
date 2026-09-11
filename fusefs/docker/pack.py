#!/usr/bin/env python3
# pack.py — build a ciphertext lower tree at image-build time, exactly like
# vcache-pack.py / protect.make_container(embed_key=True, magic=FS_MAGIC).
# Mirrors what a shipped product image would contain (ciphertext baked in).
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FS_MAGIC = bytes.fromhex("a74c2e91d63b085f")
lower, expected = sys.argv[1], sys.argv[2]
os.makedirs(lower, exist_ok=True)

def container(data: bytes) -> bytes:
    key = os.urandom(32); iv = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(iv, data, None)
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return FS_MAGIC + iv + tag + ct + key + FS_MAGIC

plain = b"DOCKER-FUSEFS-SECRET-" + b"\x7fELF" + os.urandom(2048) + b"-END"
open(os.path.join(lower, "secret.so"), "wb").write(container(plain))
open(os.path.join(lower, "notes.txt"), "wb").write(b"third-party plaintext\n")
open(expected, "wb").write(plain)
print(f"[pack] wrote ciphertext tree to {lower}")
