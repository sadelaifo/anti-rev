#!/usr/bin/env python3
# pack_jar.py — encrypt a single file into an embedded-key container (FS_MAGIC),
# exactly like vcache-pack.py.  Usage: pack_jar.py <in> <out>
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FS_MAGIC = bytes.fromhex("a74c2e91d63b085f")
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
key, iv = os.urandom(32), os.urandom(12)
ct_tag = AESGCM(key).encrypt(iv, data, None)
ct, tag = ct_tag[:-16], ct_tag[-16:]
os.makedirs(os.path.dirname(dst), exist_ok=True)
open(dst, "wb").write(FS_MAGIC + iv + tag + ct + key + FS_MAGIC)
print(f"[pack] {src} -> {dst} ({os.path.getsize(dst)} bytes)")
