#!/usr/bin/env python3
"""
antirev-protect — offline binary protector

Usage:
    protect.py --stub <stub_binary> --main <elf_binary> \
               [--lib lib1.so lib2.so ...] \
               --key <keyfile>  --output <protected_binary>

    --key   Path to key file (32 bytes as 64 hex chars).
            Created with a fresh random key if it does not exist.

The protected binary is: stub ELF + encrypted bundle + 48-byte trailer.
Trailer layout: [bundle_offset:8B LE][key:32B][magic:8B "ANTREV01"]
The key is embedded in the binary — no env var or server needed to run it.
"""

import argparse
import os
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

MAGIC    = b"ANTREV01"
KEY_SIZE = 32   # AES-256
IV_SIZE  = 12   # GCM nonce


def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (iv, tag, ciphertext) for the given plaintext."""
    iv = os.urandom(IV_SIZE)
    aesgcm = AESGCM(key)
    # cryptography library returns ciphertext || tag (tag is last 16 bytes)
    ct_and_tag = aesgcm.encrypt(iv, data, None)
    ct  = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    return iv, tag, ct


def pack_entry(name: str, data: bytes, key: bytes, is_main: bool) -> bytes:
    """Serialize one bundle entry."""
    iv, tag, ct = encrypt_file(data, key)
    name_b = name.encode()
    entry  = struct.pack("<H", len(name_b))   # name_len
    entry += name_b                            # name
    entry += struct.pack("<B", 1 if is_main else 0)  # flags
    entry += iv                                # 12 bytes
    entry += tag                               # 16 bytes
    entry += struct.pack("<Q", len(ct))        # ciphertext size
    entry += ct                                # ciphertext
    return entry


def load_or_create_key(key_path: Path) -> bytes:
    if key_path.exists():
        hex_str = key_path.read_text().strip()
        key = bytes.fromhex(hex_str)
        if len(key) != KEY_SIZE:
            sys.exit(f"[error] key file must contain {KEY_SIZE*2} hex chars, got {len(hex_str)}")
        print(f"[antirev] Loaded key from {key_path}")
    else:
        key = os.urandom(KEY_SIZE)
        key_path.write_text(key.hex() + "\n")
        key_path.chmod(0o600)
        print(f"[antirev] Generated new key → {key_path}  (keep this secret!)")
    return key


def main():
    p = argparse.ArgumentParser(description="antirev binary protector")
    p.add_argument("--stub",   required=True,  help="Pre-compiled stub binary")
    p.add_argument("--main",   required=True,  help="Main ELF to protect")
    p.add_argument("--lib",    nargs="*", default=[], metavar="LIB",
                   help="Custom .so files to protect")
    p.add_argument("--key",    required=True,  help="Key file (hex); created if absent")
    p.add_argument("--output", required=True,  help="Output protected binary")
    args = p.parse_args()

    stub_path = Path(args.stub)
    main_path = Path(args.main)
    out_path  = Path(args.output)
    key_path  = Path(args.key)

    if not stub_path.exists():
        sys.exit(f"[error] stub not found: {stub_path}")
    if not main_path.exists():
        sys.exit(f"[error] main binary not found: {main_path}")
    for lib in args.lib:
        if not Path(lib).exists():
            sys.exit(f"[error] library not found: {lib}")

    key = load_or_create_key(key_path)

    # Build bundle
    files = [(main_path, True)] + [(Path(l), False) for l in args.lib]
    bundle = struct.pack("<I", len(files))   # num_files

    for path, is_main in files:
        data = path.read_bytes()
        entry = pack_entry(path.name, data, key, is_main)
        bundle += entry
        role = "main" if is_main else "lib "
        print(f"[antirev] Encrypted {role}: {path.name}  "
              f"({len(data):,} → {len(entry):,} bytes)")

    # Assemble: stub + bundle + trailer
    stub_data     = stub_path.read_bytes()
    bundle_offset = len(stub_data)
    trailer       = struct.pack("<Q", bundle_offset) + key + MAGIC

    out_data = stub_data + bundle + trailer
    out_path.write_bytes(out_data)
    out_path.chmod(0o755)

    print(f"\n[antirev] Protected binary  → {out_path}  ({len(out_data):,} bytes)")
    print(f"[antirev] Key file          → {key_path}  (keep secret — embedded in binary)")
    print(f"\n[antirev] To run:")
    print(f"    {out_path} [args...]")


if __name__ == "__main__":
    main()
