#!/usr/bin/env python3
"""
antirev-protect — offline binary protector

Subcommands:

  protect-exe
      Encrypt a main ELF and bundle it into the stub launcher.

      protect.py protect-exe --stub <stub> --main <elf> \\
                             --key <keyfile> --output <protected>

  encrypt-lib
      Encrypt one or more shared libraries in-place (or to --output-dir).
      Encrypted format: [magic:8B][iv:12B][tag:16B][ciphertext].

      protect.py encrypt-lib --key <keyfile> --libs lib1.so [lib2.so ...] \\
                             [--output-dir <dir>]

Key file: 32 bytes as 64 hex chars.  Created with a fresh random key if absent.
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


# ── Helpers ──────────────────────────────────────────────────────────

def load_or_create_key(key_path: Path) -> bytes:
    if key_path.exists():
        hex_str = key_path.read_text().strip()
        key = bytes.fromhex(hex_str)
        if len(key) != KEY_SIZE:
            sys.exit(f"[error] key file must contain {KEY_SIZE*2} hex chars")
        print(f"[antirev] Loaded key from {key_path}")
    else:
        key = os.urandom(KEY_SIZE)
        key_path.write_text(key.hex() + "\n")
        key_path.chmod(0o600)
        print(f"[antirev] Generated new key → {key_path}  (keep this secret!)")
    return key


def encrypt_data(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (iv, tag, ciphertext)."""
    iv = os.urandom(IV_SIZE)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, data, None)
    ct  = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    return iv, tag, ct


# ── Subcommand: protect-exe ──────────────────────────────────────────

def cmd_protect_exe(args):
    stub_path = Path(args.stub)
    main_path = Path(args.main)
    out_path  = Path(args.output)
    key_path  = Path(args.key)

    for p, label in [(stub_path, "stub"), (main_path, "main binary")]:
        if not p.exists():
            sys.exit(f"[error] {label} not found: {p}")

    key = load_or_create_key(key_path)

    # Bundle: [num_files:4B] [entry...]
    data   = main_path.read_bytes()
    iv, tag, ct = encrypt_data(data, key)
    name_b = main_path.name.encode()

    entry  = struct.pack("<H", len(name_b))
    entry += name_b
    entry += struct.pack("<B", 1)   # flags: is_main
    entry += iv
    entry += tag
    entry += struct.pack("<Q", len(ct))
    entry += ct

    bundle = struct.pack("<I", 1) + entry   # num_files = 1

    stub_data     = stub_path.read_bytes()
    bundle_offset = len(stub_data)
    trailer       = struct.pack("<Q", bundle_offset) + key + MAGIC

    out_data = stub_data + bundle + trailer
    out_path.write_bytes(out_data)
    out_path.chmod(0o755)

    print(f"[antirev] Encrypted main: {main_path.name}  "
          f"({len(data):,} → {len(entry):,} bytes)")
    print(f"\n[antirev] Protected binary → {out_path}  ({len(out_data):,} bytes)")
    print(f"[antirev] Key file         → {key_path}  (keep secret)")
    print(f"\n[antirev] To run:\n    {out_path} [args...]")


# ── Subcommand: encrypt-lib ──────────────────────────────────────────

def cmd_encrypt_lib(args):
    key_path = Path(args.key)
    key      = load_or_create_key(key_path)
    out_dir  = Path(args.output_dir) if args.output_dir else None

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    for lib_str in args.libs:
        lib = Path(lib_str)
        if not lib.exists():
            sys.exit(f"[error] library not found: {lib}")

        data         = lib.read_bytes()
        iv, tag, ct  = encrypt_data(data, key)

        enc_data = MAGIC + iv + tag + ct

        dest = (out_dir / lib.name) if out_dir else lib
        dest.write_bytes(enc_data)
        print(f"[antirev] Encrypted lib: {lib.name}  "
              f"({len(data):,} → {len(enc_data):,} bytes)  → {dest}")


# ── Entry point ──────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="antirev binary protector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # protect-exe
    pe = sub.add_parser("protect-exe", help="Bundle and encrypt a main ELF into the stub")
    pe.add_argument("--stub",   required=True, help="Pre-compiled stub binary")
    pe.add_argument("--main",   required=True, help="Main ELF to protect")
    pe.add_argument("--key",    required=True, help="Key file (hex); created if absent")
    pe.add_argument("--output", required=True, help="Output protected binary")

    # encrypt-lib
    el = sub.add_parser("encrypt-lib", help="Encrypt shared library file(s) in-place")
    el.add_argument("--key",        required=True,       help="Key file (hex); created if absent")
    el.add_argument("--libs",       required=True, nargs="+", metavar="LIB")
    el.add_argument("--output-dir", default=None,        help="Write encrypted libs here (default: in-place)")

    args = p.parse_args()

    if args.cmd == "protect-exe":
        cmd_protect_exe(args)
    elif args.cmd == "encrypt-lib":
        cmd_encrypt_lib(args)


if __name__ == "__main__":
    main()
