#!/usr/bin/env python3
"""encrypt-file.py — encrypt ONE file into a KEYLESS FS_MAGIC container for
fusefs / kmod2 (key-in-binary: the AES-256 key is compiled into vcachefsd/.ko,
NOT stored in the file).  Encrypt with the SAME key you baked into the binary
(FUSEFS_KEYFILE / KMOD2_KEYFILE) or a raw copy of the tree is decryptable-free
but the mount still won't decrypt it with a mismatched key.

Container: FS_MAGIC(a74c2e91d63b085f) + iv(12) + tag(16) + ct  (no key trailer).

Usage:
  encrypt-file.py <keyfile.hex> <input> <output>
  encrypt-file.py <keyfile.hex> <file>          # encrypt in place (overwrites)
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "shared"))
from protect import make_container  # noqa: E402

FS_MAGIC = bytes.fromhex("a74c2e91d63b085f")


def main(argv):
    if len(argv) not in (3, 4):
        sys.exit("usage: encrypt-file.py <keyfile.hex> <input> [output]")
    keyf, inp = argv[1], argv[2]
    out = argv[3] if len(argv) == 4 else inp
    try:
        key = bytes.fromhex(pathlib.Path(keyf).read_text().strip())
    except (ValueError, OSError) as e:
        sys.exit(f"[encrypt-file] bad keyfile {keyf}: {e}")
    if len(key) != 32:
        sys.exit(f"[encrypt-file] key must be 32 bytes (AES-256); got {len(key)}")
    data = pathlib.Path(inp).read_bytes()
    blob = make_container(data, key, embed_key=False, magic=FS_MAGIC)
    pathlib.Path(out).write_bytes(blob)
    print(f"[encrypt-file] {inp} -> {out}  ({len(data)} -> {len(blob)} bytes, keyless FS_MAGIC)")


if __name__ == "__main__":
    main(sys.argv)
