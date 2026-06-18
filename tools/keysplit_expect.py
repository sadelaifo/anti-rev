#!/usr/bin/env python3
"""keysplit_expect.py -- compute the expected key-split derivation values.

Mirrors stub.c derive_real_key() and encryptor/protect.py:derive_real_key()
exactly:

    real_key = SHA256( part1[32] || SHA256(lrxd file) || version.strip() )

Run it against the PACK-side inputs and against the RUNTIME inputs
($HOME/SA/...), and compare each line to the stub's `keysplit[dbg]` log
lines, to localize a "decryption failed" mismatch:

  pack side   :  keysplit_expect.py --key antirev.key \
                     --lrxd out/lrxd-aarch64 --version /path/to/version
  runtime side:  keysplit_expect.py --trailer "$HOME/SA/bin/sa/lrxd" \
                     --lrxd "$HOME/SA/bin/sa/lrxd" --version "$HOME/SA/version"

part1 comes from either a hex --key file (what the packer used) or the
ANTREV01 trailer of a packed binary via --trailer (last 48 bytes:
[offset:8][part1:32][magic:8]).

Output field -> stub log line:
  part1                  -> keysplit[dbg]: part1=
  hash(lrxd)             -> keysplit[dbg]: hash(lrxd)=
  version_stripped_len   -> keysplit[dbg]: version_stripped_len=
  version_stripped_hash  -> keysplit[dbg]: ... hash=
  real_key               -> keysplit[dbg]: real_key=
"""
import argparse
import hashlib
import sys
from pathlib import Path

MAGIC = b"ANTREV01"


def load_part1(args) -> bytes:
    if args.key:
        return bytes.fromhex(Path(args.key).read_text().strip())
    data = Path(args.trailer).read_bytes()
    if len(data) < 48 or data[-8:] != MAGIC:
        sys.exit(f"--trailer {args.trailer}: ANTREV01 trailer not found")
    return data[-40:-8]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--key", help="hex key file holding part1 (what the packer used)")
    src.add_argument("--trailer", help="packed binary whose ANTREV01 trailer holds part1")
    ap.add_argument("--lrxd", required=True, help="lrxd binary to hash")
    ap.add_argument("--version", required=True, help="version file (content is stripped)")
    args = ap.parse_args()

    part1 = load_part1(args)
    if len(part1) != 32:
        sys.exit(f"part1 must be 32 bytes, got {len(part1)}")

    lrxd_bytes = Path(args.lrxd).read_bytes()
    version_bytes = Path(args.version).read_bytes().strip()

    part2 = hashlib.sha256(lrxd_bytes).digest()
    real_key = hashlib.sha256(part1 + part2 + version_bytes).digest()

    print(f"part1                 : {part1.hex()}")
    print(f"hash(lrxd)            : {part2.hex()}   ({args.lrxd}, {len(lrxd_bytes)} bytes)")
    print(f"version_stripped_len  : {len(version_bytes)}   ({args.version})")
    print(f"version_stripped_hash : {hashlib.sha256(version_bytes).hexdigest()}")
    print(f"real_key              : {real_key.hex()}")


if __name__ == "__main__":
    main()
