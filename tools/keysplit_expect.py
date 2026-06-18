#!/usr/bin/env python3
"""keysplit_expect.py -- compute the expected key-split derivation values.

Mirrors stub.c derive_real_key() and encryptor/protect.py:derive_real_key()
exactly:

    real_key = SHA256( part1[32] || SHA256(lrxd file) || version_field )

where version_field = (EXECUTE version script).stdout[20:35] -- a fixed
15-byte window of the raw stdout starting at the 21st byte, taken verbatim.

Run it against the PACK-side inputs and against the RUNTIME inputs
($HOME/SA/...), and compare each line to the stub's `keysplit[dbg]` log
lines, to localize a "decryption failed" mismatch:

  pack side   :  keysplit_expect.py --key antirev.key \
                     --lrxd out/lrxd-aarch64 --version /path/to/version
  runtime side:  keysplit_expect.py --trailer "$HOME/SA/bin/sa/lrxd" \
                     --lrxd "$HOME/SA/bin/sa/lrxd" --version "$HOME/SA/version"

--version is the version SHELL SCRIPT; it is executed and its stdout sliced.
part1 comes from either a hex --key file (what the packer used) or the
ANTREV01 trailer of a packed binary via --trailer (last 48 bytes:
[offset:8][part1:32][magic:8]).

Output field -> stub log line:
  hash(lrxd)             -> keysplit[dbg]: hash(lrxd)=
  version stdout bytes   -> keysplit[dbg]: version stdout=N bytes
  version_field_hash     -> keysplit[dbg]: ... field[20:35] hash=
  part1_fp               -> keysplit[dbg]: part1_fp=
  real_key_fp            -> keysplit[dbg]: real_key_fp=

The stub never logs raw key material; it logs a one-way fingerprint
(first 4 bytes of SHA256(value)) for part1 and real_key.  This tool prints
both the full local values (you have the key here) AND the matching fp so a
field log can be compared without the key ever leaving the box.
"""
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

MAGIC = b"ANTREV01"

# version component: KS_VER_LEN bytes of the version script's RAW stdout,
# starting at byte offset KS_VER_OFF (the 21st byte, 1-based).  Mirrors
# stub.c / protect.py / antirev_client.py.
KS_VER_OFF = 20
KS_VER_LEN = 15


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
    ap.add_argument("--version", required=True,
                    help="version shell script (EXECUTED; bytes [20:35] of stdout used)")
    args = ap.parse_args()

    part1 = load_part1(args)
    if len(part1) != 32:
        sys.exit(f"part1 must be 32 bytes, got {len(part1)}")

    lrxd_bytes = Path(args.lrxd).read_bytes()
    out = subprocess.run([str(args.version)], capture_output=True).stdout
    if len(out) < KS_VER_OFF + KS_VER_LEN:
        sys.exit(f"--version {args.version}: produced {len(out)} bytes of stdout, "
                 f"need >= {KS_VER_OFF + KS_VER_LEN}")
    version_bytes = out[KS_VER_OFF:KS_VER_OFF + KS_VER_LEN]

    part2 = hashlib.sha256(lrxd_bytes).digest()
    real_key = hashlib.sha256(part1 + part2 + version_bytes).digest()

    def fp(b: bytes) -> str:               # mirror stub.c ks_fp: SHA256(value)[:4]
        return hashlib.sha256(b).hexdigest()[:8]

    print(f"hash(lrxd)            : {part2.hex()}   ({args.lrxd}, {len(lrxd_bytes)} bytes)")
    print(f"version stdout bytes  : {len(out)}   ({args.version}, executed)")
    print(f"version_field[20:35]  : {version_bytes!r}")
    print(f"version_field_hash    : {hashlib.sha256(version_bytes).hexdigest()}")
    print(f"part1                 : {part1.hex()}")
    print(f"part1_fp              : {fp(part1)}   (matches stub keysplit[dbg]: part1_fp=)")
    print(f"real_key              : {real_key.hex()}")
    print(f"real_key_fp           : {fp(real_key)}   (matches stub keysplit[dbg]: real_key_fp=)")


if __name__ == "__main__":
    main()
