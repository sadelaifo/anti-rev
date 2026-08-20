#!/usr/bin/env python3
"""Unit test for the key-mode feature (split vs single).

Pure Python (hashlib/struct only — no libcrypto, no gcc, no daemon), so it runs
anywhere.  It checks the packer-side derivation + the bundle flag encoding that
the stub / daemon / client all read, and demonstrates the failure mode the flag
prevents: a SPLIT bundle's encryption key is NOT part1, so a consumer that used
part1 directly (i.e. ignored the mode) would decrypt garbage.

Run:  python3 encryptor/test_key_mode.py
"""
import hashlib
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from protect import (derive_real_key, resolve_enc_key, _build_protected,
                     MAGIC, KEY_SIZE, BFLAG_HAS_MAIN, BFLAG_KEY_SINGLE)

PASS = 0
FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {msg}")
    else:
        FAIL += 1
        print(f"  [FAIL] {msg}")


def read_bundle_flags(protected: bytes) -> int:
    """Mirror stub self_key_single(): trailer = [off:8][part1:32][MAGIC:8];
    flags = first byte of the bundle at `off`."""
    assert protected[-8:] == MAGIC
    off = struct.unpack("<Q", protected[-48:-40])[0]
    return protected[off]


def main():
    part1 = bytes(range(32))                      # deterministic 32-byte key
    version_field = b"V100R001C00"

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        lrxd = td / "lrxd"
        lrxd.write_bytes(b"\x7fELF-fake-daemon-bytes")   # any bytes; hashed whole

        print("== resolve_enc_key ==")
        single_key = resolve_enc_key(part1, "single")
        check(single_key == part1, "single: enc key IS the key file value (part1)")

        split_key = resolve_enc_key(part1, "split", lrxd, version_field)
        expect = hashlib.sha256(
            part1 + hashlib.sha256(lrxd.read_bytes()).digest() + version_field
        ).digest()
        check(split_key == expect, "split: enc key = SHA256(part1||SHA256(lrxd)||version)")
        check(split_key == derive_real_key(part1, lrxd, version_field),
              "split: resolve_enc_key matches derive_real_key")

        # THE failure mode the flag prevents: a split bundle is encrypted with
        # split_key, so a consumer that used part1 (single) would be wrong.
        check(split_key != part1,
              "split enc key != part1 -> a mode-blind consumer would mis-key (the bug)")

        print("== bundle flag encoding (what the stub reads) ==")
        stub = td / "stub"
        stub.write_bytes(b"STUBSTUB" * 4)         # any stub bytes

        out_single = td / "s.protected"
        _build_protected(stub, out_single, part1, b"",
                         bundle_flags=BFLAG_HAS_MAIN | BFLAG_KEY_SINGLE)
        flags = read_bundle_flags(out_single.read_bytes())
        check(flags & BFLAG_KEY_SINGLE, "single bundle: BFLAG_KEY_SINGLE set in bundle_flags")

        out_split = td / "p.protected"
        _build_protected(stub, out_split, part1, b"", bundle_flags=BFLAG_HAS_MAIN)
        flags = read_bundle_flags(out_split.read_bytes())
        check(not (flags & BFLAG_KEY_SINGLE),
              "split bundle: BFLAG_KEY_SINGLE clear (stub will derive)")

        # trailer stores part1 in BOTH modes (the stub decides how to use it)
        check(out_single.read_bytes()[-40:-8] == part1
              and out_split.read_bytes()[-40:-8] == part1,
              "both modes: trailer embeds part1/key")

    print(f"\n== RESULT: {PASS} passed, {FAIL} failed ==")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
