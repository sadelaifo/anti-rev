#!/usr/bin/env python3
# authz-sign-exe.py — append a vendor per-exe signature to a PLAINTEXT binary,
# for the qemu-user gate "option 1" (guest exes ship as normal ELF + signature;
# only their .so libs are encrypted).
#
#   authz-sign-exe.py <priv.pem> <cert.pem> <binary> [<binary> ...]
#
# Layout produced (identical to vcache-pack.py's exe signing, so the kernel's
# vcachefs_probe_sig()/arev_verify_file_sig() accept it):
#     [original bytes][sig][sig_len:4 LE][SIG_MAGIC:8]
# where sig = detached PKCS#7 (DER, SHA-256, no signed attrs) over the ORIGINAL
# bytes.  Signing is idempotent-guarded: a file that already ends in SIG_MAGIC is
# skipped (re-signing would sign over the previous signature).
import os
import struct
import subprocess
import sys
import tempfile

# Must byte-match kmod2/module/antirevfs.h ANTREV_SIG_MAGIC and
# vcache-pack.py SIG_MAGIC.
SIG_MAGIC = bytes.fromhex("3d6af0128c55b427")


def sign_one(key: str, cert: str, path: str) -> None:
    data = open(path, "rb").read()
    if data[-8:] == SIG_MAGIC:
        print(f"[skip] {path}: already signed")
        return
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        tmp = tf.name
    try:
        sig = subprocess.check_output(
            ["openssl", "cms", "-sign", "-binary", "-noattr", "-md", "sha256",
             "-in", tmp, "-signer", cert, "-inkey", key, "-outform", "DER"],
            stderr=subprocess.PIPE)
    finally:
        os.unlink(tmp)
    out = data + sig + struct.pack("<I", len(sig)) + SIG_MAGIC
    with open(path, "wb") as f:
        f.write(out)
    print(f"[sign] {path}: +{len(sig)}-byte sig + 12-byte footer")


def main() -> int:
    if len(sys.argv) < 4:
        sys.exit("usage: authz-sign-exe.py <priv.pem> <cert.pem> <binary>...")
    key, cert = sys.argv[1], sys.argv[2]
    for p in sys.argv[3:]:
        sign_one(key, cert, p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
