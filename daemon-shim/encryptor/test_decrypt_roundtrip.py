#!/usr/bin/env python3
"""Round-trip test for antirev-decrypt.py.

Builds an encrypted tree with protect.py's own packing primitives, then
decrypts it and asserts the originals come back — including that the exe's
needed-libs (dependency) section is dropped, and that the deployment key is
auto-recovered from a protected-exe trailer when --key is omitted.

Run:  python encryptor/test_decrypt_roundtrip.py
"""
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import protect  # noqa: E402

DECRYPT = HERE / "antirev-decrypt.py"


def _build_tree(td: Path):
    key = os.urandom(protect.KEY_SIZE)
    keyfile = td / "proj.key.hex"
    keyfile.write_text(key.hex() + "\n")

    proj = td / "proj"
    (proj / "lib").mkdir(parents=True)
    (proj / "bin").mkdir(parents=True)
    (proj / "etc").mkdir(parents=True)

    # 1) keyless encrypted lib
    lib_plain = b"\x7fELF" + b"LIB-original-bytes" * 64
    (proj / "lib" / "libfoo.so").write_bytes(
        protect.make_container(lib_plain, key))            # keyless form

    # 2) protected exe: stub + bundle(main entry + needed-libs) + trailer
    stub = td / "stub.bin"
    stub.write_bytes(b"\x7fELF" + b"STUB" * 32)
    exe_plain = b"\x7fELF" + b"EXE-original-bytes" * 80
    entry = protect._build_entry(Path("myapp"), exe_plain, key)
    # dependency section (must be dropped on decrypt)
    needed = ["libfoo.so", "libbar.so"]
    sec = struct.pack("<H", len(needed))
    for nm in needed:
        nb = nm.encode()
        sec += struct.pack("<H", len(nb)) + nb
    protect._build_protected(stub, proj / "bin" / "myapp", key,
                             entry, protect.BFLAG_HAS_MAIN, sec)

    # 3) plaintext data file
    (proj / "etc" / "app.conf").write_bytes(b"plain-config\n")

    return proj, keyfile, key, lib_plain, exe_plain


def main():
    with tempfile.TemporaryDirectory() as t:
        td = Path(t)
        proj, keyfile, key, lib_plain, exe_plain = _build_tree(td)

        # ---- run with explicit --key, to an output dir ----
        out = td / "proj_plain"
        r = subprocess.run(
            [sys.executable, str(DECRYPT), str(proj),
             "--key", str(keyfile), "--output", str(out)],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr

        got_lib = (out / "lib" / "libfoo.so").read_bytes()
        got_exe = (out / "bin" / "myapp").read_bytes()
        assert got_lib == lib_plain, "lib round-trip mismatch"
        assert got_exe == exe_plain, "exe round-trip mismatch (dep section not stripped?)"
        assert len(got_exe) == len(exe_plain), "exe carries extra bytes (needed-libs leaked)"
        assert (out / "etc" / "app.conf").read_bytes() == b"plain-config\n", "plaintext copy"
        print("ok: round-trip with --key (lib + exe + plaintext); dep section dropped")

        # ---- run WITHOUT --key: key auto-recovered from the exe trailer ----
        out2 = td / "proj_plain_nokey"
        r2 = subprocess.run(
            [sys.executable, str(DECRYPT), str(proj), "--output", str(out2)],
            capture_output=True, text=True)
        assert r2.returncode == 0, r2.stdout + r2.stderr
        assert (out2 / "lib" / "libfoo.so").read_bytes() == lib_plain, \
            "keyless lib should decrypt via key recovered from exe trailer"
        assert (out2 / "bin" / "myapp").read_bytes() == exe_plain
        print("ok: key auto-recovered from exe trailer (no --key) decrypts keyless lib")

        # ---- wrong key fails loudly ----
        badkey = td / "bad.key.hex"
        badkey.write_text(os.urandom(protect.KEY_SIZE).hex() + "\n")
        out3 = td / "proj_bad"
        r3 = subprocess.run(
            [sys.executable, str(DECRYPT), str(proj),
             "--key", str(badkey), "--output", str(out3)],
            capture_output=True, text=True)
        # exe still decrypts (trailer key), but the keyless lib fails -> exit 1
        assert r3.returncode == 1, "wrong key for keyless lib should fail"
        assert "FAILED" in r3.stdout
        print("ok: wrong key for keyless lib fails loudly (exit 1)")

    print("\nALL PASS")


if __name__ == "__main__":
    main()
