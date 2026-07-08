#!/usr/bin/env python3
"""
antirev-protect — offline binary protector

Subcommands:

  protect-exe
      Encrypt a main ELF and bundle it into the stub launcher.

      protect.py protect-exe --stub <stub> --main <elf> \\
                             --key <keyfile> --output <protected>
      protect.py protect-exe --stub <stub> --main <elf> \\
                             --key <keyfile> --daemon-libs --output <protected>

  protect-daemon
      Build a lightweight lib-daemon binary: stub + key trailer only.
      At runtime it scans its own directory for encrypted .so files,
      decrypts them into memfds, and serves them via SCM_RIGHTS to
      client stubs.

      protect.py protect-daemon --stub <stub> --key <keyfile> \\
                                --output <daemon_binary>

  encrypt-lib
      Encrypt one or more shared libraries in-place (or to --output-dir).
      Encrypted format: [magic:8B][iv:12B][tag:16B][ciphertext].

      protect.py encrypt-lib --key <keyfile> --libs lib1.so [lib2.so ...] \\
                             [--output-dir <dir>]

  encrypt-patch
      Encrypt hot-patch ".patch" file(s) for the live-patch shim
      (lrxd_<arch>.so).  Same ANTREV01 container as encrypt-lib, but the
      key is the KEYSPLIT-derived real key (part1 + SHA256(lrxd) +
      version), matching what the daemon re-derives in handle_get_patch —
      so --lrxd must be byte-identical to the target's $HOME/SA/bin/sa/lrxd
      and --version must equal what the target's $HOME/SA/version parses to
      (the value, not the script).  keysplit is per-arch; pass the lrxd for
      the arch the patch targets.  Basename is preserved so the daemon
      resolves it under its scan dir via OP_GET_PATCH.

      protect.py encrypt-patch --key <keyfile> --lrxd <lrxd-bin> \\
                               --version <version-value> \\
                               --patches a.patch [b.patch ...] [--output-dir <dir>]

Key file: 32 bytes as 64 hex chars.  Created with a fresh random key if absent.
"""
from __future__ import annotations

import argparse
import ctypes as _ct
import ctypes.util as _ctu
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

MAGIC    = b"ANTREV01"
KEY_SIZE = 32   # AES-256
IV_SIZE  = 12   # GCM nonce


# ── AES-256-GCM via system libcrypto (no pip `cryptography` dependency) ──
# Uses the OpenSSL EVP API through ctypes — the same system library the daemon
# links and that tools/antirev_client.py already calls for AES.  The encrypted
# container ([magic][iv][tag][ct]) is byte-for-byte what the C stub / kernel
# module decrypt, so nothing downstream changes.
_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG   = 0x10
_TAG_SIZE               = 16

_libcrypto = None


def _load_libcrypto():
    global _libcrypto
    if _libcrypto is not None:
        return _libcrypto
    name = _ctu.find_library("crypto") or "libcrypto.so.3"
    try:
        lib = _ct.CDLL(name)
    except OSError as e:
        sys.exit(f"[error] cannot load system libcrypto ({name}): {e}. "
                 f"Install OpenSSL (e.g. libssl / openssl-libs).")
    vp, cp, ip = _ct.c_void_p, _ct.c_char_p, _ct.POINTER(_ct.c_int)
    lib.EVP_CIPHER_CTX_new.restype  = vp
    lib.EVP_CIPHER_CTX_new.argtypes = []
    lib.EVP_CIPHER_CTX_free.argtypes = [vp]
    lib.EVP_aes_256_gcm.restype = vp
    lib.EVP_aes_256_gcm.argtypes = []
    lib.EVP_EncryptInit_ex.restype  = _ct.c_int
    lib.EVP_EncryptInit_ex.argtypes = [vp, vp, vp, cp, cp]
    lib.EVP_EncryptUpdate.restype  = _ct.c_int
    lib.EVP_EncryptUpdate.argtypes = [vp, cp, ip, cp, _ct.c_int]
    lib.EVP_EncryptFinal_ex.restype  = _ct.c_int
    lib.EVP_EncryptFinal_ex.argtypes = [vp, cp, ip]
    lib.EVP_CIPHER_CTX_ctrl.restype  = _ct.c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [vp, _ct.c_int, _ct.c_int, vp]
    _libcrypto = lib
    return lib


def _aes256_gcm_encrypt(key: bytes, iv: bytes, data: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt (no AAD).  Returns (ciphertext, 16-byte tag)."""
    lib = _load_libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
            raise RuntimeError("EVP_EncryptInit_ex(cipher) failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(iv), None) != 1:
            raise RuntimeError("set GCM IV length failed")
        if lib.EVP_EncryptInit_ex(ctx, None, None, key, iv) != 1:
            raise RuntimeError("EVP_EncryptInit_ex(key/iv) failed")
        outbuf = _ct.create_string_buffer(len(data) + 16)
        outlen = _ct.c_int(0)
        if data:
            if lib.EVP_EncryptUpdate(ctx, outbuf, _ct.byref(outlen), data, len(data)) != 1:
                raise RuntimeError("EVP_EncryptUpdate failed")
        ct_len = outlen.value
        finbuf = _ct.create_string_buffer(16)
        finlen = _ct.c_int(0)
        if lib.EVP_EncryptFinal_ex(ctx, finbuf, _ct.byref(finlen)) != 1:
            raise RuntimeError("EVP_EncryptFinal_ex failed")
        ct = outbuf.raw[:ct_len] + finbuf.raw[:finlen.value]
        tag = _ct.create_string_buffer(_TAG_SIZE)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, _TAG_SIZE, tag) != 1:
            raise RuntimeError("get GCM tag failed")
        return ct, tag.raw[:_TAG_SIZE]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


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
    ct, tag = _aes256_gcm_encrypt(key, iv, data)
    return iv, tag, ct


# version component: parsed from the version script's RAW stdout — the text
# after b"Version: " on its line, truncated before any b"SPC", stripped.  MUST
# stay byte-for-byte identical to stub.c (ksv_parse in keysplit_version.h),
# tools/antirev_client.py, and tools/keysplit_expect.py.
_VERSION_MARKER = b"Version: DY"   # formal (no-dot) marker; value starts after "DY"
_VERSION_SPC    = b"SPC"


def parse_version_field(stdout: bytes) -> bytes:
    """Extract the version key-component from the version script's raw stdout.

    Two formats (identical to stub.c ksv_parse / antirev_client._parse_version_field):
      IF the whole stdout contains b".":  (test builds, dotted version)
          field = everything AFTER the first b"." (excluding the dot), to the end,
          whitespace-stripped.  The marker / "SPC" are ignored.
      ELSE (no b"."):  (formal builds, DY-marker version)
          find b"Version: DY"; take from just after it to end of line ('\\n'/EOF),
          truncate before any b"SPC", whitespace-strip.

    Hard-fails if the field is empty, or (no-dot case) the DY marker is absent.
    Used for tests and for CLI callers that point at a live script; the
    config-driven pack path supplies the value directly (already parsed)."""
    if b"." in stdout:
        field = stdout[stdout.index(b".") + 1:].strip()
    else:
        i = stdout.find(_VERSION_MARKER)
        if i < 0:
            sys.exit('[error] keysplit: version output has no "." and no '
                     '"Version: DY" marker')
        start = i + len(_VERSION_MARKER)
        nl    = stdout.find(b"\n", start)
        line  = stdout[start:nl if nl >= 0 else len(stdout)]
        spc   = line.find(_VERSION_SPC)
        if spc >= 0:
            line = line[:spc]
        field = line.strip()
    if not field:
        sys.exit("[error] keysplit: version field is empty after parsing")
    return field


def derive_real_key(part1: bytes, lrxd_path: Path, version_field: bytes) -> bytes:
    """Key-split derivation — the actual AES key is never stored whole.

        real_key = SHA256( part1[32] || SHA256(lrxd file) || version_field )

    part1        : the 32-byte share embedded in every trailer (what
                   load_or_create_key returns).
    lrxd_path    : the daemon binary deployed at $HOME/SA/bin/sa/lrxd,
                   hashed whole — binds the key to lrxd's integrity.
    version_field: the deployment version VALUE as raw bytes (already parsed /
                   stripped).  The config-driven packer passes config.yaml
                   `version:` verbatim; the runtime stub derives the same bytes
                   by parsing $HOME/SA/version's stdout (see parse_version_field).

    MUST stay byte-for-byte identical to stub.c derive_real_key() and
    tools/antirev_client.py.
    """
    import hashlib
    if len(part1) != KEY_SIZE:
        sys.exit("[error] keysplit: part1 must be 32 bytes")
    if not version_field:
        sys.exit("[error] keysplit: version_field must be non-empty")
    part2 = hashlib.sha256(Path(lrxd_path).read_bytes()).digest()
    return hashlib.sha256(part1 + part2 + bytes(version_field)).digest()


# ── Bundle building ────────────────────────────────────────────────

BFLAG_HAS_MAIN    = 0x01
BFLAG_DAEMON_LIBS = 0x02


def _build_entry(path: Path, data: bytes, key: bytes) -> bytes:
    """Build a single bundle entry (header + encrypted data)."""
    iv, tag, ct = encrypt_data(data, key)
    name_b = path.name.encode()
    entry  = struct.pack("<H", len(name_b))
    entry += name_b
    entry += iv
    entry += tag
    entry += struct.pack("<Q", len(ct))
    entry += ct
    return entry


def _get_dt_needed(path: Path) -> list[str]:
    """Get DT_NEEDED library names from an ELF binary using readelf."""
    try:
        result = subprocess.run(
            ['readelf', '-d', str(path)],
            capture_output=True, text=True, timeout=10
        )
        needed = []
        for line in result.stdout.splitlines():
            m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
            if m:
                needed.append(m.group(1))
        return needed
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _build_ldconfig_cache() -> dict:
    """Parse ldconfig -p to build soname → path mapping.

    Also indexes LD_LIBRARY_PATH entries so that libs in custom
    directories (not registered in ldconfig) are discoverable.
    """
    cache = {}
    # LD_LIBRARY_PATH first — gives precedence to custom dirs, same
    # priority order as the runtime dynamic linker.
    for d in os.environ.get('LD_LIBRARY_PATH', '').split(':'):
        if not d or not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                if '.so' in name and name not in cache:
                    cache[name] = os.path.join(d, name)
        except OSError:
            pass
    # ldconfig cache (lower priority — don't overwrite LD_LIBRARY_PATH hits).
    try:
        result = subprocess.run(
            ['ldconfig', '-p'], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            m = re.match(r'\s+(\S+)\s+\(.*\)\s+=>\s+(\S+)', line)
            if m and m.group(1) not in cache:
                cache[m.group(1)] = m.group(2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return cache


def _get_transitive_needed(main_path: Path) -> list[str]:
    """Find encrypted libs needed by main_path, in topological order.

    Phase 1: BFS through DT_NEEDED, following unencrypted libs on disk.
    Libs NOT resolvable on disk are presumed encrypted.

    Phase 2: Topological sort (Kahn's algorithm) among the encrypted
    libs so leaf dependencies come first in the LD_PRELOAD list.

    Note: this function cannot follow DT_NEEDED of encrypted libs
    (they're not on disk).  antirev-pack.py's get_transitive_needed()
    handles this correctly using the plaintext originals.  This version
    is only used for standalone protect-exe --daemon-libs invocations.
    """
    from collections import deque

    ldcache = _build_ldconfig_cache()
    encrypted = set()
    visited = set()
    queue = _get_dt_needed(main_path)

    while queue:
        name = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)

        lib_path = ldcache.get(name)
        if lib_path:
            for dep in _get_dt_needed(Path(lib_path)):
                if dep not in visited:
                    queue.append(dep)
        else:
            encrypted.add(name)

    if not encrypted:
        return []

    # Build dependency edges among encrypted libs.
    # Since encrypted libs aren't on disk, we can't read their DT_NEEDED
    # here — each encrypted lib is treated as an independent node.
    # antirev-pack.py's version does the full topo sort with access to
    # plaintext originals.  Here we just sort by name for determinism.
    return sorted(encrypted)


def _build_protected(stub_path: Path, out_path: Path, key: bytes,
                     bundle_entries: bytes,
                     bundle_flags: int, needed_section: bytes = b""):
    """Write stub + bundle + trailer to out_path."""
    bundle = struct.pack("<B", bundle_flags) \
           + bundle_entries + needed_section

    stub_data     = stub_path.read_bytes()
    bundle_offset = len(stub_data)
    trailer       = struct.pack("<Q", bundle_offset) + key + MAGIC

    out_data = stub_data + bundle + trailer
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(out_data)
    out_path.chmod(0o755)
    return len(out_data)


# ── Subcommand: protect-exe ──────────────────────────────────────────

def cmd_protect_exe(args):
    stub_path = Path(args.stub)
    main_path = Path(args.main)
    out_path  = Path(args.output)
    key_path  = Path(args.key)
    daemon_libs = args.daemon_libs

    for p, label in [(stub_path, "stub"), (main_path, "main binary")]:
        if not p.exists():
            sys.exit(f"[error] {label} not found: {p}")

    key = load_or_create_key(key_path)

    # Main exe entry
    main_data = main_path.read_bytes()
    main_entry = _build_entry(main_path, main_data, key)
    print(f"[antirev] Encrypted main: {main_path.name}  "
          f"({len(main_data):,} bytes)")

    bundle_flags = BFLAG_HAS_MAIN
    if daemon_libs:
        bundle_flags |= BFLAG_DAEMON_LIBS

    # Build needed-libs section: tells stub which daemon libs are DT_NEEDED
    # (transitively, including through unencrypted intermediaries)
    needed_section = b""
    if daemon_libs:
        needed_libs = _get_transitive_needed(main_path)
        needed_section = struct.pack("<H", len(needed_libs))
        for name in needed_libs:
            nb = name.encode()
            needed_section += struct.pack("<H", len(nb)) + nb

    out_size = _build_protected(stub_path, out_path, key,
                                main_entry,
                                bundle_flags, needed_section)

    mode_str = ""
    if daemon_libs:
        mode_str = "  (daemon-libs mode)"
    print(f"\n[antirev] Protected binary → {out_path}  ({out_size:,} bytes){mode_str}")
    print(f"[antirev] Key file         → {key_path}  (keep secret)")
    print(f"\n[antirev] To run:\n    {out_path} [args...]")


# ── Subcommand: protect-daemon ──────────────────────────────────────

def cmd_protect_daemon(args):
    stub_path = Path(args.stub)
    out_path  = Path(args.output)
    key_path  = Path(args.key)

    if not stub_path.exists():
        sys.exit(f"[error] stub not found: {stub_path}")

    key = load_or_create_key(key_path)

    # Lightweight daemon: stub + trailer, no bundled libs.
    # At runtime it scans its directory for encrypted .so files.
    out_size = _build_protected(stub_path, out_path, key,
                                b"", bundle_flags=0)

    print(f"\n[antirev] Lib daemon binary → {out_path}  ({out_size:,} bytes)")
    print(f"[antirev] Key file          → {key_path}  (keep secret)")
    print(f"\n[antirev] To run:\n    {out_path}   # starts daemon, exits immediately")


# ── Shared whole-file encryptor (encrypt-lib / encrypt-patch) ────────

def _encrypt_files(paths, key, out_dir, kind="lib"):
    """Encrypt one or more whole files into the ANTREV01 container
    (MAGIC + iv + tag + ct), preserving each basename.

    Shared by encrypt-lib and encrypt-patch — IDENTICAL on-disk format.
    The 32-byte `key` is supplied by the caller (it decides whether that
    is the bare part1 or a keysplit-derived real key), so this helper
    stays agnostic about key derivation."""
    out_dir = Path(out_dir) if out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    for p_str in paths:
        f = Path(p_str)
        if not f.exists():
            sys.exit(f"[error] {kind} not found: {f}")

        data        = f.read_bytes()
        iv, tag, ct = encrypt_data(data, key)
        enc_data    = MAGIC + iv + tag + ct

        dest = (out_dir / f.name) if out_dir else f
        dest.write_bytes(enc_data)
        print(f"[antirev] Encrypted {kind}: {f.name}  "
              f"({len(data):,} → {len(enc_data):,} bytes)  → {dest}")


# ── Subcommand: encrypt-lib ──────────────────────────────────────────

def cmd_encrypt_lib(args):
    # encrypt-lib uses the bare part1 (keyfile value) — this command is the
    # non-keysplit / standalone path (keysplit production goes through
    # antirev-pack.py, which derives the real key per arch).
    key = load_or_create_key(Path(args.key))
    _encrypt_files(args.libs, key, args.output_dir, kind="lib")


# ── Subcommand: encrypt-patch ────────────────────────────────────────

def cmd_encrypt_patch(args):
    """Encrypt hot-patch .patch file(s) for the live-patch shim
    (lrxd_<arch>.so), using the SAME keysplit-derived real key as the
    encrypted libs — NOT the bare part1.

    The daemon decrypts a .patch via handle_get_patch ->
    derive_real_key(part1 + SHA256(lrxd) + version), so the key here must
    be derived identically.  --lrxd must be byte-identical to what the target
    deploys at $HOME/SA/bin/sa/lrxd, and --version must equal what the target's
    $HOME/SA/version script parses to (the value; NOT the script).  keysplit is
    per-arch (part2 = SHA256 of THAT arch's lrxd), so pass the lrxd for the arch
    this patch targets.

    Also warns on a non-".patch" basename: the shim's is_patch_path()
    only redirects open() of *.patch paths, so any other name would
    encrypt fine but never be intercepted by the injector."""
    for p_str in args.patches:
        nm = Path(p_str).name
        if not nm.endswith(".pat"):
            print(f"[antirev] WARNING: {nm} does not end in '.pat' — the "
                  f"hot-patch shim only redirects open()/fopen() of *.pat "
                  f"files, so the injector will NOT pick this up.",
                  file=sys.stderr)

    lrxd_path = Path(args.lrxd)
    if not lrxd_path.exists():
        sys.exit(f"[error] --lrxd not found: {lrxd_path}")

    version_field = args.version.strip().encode()
    if not version_field:
        sys.exit("[error] --version must be a non-empty version string")

    part1    = load_or_create_key(Path(args.key))
    real_key = derive_real_key(part1, lrxd_path, version_field)
    print(f"[antirev] key-split: real key from {lrxd_path} + version "
          f"{version_field.decode('ascii', 'replace')!r}")
    _encrypt_files(args.patches, real_key, args.output_dir, kind="patch")


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
    pe.add_argument("--daemon-libs", action="store_true",
                    help="Libs served by external daemon")

    # protect-daemon
    pd = sub.add_parser("protect-daemon",
                        help="Build lightweight lib-daemon binary "
                             "(scans its dir for encrypted .so files at runtime)")
    pd.add_argument("--stub",   required=True, help="Pre-compiled stub binary")
    pd.add_argument("--key",    required=True, help="Key file (hex); created if absent")
    pd.add_argument("--output", required=True, help="Output daemon binary")

    # encrypt-lib
    el = sub.add_parser("encrypt-lib", help="Encrypt shared library file(s) in-place")
    el.add_argument("--key",        required=True,       help="Key file (hex); created if absent")
    el.add_argument("--libs",       required=True, nargs="+", metavar="LIB")
    el.add_argument("--output-dir", default=None,        help="Write encrypted libs here (default: in-place)")

    # encrypt-patch
    ep = sub.add_parser("encrypt-patch",
                        help="Encrypt hot-patch .patch file(s) for the live-patch "
                             "shim (same ANTREV01 container/key as encrypt-lib)")
    ep.add_argument("--key",        required=True,       help="Key file (part1 share, hex); created if absent")
    ep.add_argument("--patches",    required=True, nargs="+", metavar="PATCH",
                    help="One or more hot-patch files (basename should end in .patch)")
    ep.add_argument("--lrxd",       required=True,
                    help="Target arch's lrxd daemon binary (keysplit part2 = "
                         "SHA256 of this file; must match deployed $HOME/SA/bin/sa/lrxd)")
    ep.add_argument("--version",    required=True,
                    help="version VALUE (keysplit version component; the literal "
                         "deployment version, e.g. 'V100R001C00'.  Must equal what "
                         "the target's $HOME/SA/version script parses to: text after "
                         "'Version: ', truncated before any 'SPC', stripped)")
    ep.add_argument("--output-dir", default=None,        help="Write encrypted patches here (default: in-place)")

    args = p.parse_args()

    if args.cmd == "protect-exe":
        cmd_protect_exe(args)
    elif args.cmd == "protect-daemon":
        cmd_protect_daemon(args)
    elif args.cmd == "encrypt-lib":
        cmd_encrypt_lib(args)
    elif args.cmd == "encrypt-patch":
        cmd_encrypt_patch(args)


if __name__ == "__main__":
    main()
