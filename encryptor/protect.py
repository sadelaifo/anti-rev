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
      Build a lib-daemon binary: stub + encrypted libs, no main exe.
      At runtime it decrypts all libs into memfds and serves them via
      SCM_RIGHTS to client stubs.

      protect.py protect-daemon --stub <stub> --key <keyfile> \\
                                --libs lib1.so [lib2.so ...] --output <daemon_binary>

  encrypt-lib
      Encrypt one or more shared libraries in-place (or to --output-dir).
      Encrypted format: [magic:8B][iv:12B][tag:16B][ciphertext].

      protect.py encrypt-lib --key <keyfile> --libs lib1.so [lib2.so ...] \\
                             [--output-dir <dir>]

  run
      Run a plain (unencrypted) exe with the audit shim so it can dlopen
      encrypted .so files.

      protect.py run --key <keyfile> --audit-shim <shim.so> -- <exe> [args...]

Key file: 32 bytes as 64 hex chars.  Created with a fresh random key if absent.
"""

import argparse
import os
import re
import struct
import subprocess
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


# ── Bundle building ────────────────────────────────────────────────

BFLAG_HAS_LIBS    = 0x01
BFLAG_DAEMON_LIBS = 0x02
BFLAG_WRAPPER     = 0x04


def _build_entry(path: Path, data: bytes, key: bytes, is_main: bool) -> bytes:
    """Build a single bundle entry (header + encrypted data)."""
    iv, tag, ct = encrypt_data(data, key)
    name_b = path.name.encode()
    entry  = struct.pack("<H", len(name_b))
    entry += name_b
    entry += struct.pack("<B", 1 if is_main else 0)
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
    """BFS through all DT_NEEDED deps, following unencrypted libs on disk.

    Returns lib names NOT resolvable on disk (presumed encrypted) in
    dependency-first order (deepest deps first) for LD_PRELOAD ordering.
    """
    ldcache = _build_ldconfig_cache()
    needed = []
    visited = set()
    queue = _get_dt_needed(main_path)

    while queue:
        name = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)

        lib_path = ldcache.get(name)
        if lib_path:
            # Found on disk — unencrypted system lib, follow its deps
            for dep in _get_dt_needed(Path(lib_path)):
                if dep not in visited:
                    queue.append(dep)
        else:
            # Not on disk — presumed encrypted, needs LD_PRELOAD
            needed.append(name)

    needed.reverse()
    return needed


def _build_protected(stub_path: Path, out_path: Path, key: bytes,
                     bundle_entries: bytes, num_files: int,
                     bundle_flags: int, needed_section: bytes = b""):
    """Write stub + bundle + trailer to out_path."""
    bundle = struct.pack("<IB", num_files, bundle_flags) \
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
    main_entry = _build_entry(main_path, main_data, key, is_main=True)
    print(f"[antirev] Encrypted main: {main_path.name}  "
          f"({len(main_data):,} bytes)")

    num_files = 1
    bundle_flags = 0x00
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
                                main_entry, num_files,
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
    lib_paths = [Path(p) for p in args.libs]

    if not stub_path.exists():
        sys.exit(f"[error] stub not found: {stub_path}")
    for p in lib_paths:
        if not p.exists():
            sys.exit(f"[error] lib not found: {p}")

    key = load_or_create_key(key_path)

    # Build entries for all libs (no main)
    lib_entries = b""
    for lp in lib_paths:
        ld = lp.read_bytes()
        lib_entries += _build_entry(lp, ld, key, is_main=False)
        print(f"[antirev] Daemon lib: {lp.name}  ({len(ld):,} bytes)")

    num_files = len(lib_paths)
    bundle_flags = BFLAG_HAS_LIBS

    out_size = _build_protected(stub_path, out_path, key,
                                lib_entries, num_files, bundle_flags)

    print(f"\n[antirev] Lib daemon binary → {out_path}  ({out_size:,} bytes)")
    print(f"[antirev] Key file          → {key_path}  (keep secret)")
    print(f"\n[antirev] To run:\n    {out_path}   # starts daemon, exits immediately")


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


# ── Subcommand: run ─────────────────────────────────────────────────

def cmd_run(args):
    """Launch a plain (unencrypted) exe with LD_AUDIT so it can dlopen encrypted .so files."""
    key_path   = Path(args.key)
    shim_path  = Path(args.audit_shim)

    if not key_path.exists():
        sys.exit(f"[error] key file not found: {key_path}")
    if not shim_path.exists():
        sys.exit(f"[error] audit shim not found: {shim_path}")

    key = key_path.read_text().strip()
    if len(bytes.fromhex(key)) != KEY_SIZE:
        sys.exit(f"[error] key file must contain {KEY_SIZE*2} hex chars")

    env = os.environ.copy()
    env["LD_AUDIT"] = str(shim_path.resolve())
    env["ANTIREV_KEY_HEX"] = key

    argv = args.argv
    os.execvpe(argv[0], argv, env)


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
                        help="Build lib-daemon binary (libs only, no main exe)")
    pd.add_argument("--stub",   required=True, help="Pre-compiled stub binary")
    pd.add_argument("--key",    required=True, help="Key file (hex); created if absent")
    pd.add_argument("--libs",   required=True, nargs="+", metavar="LIB",
                    help="Shared libraries to serve")
    pd.add_argument("--output", required=True, help="Output daemon binary")

    # encrypt-lib
    el = sub.add_parser("encrypt-lib", help="Encrypt shared library file(s) in-place")
    el.add_argument("--key",        required=True,       help="Key file (hex); created if absent")
    el.add_argument("--libs",       required=True, nargs="+", metavar="LIB")
    el.add_argument("--output-dir", default=None,        help="Write encrypted libs here (default: in-place)")

    # run
    ru = sub.add_parser("run", help="Run a plain exe with LD_AUDIT for encrypted .so loading")
    ru.add_argument("--key",         required=True, help="Key file (hex)")
    ru.add_argument("--audit-shim",  required=True, help="Path to audit_shim .so")
    ru.add_argument("argv",          nargs="+",     metavar="EXE [ARGS...]",
                    help="Executable and its arguments")

    args = p.parse_args()

    if args.cmd == "protect-exe":
        cmd_protect_exe(args)
    elif args.cmd == "protect-daemon":
        cmd_protect_daemon(args)
    elif args.cmd == "encrypt-lib":
        cmd_encrypt_lib(args)
    elif args.cmd == "run":
        cmd_run(args)


if __name__ == "__main__":
    main()
