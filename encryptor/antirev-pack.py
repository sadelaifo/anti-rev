#!/usr/bin/env python3
"""
antirev-pack — config-driven batch protector

Usage:
    antirev-pack.py <config.yaml>

Config format:

    install_dir: /opt/myapp            # source directory with original binaries
    output_dir:  /opt/myapp-prot       # destination for protected output
    key: ./production.key              # created if absent
    stub: ./build/stub                 # single stub (when all binaries are same arch)
    # or multi-arch:
    # stubs:
    #   x86_64:  ./build/stub
    #   aarch64: ./build/stub_aarch64

    blacklist:                         # optional: ELF files to skip entirely
      - redis-server                   # exact filename match
      - libcrypto.so*                  # glob/wildcard pattern
      - third_party/                   # subdirectory (trailing slash)
      - lib/legacy                     # subdirectory (no trailing slash also works)
      - bin/debug_tool                 # specific relative path

    copy:                              # optional: non-ELF files to copy as-is
      - etc/                           # copy entire config directory
      - bin/start.sh                   # copy a specific file
      - *.conf                         # copy by pattern

What it does:
  - Recursively scans install_dir for all ELF files (executables and libraries)
  - Classifies each as executable (ET_EXEC/ET_DYN without .so) or shared library
  - Skips blacklisted ELF files entirely (not copied, not encrypted)
  - Only copies non-ELF files that match the 'copy' list (if omitted, nothing copied)
  - Protects executables with the stub, encrypts shared libraries
  - Uses parallel workers for encryption, protection, and file copies
"""

import argparse
import fnmatch
import os
import shutil
import struct
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

sys.path.insert(0, str(Path(__file__).parent))
from protect import load_or_create_key, encrypt_data, MAGIC

# ELF magic and type constants
ELF_MAGIC = b'\x7fELF'
ET_EXEC = 2
ET_DYN  = 3

# ELF machine types for architecture detection
EM_X86_64  = 62
EM_AARCH64 = 183


def classify_elf(path: Path) -> tuple[str, str]:
    """Classify an ELF file. Returns (kind, arch) or None if not ELF.

    kind: 'exe' or 'lib'
    arch: 'x86_64' or 'aarch64'
    """
    try:
        with open(path, 'rb') as f:
            # Single read of the first 20 bytes covers everything we need:
            # [0:4]   ELF magic
            # [5]     endianness
            # [16:18] e_type
            # [18:20] e_machine
            hdr = f.read(20)
            if len(hdr) < 20 or hdr[:4] != ELF_MAGIC:
                return None

            endian = '<' if hdr[5] == 1 else '>'
            e_type    = struct.unpack_from(f'{endian}H', hdr, 16)[0]
            e_machine = struct.unpack_from(f'{endian}H', hdr, 18)[0]

            arch = 'aarch64' if e_machine == EM_AARCH64 else 'x86_64'

            is_so = '.so' in path.name
            if e_type == ET_EXEC:
                kind = 'exe'
            elif e_type == ET_DYN:
                kind = 'lib' if is_so else 'exe'
            else:
                return None

            return kind, arch
    except OSError:
        return None


def is_blacklisted(rel_path: str, blacklist: list[tuple[str, str]]) -> bool:
    """Check if a relative path matches any pre-classified blacklist entry.

    Each entry is (pattern, kind) where kind is 'dir', 'path', or 'name'.
    """
    name = Path(rel_path).name
    rel_normalized = rel_path.replace('\\', '/')

    for pattern, kind in blacklist:
        if kind == 'dir':
            if rel_normalized.startswith(pattern) or \
               rel_normalized == pattern.rstrip('/'):
                return True
        elif kind == 'path':
            if rel_normalized == pattern or \
               rel_normalized.startswith(pattern + '/'):
                return True
        else:  # 'name'
            if fnmatch.fnmatch(name, pattern):
                return True

    return False


def compile_blacklist(raw: list[str]) -> list[tuple[str, str]]:
    """Pre-classify blacklist entries once instead of per-file."""
    compiled = []
    for entry in raw:
        entry = entry.replace('\\', '/')
        if entry.endswith('/'):
            compiled.append((entry, 'dir'))
        elif '/' in entry:
            compiled.append((entry, 'path'))
        else:
            compiled.append((entry, 'name'))
    return compiled


# ── Worker functions (run in child processes) ─────────────────────────

def _encrypt_lib_worker(src: str, dst: str, key: bytes) -> str:
    """Encrypt a single .so file. Returns status string."""
    src_p, dst_p = Path(src), Path(dst)
    data = src_p.read_bytes()
    iv, tag, ct = encrypt_data(data, key)
    dst_p.parent.mkdir(parents=True, exist_ok=True)
    dst_p.write_bytes(MAGIC + iv + tag + ct)
    out_size = dst_p.stat().st_size
    return (f"[pack] Encrypted  lib: {src_p.name:<30}  "
            f"{len(data):>10,} -> {out_size:>10,} bytes")


def _protect_exe_worker(src: str, stub: str, dst: str, key: bytes) -> str:
    """Encrypt and bundle an executable in-process. Returns status string."""
    src_p  = Path(src)
    stub_p = Path(stub)
    dst_p  = Path(dst)

    data = src_p.read_bytes()
    iv, tag, ct = encrypt_data(data, key)
    name_b = src_p.name.encode()

    entry  = struct.pack("<H", len(name_b))
    entry += name_b
    entry += struct.pack("<B", 1)   # flags: is_main
    entry += iv
    entry += tag
    entry += struct.pack("<Q", len(ct))
    entry += ct

    bundle = struct.pack("<I", 1) + entry

    stub_data     = stub_p.read_bytes()
    bundle_offset = len(stub_data)
    trailer       = struct.pack("<Q", bundle_offset) + key + MAGIC

    dst_p.parent.mkdir(parents=True, exist_ok=True)
    dst_p.write_bytes(stub_data + bundle + trailer)
    os.chmod(str(dst_p), 0o755)

    out_size = dst_p.stat().st_size
    return (f"[pack] Protected  exe: {src_p.name:<30}  "
            f"{len(data):>10,} -> {out_size:>10,} bytes")


def _copy_worker(items: list[tuple[str, str]]) -> int:
    """Copy a batch of files. Returns count."""
    for src, dst in items:
        dst_p = Path(dst)
        dst_p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst_p)
    return len(items)


def main():
    ap = argparse.ArgumentParser(description="antirev config-driven batch protector")
    ap.add_argument("config", help="YAML config file")
    ap.add_argument("-j", "--jobs", type=int, default=0,
                    help="Number of parallel workers (default: CPU count)")
    args = ap.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        sys.exit(f"[error] config not found: {config_path}")

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    # ── Validate required fields ──────────────────────────────────────
    for field in ('install_dir', 'output_dir'):
        if field not in cfg:
            sys.exit(f"[error] missing required field '{field}' in config")
    if 'stub' not in cfg and 'stubs' not in cfg:
        sys.exit("[error] config must have 'stub' or 'stubs' field")

    install_dir = Path(cfg['install_dir']).resolve()
    output_dir  = Path(cfg['output_dir']).resolve()
    key_path    = (config_path.parent / cfg.get('key', 'antirev.key')).resolve()
    blacklist   = compile_blacklist(cfg.get('blacklist', []))
    workers     = args.jobs if args.jobs > 0 else (os.cpu_count() or 4)

    # Build arch -> stub mapping (supports single 'stub' or multi-arch 'stubs')
    stubs: dict[str, Path] = {}
    if 'stubs' in cfg:
        for arch, p in cfg['stubs'].items():
            stubs[arch] = (config_path.parent / p).resolve()
    elif 'stub' in cfg:
        single = (config_path.parent / cfg['stub']).resolve()
        elf_info = classify_elf(single)
        if elf_info:
            stubs[elf_info[1]] = single
        else:
            stubs['x86_64'] = single
            stubs['aarch64'] = single

    if not install_dir.exists():
        sys.exit(f"[error] install_dir not found: {install_dir}")
    for arch, stub in stubs.items():
        if not stub.exists():
            sys.exit(f"[error] stub not found for {arch}: {stub}")

    key = load_or_create_key(key_path)
    copylist = compile_blacklist(cfg.get('copy', []))

    # ── Scan all files ────────────────────────────────────────────────
    exe_files  = []   # (rel_path, arch, abs_path)
    lib_files  = []   # abs_path
    copy_files = []   # abs_path
    skipped    = []   # rel_path
    ignored    = 0    # non-ELF files not in copy list

    for src in sorted(install_dir.rglob('*')):
        if not src.is_file():
            continue

        rel = str(src.relative_to(install_dir))

        if is_blacklisted(rel, blacklist):
            skipped.append(rel)
            continue

        elf_info = classify_elf(src)
        if elf_info is None:
            # Non-ELF: only copy if it matches the copy list
            if copylist and is_blacklisted(rel, copylist):
                copy_files.append(src)
            else:
                ignored += 1
            continue

        kind, arch = elf_info
        if kind == 'exe':
            exe_files.append((rel, arch, src))
        else:
            lib_files.append(src)

    # ── Report scan results ───────────────────────────────────────────
    print(f"[pack] Scanned {install_dir}")
    print(f"[pack]   Executables:  {len(exe_files)}")
    print(f"[pack]   Libraries:   {len(lib_files)}")
    print(f"[pack]   Copy:        {len(copy_files)}")
    print(f"[pack]   Ignored:     {ignored}")
    print(f"[pack]   Workers:     {workers}")
    if skipped:
        print(f"[pack]   Blacklisted: {len(skipped)}")
        for rel in skipped:
            print(f"[pack]     skip: {rel}")
    print()

    # ── Encrypt shared libraries (parallel) ───────────────────────────
    if lib_files:
        print(f"[pack] Encrypting {len(lib_files)} shared "
              f"librar{'y' if len(lib_files) == 1 else 'ies'}...")
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _encrypt_lib_worker,
                    str(src),
                    str(output_dir / src.relative_to(install_dir)),
                    key,
                ): src
                for src in lib_files
            }
            for fut in as_completed(futures):
                try:
                    print(fut.result())
                except Exception as e:
                    sys.exit(f"[error] encrypt failed for {futures[fut]}: {e}")
        print()

    # ── Protect executables (parallel) ────────────────────────────────
    if exe_files:
        print(f"[pack] Protecting {len(exe_files)} executable(s)...")
        for rel, arch, src in exe_files:
            if arch not in stubs:
                sys.exit(f"[error] no stub for arch '{arch}' "
                         f"(needed by {rel}). Add it to 'stubs' in config.")
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _protect_exe_worker,
                    str(src),
                    str(stubs[arch]),
                    str(output_dir / rel),
                    key,
                ): rel
                for rel, arch, src in exe_files
            }
            for fut in as_completed(futures):
                try:
                    print(fut.result())
                except Exception as e:
                    sys.exit(f"[error] protect failed for {futures[fut]}: {e}")
        print()

    # ── Copy everything else (parallel, batched) ──────────────────────
    if copy_files:
        pairs = [
            (str(src), str(output_dir / src.relative_to(install_dir)))
            for src in copy_files
        ]
        # Split into batches — one per worker, minimum 1
        batch_size = max(1, len(pairs) // workers)
        batches = [pairs[i:i + batch_size]
                   for i in range(0, len(pairs), batch_size)]

        with ProcessPoolExecutor(max_workers=min(workers, len(batches))) as pool:
            total = sum(pool.map(_copy_worker, batches))
        print(f"[pack] Copied {total} file(s) as-is")
        print()

    print(f"[pack] Done")
    print(f"[pack]   Output -> {output_dir}")
    print(f"[pack]   Key    -> {key_path}  (keep secret)")


if __name__ == '__main__':
    main()
