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

    blacklist:                         # optional: items to skip (copied as-is)
      - redis-server                   # exact filename match
      - libcrypto.so*                  # glob/wildcard pattern
      - third_party/                   # subdirectory (trailing slash)
      - lib/legacy                     # subdirectory (no trailing slash also works)
      - bin/debug_tool                 # specific relative path

What it does:
  - Recursively scans install_dir for all ELF files (executables and libraries)
  - Classifies each as executable (ET_EXEC/ET_DYN without .so) or shared library
  - Skips blacklisted files and directories (copied as-is instead)
  - Protects executables with the stub, encrypts shared libraries
  - Copies all non-ELF files as-is
  - output_dir is a drop-in replacement: no config or script changes needed
"""

import argparse
import fnmatch
import shutil
import struct
import subprocess
import sys
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


def classify_elf(path: Path) -> tuple[str, str] | None:
    """Classify an ELF file. Returns (kind, arch) or None if not ELF.

    kind: 'exe' or 'lib'
    arch: 'x86_64' or 'aarch64'
    """
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic != ELF_MAGIC:
                return None

            # ELF header: e_ident[4] = class, [5] = endianness
            f.seek(4)
            ei_class = struct.unpack('B', f.read(1))[0]   # 1=32bit, 2=64bit
            ei_data  = struct.unpack('B', f.read(1))[0]    # 1=LE, 2=BE

            endian = '<' if ei_data == 1 else '>'

            # e_type at offset 16 (2 bytes)
            f.seek(16)
            e_type = struct.unpack(f'{endian}H', f.read(2))[0]

            # e_machine at offset 18 (2 bytes)
            e_machine = struct.unpack(f'{endian}H', f.read(2))[0]

            if e_machine == EM_AARCH64:
                arch = 'aarch64'
            else:
                arch = 'x86_64'

            # Classify: .so files are libraries, everything else that is
            # ET_EXEC or ET_DYN (PIE executables) is an executable.
            # Many modern executables are ET_DYN (PIE), so we use the
            # filename to distinguish: if any component contains ".so"
            # it's a library.
            name = path.name
            is_so = '.so' in name

            if e_type == ET_EXEC:
                kind = 'exe'
            elif e_type == ET_DYN:
                kind = 'lib' if is_so else 'exe'
            else:
                return None  # ET_REL, ET_CORE, etc. — skip

            return kind, arch
    except (OSError, struct.error):
        return None


def is_blacklisted(rel_path: str, blacklist: list[str]) -> bool:
    """Check if a relative path matches any blacklist entry.

    Blacklist entries can be:
      - Exact filename:      "redis-server"    matches any file with that name
      - Glob pattern:        "libcrypto.so*"   matches filenames via fnmatch
      - Subdirectory:        "third_party/"    matches anything under that dir
      - Relative path:       "bin/debug_tool"  matches that exact relative path
    """
    name = Path(rel_path).name
    # Normalize to forward slashes for consistent matching
    rel_normalized = rel_path.replace('\\', '/')

    for entry in blacklist:
        entry = entry.replace('\\', '/')

        # Subdirectory match: entry ends with / or matches a directory prefix
        if entry.endswith('/'):
            dir_prefix = entry  # e.g. "third_party/"
            if rel_normalized.startswith(dir_prefix) or \
               rel_normalized == entry.rstrip('/'):
                return True
            continue

        # Check if entry looks like a relative path (contains /)
        if '/' in entry:
            # Exact relative path match or directory prefix match
            if rel_normalized == entry:
                return True
            # Also treat as directory prefix (e.g. "lib/legacy" skips
            # "lib/legacy/foo.so")
            if rel_normalized.startswith(entry + '/'):
                return True
            continue

        # Filename match (exact or glob pattern)
        if fnmatch.fnmatch(name, entry):
            return True

    return False


def encrypt_lib(src: Path, dst: Path, key: bytes):
    data = src.read_bytes()
    iv, tag, ct = encrypt_data(data, key)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(MAGIC + iv + tag + ct)
    print(f"[pack] Encrypted  lib: {str(src.name):<30}  "
          f"{len(data):>10,} -> {dst.stat().st_size:>10,} bytes")


def protect_exe(src: Path, stub: Path, dst: Path, key_path: Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([
        sys.executable,
        str(Path(__file__).parent / 'protect.py'),
        'protect-exe',
        '--stub',   str(stub),
        '--main',   str(src),
        '--key',    str(key_path),
        '--output', str(dst),
    ], capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"[error] protect-exe failed for {src}:\n{result.stderr}")
    for line in result.stdout.splitlines():
        if 'Encrypted main' in line or 'Protected binary' in line:
            print(f"[pack] {line.strip().lstrip('[antirev] ')}")


def main():
    ap = argparse.ArgumentParser(description="antirev config-driven batch protector")
    ap.add_argument("config", help="YAML config file")
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
    blacklist   = cfg.get('blacklist', [])

    # Build arch -> stub mapping (supports single 'stub' or multi-arch 'stubs')
    stubs: dict[str, Path] = {}
    if 'stubs' in cfg:
        for arch, p in cfg['stubs'].items():
            stubs[arch] = (config_path.parent / p).resolve()
    elif 'stub' in cfg:
        # Single stub — detect its architecture and also use as fallback
        single = (config_path.parent / cfg['stub']).resolve()
        elf_info = classify_elf(single)
        if elf_info:
            stubs[elf_info[1]] = single
        else:
            # Can't detect arch, assign to both as fallback
            stubs['x86_64'] = single
            stubs['aarch64'] = single

    if not install_dir.exists():
        sys.exit(f"[error] install_dir not found: {install_dir}")
    for arch, stub in stubs.items():
        if not stub.exists():
            sys.exit(f"[error] stub not found for {arch}: {stub}")

    key = load_or_create_key(key_path)

    # ── Scan all files ────────────────────────────────────────────────
    exe_files  = []   # (rel_path, arch, abs_path)
    lib_files  = []   # abs_path
    copy_files = []   # abs_path
    skipped    = []   # (rel_path, reason)

    for src in sorted(install_dir.rglob('*')):
        if not src.is_file():
            continue

        rel = str(src.relative_to(install_dir))

        if is_blacklisted(rel, blacklist):
            copy_files.append(src)
            skipped.append((rel, 'blacklisted'))
            continue

        elf_info = classify_elf(src)
        if elf_info is None:
            copy_files.append(src)
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
    print(f"[pack]   Other files: {len(copy_files)}")
    if skipped:
        print(f"[pack]   Blacklisted: {len(skipped)}")
        for rel, reason in skipped:
            print(f"[pack]     skip: {rel}")
    print()

    # ── Encrypt shared libraries ──────────────────────────────────────
    if lib_files:
        print(f"[pack] Encrypting {len(lib_files)} shared "
              f"librar{'y' if len(lib_files) == 1 else 'ies'}...")
        for src in lib_files:
            encrypt_lib(src, output_dir / src.relative_to(install_dir), key)
        print()

    # ── Protect executables ───────────────────────────────────────────
    if exe_files:
        print(f"[pack] Protecting {len(exe_files)} executable(s)...")
        for rel, arch, src in exe_files:
            if arch not in stubs:
                sys.exit(f"[error] no stub for arch '{arch}' "
                         f"(needed by {rel}). Add it to 'stubs' in config.")
            protect_exe(src, stubs[arch], output_dir / rel, key_path)
        print()

    # ── Copy everything else as-is ────────────────────────────────────
    if copy_files:
        for src in copy_files:
            dst = output_dir / src.relative_to(install_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        print(f"[pack] Copied {len(copy_files)} file(s) as-is")
        print()

    print(f"[pack] Done")
    print(f"[pack]   Output -> {output_dir}")
    print(f"[pack]   Key    -> {key_path}  (keep secret)")


if __name__ == '__main__':
    main()
