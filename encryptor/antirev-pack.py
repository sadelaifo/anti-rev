#!/usr/bin/env python3
"""
antirev-pack — manifest-driven batch protector

Usage:
    antirev-pack.py <manifest.yaml>

Manifest format:

    key: ./production.key          # created if absent

    stubs:
      x86_64:  ./build/stub
      aarch64: ./build/stub_aarch64

    install_dir: /opt/myapp        # source: original (unencrypted) software
    output_dir:  /opt/myapp-prot   # destination: protected drop-in replacement

    exes:
      - path: bin/daemon1          # relative to install_dir
        arch: x86_64
      - path: bin/daemon2
        arch: x86_64
      - path: slave/bin/worker1
        arch: aarch64

What it does:
  - Encrypts every .so found in install_dir  → output_dir (same relative path)
  - Protects each listed exe with the stub   → output_dir (same relative path)
  - Copies everything else (configs etc.)    → output_dir as-is
  - output_dir is a drop-in replacement: no config or script changes needed
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

sys.path.insert(0, str(Path(__file__).parent))
from protect import load_or_create_key, encrypt_data, MAGIC


def encrypt_lib(src: Path, dst: Path, key: bytes):
    data = src.read_bytes()
    iv, tag, ct = encrypt_data(data, key)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(MAGIC + iv + tag + ct)
    print(f"[pack] Encrypted  lib: {src.name:<30}  "
          f"{len(data):>10,} → {dst.stat().st_size:>10,} bytes")


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
    ap = argparse.ArgumentParser(description="antirev manifest-driven batch protector")
    ap.add_argument("manifest", help="YAML manifest file")
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        sys.exit(f"[error] manifest not found: {manifest_path}")

    with open(manifest_path) as f:
        m = yaml.safe_load(f)

    install_dir = Path(m['install_dir']).resolve()
    output_dir  = Path(m['output_dir']).resolve()
    key_path    = (manifest_path.parent / m['key']).resolve()
    stubs       = {arch: (manifest_path.parent / p).resolve()
                   for arch, p in m.get('stubs', {}).items()}

    if not install_dir.exists():
        sys.exit(f"[error] install_dir not found: {install_dir}")
    for arch, stub in stubs.items():
        if not stub.exists():
            sys.exit(f"[error] stub not found for {arch}: {stub}")

    key = load_or_create_key(key_path)

    exe_specs = []
    for spec in m.get('exes', []):
        rel  = spec['path']
        arch = spec.get('arch', 'x86_64')
        src  = (install_dir / rel).resolve()
        if not src.exists():
            sys.exit(f"[error] exe not found: {src}")
        if arch not in stubs:
            sys.exit(f"[error] no stub configured for arch '{arch}'")
        exe_specs.append((rel, arch, src))

    exe_paths = {src for _, _, src in exe_specs}

    # ── Encrypt all .so files ─────────────────────────────────────────
    so_files = [p for p in install_dir.rglob('*.so*')
                if p.is_file() and p not in exe_paths]
    print(f"[pack] Encrypting {len(so_files)} shared librar{'y' if len(so_files)==1 else 'ies'}...")
    for src in sorted(so_files):
        encrypt_lib(src, output_dir / src.relative_to(install_dir), key)
    print()

    # ── Protect each exe ──────────────────────────────────────────────
    print(f"[pack] Protecting {len(exe_specs)} executable(s)...")
    for rel, arch, src in exe_specs:
        protect_exe(src, stubs[arch], output_dir / rel, key_path)
    print()

    # ── Copy everything else as-is ────────────────────────────────────
    so_paths = set(so_files)
    copied = 0
    for src in install_dir.rglob('*'):
        if not src.is_file() or src in exe_paths or src in so_paths:
            continue
        dst = output_dir / src.relative_to(install_dir)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1
    if copied:
        print(f"[pack] Copied {copied} file(s) as-is")
        print()

    print(f"[pack] ✓ Output → {output_dir}")
    print(f"[pack]   Key    → {key_path}  (keep secret)")


if __name__ == '__main__':
    main()
