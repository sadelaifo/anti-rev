#!/usr/bin/env python3
"""
symbol_collision — detect LD_PRELOAD symbol interposition risks.

When antirev puts encrypted libs on LD_PRELOAD, their exported symbols
take precedence over same-named symbols in unencrypted libraries.  This
tool finds such collisions before they cause silent misbehavior at runtime.

Checks:
  1. Encrypted LD_PRELOAD libs vs unencrypted libs the exe also uses
  2. Between encrypted LD_PRELOAD libs themselves (first one wins)

Usage:
    # Check a single exe against its encrypted deps:
    symbol_collision.py /path/to/original/Foo --enc-dir /path/to/plaintext/libs/

    # Check all exes in a directory:
    symbol_collision.py /path/to/install_dir/ --enc-dir /path/to/encrypted/libs/

    # Use antirev-pack config (reads install_dir, blacklist, encrypt_libs):
    symbol_collision.py --config pack.yaml
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


# ── ELF helpers ──────────────────────────────────────────────────────

ELF_MAGIC = b'\x7fELF'

# Boilerplate symbols present in virtually all ELFs — not meaningful collisions
IGNORE_SYMS = frozenset({
    '_init', '_fini', '__bss_start', '_edata', '_end',
    '__data_start', 'data_start', '_IO_stdin_used',
    '__dso_handle', '__TMC_END__',
})


def is_elf(path: Path) -> bool:
    try:
        with open(path, 'rb') as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def classify_elf(path: Path) -> str | None:
    """Return 'exe' or 'lib' or None."""
    try:
        with open(path, 'rb') as f:
            hdr = f.read(20)
            if len(hdr) < 20 or hdr[:4] != ELF_MAGIC:
                return None
            endian = '<' if hdr[5] == 1 else '>'
            e_type = struct.unpack_from(f'{endian}H', hdr, 16)[0]
            if e_type == 2:  # ET_EXEC
                return 'exe'
            if e_type == 3:  # ET_DYN
                return 'lib' if '.so' in path.name else 'exe'
    except OSError:
        pass
    return None


def parse_elf_dynamic(path: str) -> tuple[str, list[str], set[str]]:
    """Parse soname, DT_NEEDED, and exported (defined) dynamic symbols.

    Returns (soname, needed_list, defined_global_syms).
    """
    try:
        result = subprocess.run(
            ['readelf', '-d', '--dyn-syms', path],
            capture_output=True, text=True, timeout=30
        )
        out = result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return '', [], set()

    soname = ''
    needed = []
    syms = set()

    for line in out.splitlines():
        # DT_SONAME
        m = re.search(r'\(SONAME\)\s+Library soname: \[(.+)\]', line)
        if m:
            soname = m.group(1)
            continue
        # DT_NEEDED
        m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
        if m:
            needed.append(m.group(1))
            continue
        # Dynamic symbol table entry:
        # Num: Value Size Type Bind Vis Ndx Name
        # We want GLOBAL or WEAK FUNC/OBJECT that are DEFINED (Ndx != UND)
        m = re.match(
            r'\s+\d+:\s+[0-9a-f]+\s+\d+\s+'
            r'(\w+)\s+(\w+)\s+\w+\s+(\w+)\s+(.*)',
            line
        )
        if m:
            sym_type, sym_bind, ndx, sym_name = m.groups()
            # Skip undefined, local, and non-function/object symbols
            if ndx == 'UND' or ndx == '0':
                continue
            if sym_bind not in ('GLOBAL', 'WEAK'):
                continue
            if sym_type not in ('FUNC', 'OBJECT', 'IFUNC'):
                continue
            # Strip version suffix (e.g. "foo@@VERS_1.0" -> "foo")
            clean = sym_name.split('@@')[0].split('@')[0].strip()
            if clean and clean not in IGNORE_SYMS:
                syms.add((clean, sym_bind, sym_type))

    return soname, needed, syms


def build_ldconfig_cache() -> dict[str, str]:
    """Build soname -> path mapping from ldconfig + LD_LIBRARY_PATH."""
    cache = {}
    for d in os.environ.get('LD_LIBRARY_PATH', '').split(':'):
        if not d or not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                if '.so' in name and name not in cache:
                    cache[name] = os.path.join(d, name)
        except OSError:
            pass
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


# ── Parallel ELF cache ───────────────────────────────────────────────

class ElfCache:
    """Thread-safe cache for parsed ELF metadata."""

    def __init__(self):
        self._data = {}  # path_str -> (soname, needed, syms)

    def bulk_parse(self, paths: list[str]):
        n = min(os.cpu_count() or 4, len(paths), 64)
        with ThreadPoolExecutor(max_workers=n) as pool:
            for p, result in zip(paths, pool.map(parse_elf_dynamic, paths)):
                self._data[p] = result

    def get(self, path: str) -> tuple[str, list[str], set[str]]:
        if path not in self._data:
            self._data[path] = parse_elf_dynamic(path)
        return self._data[path]

    def soname(self, path: str) -> str:
        return self.get(path)[0]

    def needed(self, path: str) -> list[str]:
        return self.get(path)[1]

    def symbols(self, path: str) -> set[str]:
        return self.get(path)[2]


# ── Core analysis ────────────────────────────────────────────────────

def find_preload_libs(exe_path: str, encrypted_names: set[str],
                      enc_paths: dict[str, str],
                      soname_to_filename: dict[str, str],
                      cache: ElfCache,
                      ldcache: dict[str, str]) -> list[str]:
    """BFS from exe's DT_NEEDED to find which encrypted libs go on LD_PRELOAD.

    Same logic as antirev-pack.py's get_transitive_needed().
    Returns filenames in dependency-first order.
    """
    result = []
    visited = set()
    queue = list(cache.needed(exe_path))

    while queue:
        name = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)

        filename = soname_to_filename.get(name, name)

        if filename in encrypted_names:
            result.append(filename)
            p = enc_paths.get(filename) or enc_paths.get(name)
            if p:
                for dep in cache.needed(p):
                    if dep not in visited:
                        queue.append(dep)
        else:
            # Unencrypted — follow deps to find encrypted libs behind it
            lib_path = ldcache.get(name)
            if lib_path:
                for dep in cache.needed(lib_path):
                    if dep not in visited:
                        queue.append(dep)

    result.reverse()
    return result


def find_unencrypted_deps(exe_path: str, encrypted_names: set[str],
                          soname_to_filename: dict[str, str],
                          cache: ElfCache,
                          ldcache: dict[str, str]) -> dict[str, str]:
    """BFS from exe to find all unencrypted libs it depends on.

    Returns {soname: resolved_path}.
    """
    result = {}
    visited = set()
    queue = list(cache.needed(exe_path))

    while queue:
        name = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)

        filename = soname_to_filename.get(name, name)
        if filename in encrypted_names:
            continue  # skip encrypted libs

        lib_path = ldcache.get(name)
        if lib_path:
            result[name] = lib_path
            for dep in cache.needed(lib_path):
                if dep not in visited:
                    queue.append(dep)

    return result


def check_collisions(exe_name: str,
                     preload_libs: list[str],
                     enc_paths: dict[str, str],
                     unenc_deps: dict[str, str],
                     cache: ElfCache) -> list[dict]:
    """Find symbol collisions for one exe.

    Returns list of collision records:
      {sym, sym_type, winner_lib, loser_lib, loser_bind, kind}
    """
    collisions = []

    # Collect symbols from each preloaded encrypted lib (in order)
    preload_syms = {}  # sym_name -> (lib_name, bind, type)
    for lib_name in preload_libs:
        p = enc_paths.get(lib_name)
        if not p:
            continue
        for sym_name, sym_bind, sym_type in cache.symbols(p):
            if sym_name not in preload_syms:
                preload_syms[sym_name] = (lib_name, sym_bind, sym_type)

    # Check 1: encrypted LD_PRELOAD vs unencrypted libs
    for dep_name, dep_path in unenc_deps.items():
        for sym_name, sym_bind, sym_type in cache.symbols(dep_path):
            if sym_name in preload_syms:
                winner_lib, winner_bind, winner_type = preload_syms[sym_name]
                # WEAK symbols are designed to be overridden — lower severity
                severity = 'warn'
                if sym_bind == 'GLOBAL' and winner_bind == 'GLOBAL':
                    severity = 'error'
                collisions.append({
                    'sym': sym_name,
                    'sym_type': sym_type,
                    'winner': winner_lib,
                    'winner_bind': winner_bind,
                    'loser': dep_name,
                    'loser_bind': sym_bind,
                    'kind': 'preload_vs_unenc',
                    'severity': severity,
                })

    # Check 2: between encrypted LD_PRELOAD libs themselves
    seen = {}  # sym_name -> first lib
    for lib_name in preload_libs:
        p = enc_paths.get(lib_name)
        if not p:
            continue
        for sym_name, sym_bind, sym_type in cache.symbols(p):
            if sym_name in seen and seen[sym_name] != lib_name:
                severity = 'warn'
                if sym_bind == 'GLOBAL':
                    severity = 'error'
                collisions.append({
                    'sym': sym_name,
                    'sym_type': sym_type,
                    'winner': seen[sym_name],
                    'winner_bind': 'GLOBAL',
                    'loser': lib_name,
                    'loser_bind': sym_bind,
                    'kind': 'preload_vs_preload',
                    'severity': severity,
                })
            elif sym_name not in seen:
                seen[sym_name] = lib_name

    return collisions


# ── Output formatting ────────────────────────────────────────────────

def print_report(exe_name: str, preload_libs: list[str],
                 unenc_deps: dict[str, str],
                 collisions: list[dict]):
    print(f"\n{'='*70}")
    print(f"  {exe_name}")
    print(f"{'='*70}")
    print(f"  LD_PRELOAD encrypted libs ({len(preload_libs)}):")
    for lib in preload_libs:
        print(f"    - {lib}")
    print(f"  Unencrypted deps ({len(unenc_deps)}):")
    for name in sorted(unenc_deps):
        print(f"    - {name}")

    if not collisions:
        print(f"\n  No symbol collisions found.\n")
        return

    errors = [c for c in collisions if c['severity'] == 'error']
    warns  = [c for c in collisions if c['severity'] == 'warn']

    if errors:
        print(f"\n  ERRORS ({len(errors)} GLOBAL symbol collisions):")
        print(f"  {'Symbol':<40} {'Type':<8} {'Winner (LD_PRELOAD)':<28} {'Loser':<28}")
        print(f"  {'-'*40} {'-'*8} {'-'*28} {'-'*28}")
        for c in sorted(errors, key=lambda x: x['sym']):
            print(f"  {c['sym']:<40} {c['sym_type']:<8} {c['winner']:<28} {c['loser']:<28}")

    if warns:
        print(f"\n  WARNINGS ({len(warns)} WEAK symbol collisions — usually harmless):")
        # Group by lib pair to reduce noise
        pairs = defaultdict(list)
        for c in warns:
            pairs[(c['winner'], c['loser'])].append(c['sym'])
        for (winner, loser), syms in sorted(pairs.items()):
            if len(syms) <= 5:
                print(f"    {winner} overrides {loser}: {', '.join(sorted(syms))}")
            else:
                shown = ', '.join(sorted(syms)[:5])
                print(f"    {winner} overrides {loser}: {shown} ... (+{len(syms)-5} more)")

    print()


# ── Main ─────────────────────────────────────────────────────────────

def scan_encrypted_libs(enc_dir: Path) -> list[Path]:
    """Find all .so files in enc_dir (plaintext originals for analysis)."""
    libs = []
    for p in sorted(enc_dir.rglob('*')):
        if p.is_file() and '.so' in p.name and is_elf(p):
            libs.append(p)
    return libs


def scan_exes(target: Path) -> list[Path]:
    """Find executables in target (single file or directory)."""
    if target.is_file():
        if classify_elf(target) == 'exe':
            return [target]
        return []
    exes = []
    for p in sorted(target.rglob('*')):
        if p.is_file() and classify_elf(p) == 'exe':
            exes.append(p)
    return exes


def main():
    ap = argparse.ArgumentParser(
        description="Detect LD_PRELOAD symbol collisions for antirev-encrypted binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    ap.add_argument("target", nargs='?',
                    help="Executable or directory of executables (plaintext originals)")
    ap.add_argument("--enc-dir", required=True,
                    help="Directory of plaintext .so files that will be encrypted")
    ap.add_argument("-L", "--lib-dir", action="append", default=[],
                    help="Additional library search directories (repeatable)")
    ap.add_argument("--json", action="store_true",
                    help="Output as JSON for scripting")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Show per-lib symbol counts")
    args = ap.parse_args()

    if not args.target:
        ap.error("target (exe or directory) is required")

    target = Path(args.target)
    enc_dir = Path(args.enc_dir)

    if not target.exists():
        sys.exit(f"[error] target not found: {target}")
    if not enc_dir.exists():
        sys.exit(f"[error] encrypted lib dir not found: {enc_dir}")

    # Add lib dirs to LD_LIBRARY_PATH for resolution
    for d in args.lib_dir:
        ld = os.environ.get('LD_LIBRARY_PATH', '')
        os.environ['LD_LIBRARY_PATH'] = d + (':' + ld if ld else '')

    # Discover files
    exes = scan_exes(target)
    enc_libs = scan_encrypted_libs(enc_dir)

    if not exes:
        sys.exit(f"[error] no executables found in {target}")
    if not enc_libs:
        sys.exit(f"[error] no .so files found in {enc_dir}")

    print(f"[scan] {len(exes)} executable(s), {len(enc_libs)} encrypted lib(s)")

    # Build caches
    ldcache = build_ldconfig_cache()
    cache = ElfCache()

    all_paths = [str(p) for p in enc_libs] + [str(p) for p in exes]
    print(f"[scan] Parsing {len(all_paths)} ELFs...")
    cache.bulk_parse(all_paths)

    # Build soname maps for encrypted libs
    encrypted_names = set()
    enc_paths = {}       # filename -> abs path str
    soname_to_filename = {}

    for p in enc_libs:
        fname = p.name
        encrypted_names.add(fname)
        enc_paths[fname] = str(p)

        soname = cache.soname(str(p))
        if soname and soname != fname:
            soname_to_filename[soname] = fname
            enc_paths[soname] = str(p)

    # Analyze each exe
    total_errors = 0
    total_warns = 0
    all_results = []

    for exe in exes:
        exe_str = str(exe)
        exe_name = exe.name

        preload_libs = find_preload_libs(
            exe_str, encrypted_names, enc_paths,
            soname_to_filename, cache, ldcache)

        unenc_deps = find_unencrypted_deps(
            exe_str, encrypted_names, soname_to_filename,
            cache, ldcache)

        # Parse any unencrypted deps not yet in cache
        for dep_path in unenc_deps.values():
            if dep_path not in cache._data:
                cache.get(dep_path)

        collisions = check_collisions(
            exe_name, preload_libs, enc_paths, unenc_deps, cache)

        errors = [c for c in collisions if c['severity'] == 'error']
        warns  = [c for c in collisions if c['severity'] == 'warn']
        total_errors += len(errors)
        total_warns += len(warns)

        if args.json:
            all_results.append({
                'exe': exe_name,
                'preload': preload_libs,
                'unencrypted': list(unenc_deps.keys()),
                'collisions': collisions,
            })
        else:
            print_report(exe_name, preload_libs, unenc_deps, collisions)

    if args.json:
        import json
        print(json.dumps(all_results, indent=2))

    # Summary
    print(f"{'='*70}")
    print(f"  Summary: {len(exes)} exe(s) checked")
    print(f"    Errors:   {total_errors} (GLOBAL symbol collisions)")
    print(f"    Warnings: {total_warns} (WEAK symbol collisions)")
    print(f"{'='*70}")

    if total_errors > 0:
        print("\nGLOBAL collisions found — these can cause silent misbehavior.")
        print("The LD_PRELOAD'd encrypted lib's symbol will override the")
        print("unencrypted lib's version in ALL code paths.\n")
        print("Options:")
        print("  1. Rename the colliding symbol in your business lib")
        print("  2. Use symbol versioning to disambiguate")
        print("  3. Move the colliding lib from LD_PRELOAD to ANTIREV_FD_MAP")
        print("     (requires removing it from the exe's DT_NEEDED chain)")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
