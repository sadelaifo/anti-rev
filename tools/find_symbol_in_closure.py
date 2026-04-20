#!/usr/bin/env python3
"""
Scan the GUI executable and its dlopen'd libs' transitive DT_NEEDED closures
for a specific symbol.  Edit the three variables below, then run:

    python3 tools/find_symbol_in_closure.py
"""

import os
import re
import subprocess
import sys
from collections import defaultdict, deque

# ── Edit these ──────────────────────────────────────────────────────────────
SYMBOL = 'descriptor_table_your_proto_2eproto'  # substring match by default

GUI_EXE = '/proj/bin/GUI'  # the main executable — also scanned

TOP_LIBS = [
    # the 23 libs that GUI dlopens — edit these names
    '/proj/lib/libFoo.so',
    '/proj/lib/libBar.so',
    # '/proj/lib/libBaz.so',
    # ...
]

LIB_DIR = '/proj/lib'  # root dir to resolve DT_NEEDED sonames
# ────────────────────────────────────────────────────────────────────────────


def find_lib(soname, lib_dir, _cache={}):
    """Find a library by soname under lib_dir (cached)."""
    if soname in _cache:
        return _cache[soname]

    # Build index on first call
    if not _cache.get('__indexed__'):
        for root, dirs, files in os.walk(lib_dir):
            for f in files:
                if f.endswith('.so') or '.so.' in f:
                    full = os.path.join(root, f)
                    _cache.setdefault(f, full)
                    # Also index without version suffix: libfoo.so.1.2 -> libfoo.so
                    base = f.split('.so')[0] + '.so'
                    _cache.setdefault(base, full)
        _cache['__indexed__'] = True

    return _cache.get(soname)


def get_needed(elf_path):
    """Return list of DT_NEEDED sonames for an ELF."""
    try:
        out = subprocess.check_output(
            ['readelf', '-d', elf_path],
            stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    needed = []
    for line in out.splitlines():
        m = re.search(r'\(NEEDED\)\s+Shared library:\s+\[(.+?)\]', line)
        if m:
            needed.append(m.group(1))
    return needed


def get_defined_symbols(elf_path):
    """Return set of defined (non-UND) symbol names."""
    try:
        out = subprocess.check_output(
            ['nm', '-D', '--defined-only', elf_path],
            stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()
    syms = set()
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            syms.add(parts[-1])  # symbol name is last column
    return syms


def walk_closure(start_lib, lib_dir):
    """BFS walk of transitive DT_NEEDED from start_lib. Returns set of paths."""
    visited = set()
    queue = deque()

    start_real = os.path.realpath(start_lib)
    queue.append(start_real)
    visited.add(start_real)

    while queue:
        current = queue.popleft()
        for soname in get_needed(current):
            dep_path = find_lib(soname, lib_dir)
            if dep_path:
                dep_real = os.path.realpath(dep_path)
                if dep_real not in visited:
                    visited.add(dep_real)
                    queue.append(dep_real)
    return visited


def demangle(sym):
    """Demangle a C++ symbol."""
    try:
        out = subprocess.check_output(
            ['c++filt', sym], stderr=subprocess.DEVNULL, text=True
        )
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return sym


def main():
    lib_dir = os.path.realpath(LIB_DIR)
    symbol = SYMBOL

    # Build scan list: GUI exe + all top-level dlopen'd libs
    scan_targets = []
    if GUI_EXE:
        rp = os.path.realpath(GUI_EXE)
        if os.path.isfile(rp):
            scan_targets.append(rp)
        else:
            print(f'WARNING: GUI_EXE {GUI_EXE} not found, skipping', file=sys.stderr)

    for p in TOP_LIBS:
        rp = os.path.realpath(p)
        if not os.path.isfile(rp):
            print(f'WARNING: {p} not found, skipping', file=sys.stderr)
            continue
        scan_targets.append(rp)

    if not scan_targets:
        print('ERROR: no valid targets to scan', file=sys.stderr)
        sys.exit(1)

    print(f'Symbol:    {symbol}')
    print(f'Lib dir:   {lib_dir}')
    print(f'Targets:   {len(scan_targets)} (1 exe + {len(scan_targets)-1} dlopen\'d libs)')
    print()

    # For each top-level lib, walk its closure and find the symbol
    # Track: which libs define it, and which top-level lib pulls them in
    symbol_providers = defaultdict(set)  # provider_path -> set of top-level libs
    closure_sizes = {}

    for tl in scan_targets:
        tl_name = os.path.basename(tl)
        print(f'Scanning closure of {tl_name} ...', end=' ', flush=True)
        closure = walk_closure(tl, lib_dir)
        closure_sizes[tl_name] = len(closure)
        print(f'{len(closure)} libs')

        for lib_path in closure:
            syms = get_defined_symbols(lib_path)
            if args.exact:
                if symbol in syms:
                    symbol_providers[lib_path].add(tl_name)
            else:
                for s in syms:
                    if symbol in s:
                        symbol_providers[lib_path].add(tl_name)
                        break

    # Report
    print()
    if not symbol_providers:
        print(f'Symbol "{symbol}" NOT found in any closure.')
        return

    print(f'=== Found symbol in {len(symbol_providers)} lib(s) ===')
    print()

    # Sort by number of top-level importers (most shared first)
    for provider, importers in sorted(symbol_providers.items(),
                                       key=lambda x: -len(x[1])):
        pname = os.path.relpath(provider, lib_dir)
        print(f'  {pname}')
        print(f'    pulled in by: {", ".join(sorted(importers))}')
        print()

    # Summary: which top-level libs share a provider?
    if len(symbol_providers) > 1:
        print('=== DUPLICATE: symbol defined in multiple libs in the same load image ===')
        print('If GUI dlopens multiple top-level libs whose closures overlap on')
        print('different providers of this symbol, protobuf will double-register')
        print('the descriptor and crash.')
        print()
        for provider, importers in sorted(symbol_providers.items(),
                                           key=lambda x: -len(x[1])):
            pname = os.path.relpath(provider, lib_dir)
            print(f'  {pname}  <--  {", ".join(sorted(importers))}')


if __name__ == '__main__':
    main()
