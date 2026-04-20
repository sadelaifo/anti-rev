#!/usr/bin/env python3
"""
Scan the GUI executable and its dlopen'd libs' transitive DT_NEEDED closures
for specific symbols.

Usage:
    python3 tools/find_symbol_in_closure.py --config config.json
    python3 tools/find_symbol_in_closure.py   # uses find_symbol_in_closure.json next to script
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'find_symbol_in_closure.json')

# ── Caches (populated once, reused across closures) ────────────────────────
_needed_cache = {}   # realpath -> [soname, ...]
_symbols_cache = {}  # realpath -> set of defined symbol names
_lib_index = {}      # soname -> realpath


def build_lib_index(lib_dir):
    """Walk lib_dir once and index all .so files by soname."""
    for root, _, files in os.walk(lib_dir):
        for f in files:
            if f.endswith('.so') or '.so.' in f:
                full = os.path.realpath(os.path.join(root, f))
                _lib_index.setdefault(f, full)
                base = f.split('.so')[0] + '.so'
                _lib_index.setdefault(base, full)


def get_needed(elf_path):
    """Return list of DT_NEEDED sonames (cached)."""
    if elf_path in _needed_cache:
        return _needed_cache[elf_path]
    try:
        out = subprocess.check_output(
            ['readelf', '-d', elf_path],
            stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        _needed_cache[elf_path] = []
        return []
    needed = []
    for line in out.splitlines():
        m = re.search(r'\(NEEDED\)\s+Shared library:\s+\[(.+?)\]', line)
        if m:
            needed.append(m.group(1))
    _needed_cache[elf_path] = needed
    return needed


def get_defined_symbols(elf_path):
    """Return set of defined symbol names (cached)."""
    if elf_path in _symbols_cache:
        return _symbols_cache[elf_path]
    try:
        out = subprocess.check_output(
            ['nm', '-D', '--defined-only', elf_path],
            stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        _symbols_cache[elf_path] = set()
        return set()
    syms = set()
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            syms.add(parts[-1])
    _symbols_cache[elf_path] = syms
    return syms


def walk_closure(start_lib):
    """BFS walk of transitive DT_NEEDED. Returns set of realpaths."""
    visited = set()
    queue = deque()
    start_real = os.path.realpath(start_lib)
    queue.append(start_real)
    visited.add(start_real)
    while queue:
        current = queue.popleft()
        for soname in get_needed(current):
            dep_path = _lib_index.get(soname)
            if dep_path and dep_path not in visited:
                visited.add(dep_path)
                queue.append(dep_path)
    return visited


def parse_elf(path):
    """Parse both DT_NEEDED and defined symbols for a single ELF (for parallel use)."""
    get_needed(path)
    get_defined_symbols(path)


def main():
    ap = argparse.ArgumentParser(
        description='Trace symbols through DT_NEEDED closures of an exe '
                    'and its dlopen\'d libs.')
    ap.add_argument('--config', '-c', default=DEFAULT_CONFIG,
                    help='Path to JSON config file (default: '
                         'find_symbol_in_closure.json next to this script)')
    cli_args = ap.parse_args()

    cfg_path = cli_args.config
    if not os.path.isfile(cfg_path):
        print(f'ERROR: config not found: {cfg_path}', file=sys.stderr)
        sys.exit(1)

    with open(cfg_path) as f:
        cfg = json.load(f)

    # Support both "symbol" (string) and "symbols" (list) in config
    raw_syms = cfg.get('symbols', cfg.get('symbol', []))
    if isinstance(raw_syms, str):
        symbols = [raw_syms]
    else:
        symbols = list(raw_syms)

    if not symbols:
        print('ERROR: no symbols specified in config', file=sys.stderr)
        sys.exit(1)

    gui_exe = cfg.get('gui_exe', '')
    top_libs = cfg['top_libs']
    lib_dir = os.path.realpath(cfg['lib_dir'])
    workers = cfg.get('workers', 8)

    # Build scan list: GUI exe + dlopen'd libs
    scan_targets = []
    if gui_exe:
        rp = os.path.realpath(gui_exe)
        if os.path.isfile(rp):
            scan_targets.append(rp)
        else:
            print(f'WARNING: gui_exe {gui_exe} not found, skipping', file=sys.stderr)

    for p in top_libs:
        rp = os.path.realpath(p)
        if os.path.isfile(rp):
            scan_targets.append(rp)
        else:
            print(f'WARNING: {p} not found, skipping', file=sys.stderr)

    if not scan_targets:
        print('ERROR: no valid targets to scan', file=sys.stderr)
        sys.exit(1)

    print(f'Symbols:   {len(symbols)}')
    for sym in symbols:
        print(f'  - {sym}')
    print(f'Lib dir:   {lib_dir}')
    print(f'Targets:   {len(scan_targets)} (exe + dlopen\'d libs)')
    print(f'Workers:   {workers}')
    print()

    # Phase 1: index all .so files under lib_dir
    print('Indexing lib dir ...', flush=True)
    build_lib_index(lib_dir)
    print(f'  {len(_lib_index)} sonames indexed')

    # Phase 2: walk closures (sequential — needs cached DT_NEEDED)
    # But first, parallel-parse DT_NEEDED for all indexed libs
    print(f'Parsing DT_NEEDED for all libs ({workers} threads) ...', flush=True)
    all_lib_paths = list(set(_lib_index.values()))
    all_lib_paths.extend(scan_targets)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(get_needed, p): p for p in all_lib_paths}
        for fut in as_completed(futs):
            fut.result()
    print(f'  {len(_needed_cache)} ELFs parsed')

    # Walk closures
    closures = {}  # target_name -> set of realpaths
    all_closure_libs = set()
    for tl in scan_targets:
        tl_name = os.path.basename(tl)
        closure = walk_closure(tl)
        closures[tl_name] = closure
        all_closure_libs.update(closure)
        print(f'  {tl_name}: {len(closure)} libs in closure')

    # Phase 3: parallel symbol scan — only for unique libs across all closures
    print(f'\nScanning symbols in {len(all_closure_libs)} unique libs ({workers} threads) ...',
          flush=True)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(get_defined_symbols, p): p for p in all_closure_libs}
        for fut in as_completed(futs):
            fut.result()

    # Phase 4: single pass — match ALL query symbols against each lib at once.
    # Build lib_path -> set of matched query symbols, then look up per closure.
    print(f'\nMatching {len(symbols)} symbol(s) across {len(all_closure_libs)} libs ...',
          flush=True)
    lib_matches = defaultdict(set)  # lib_path -> {matched query symbols}
    for lib_path in all_closure_libs:
        lib_syms = _symbols_cache.get(lib_path, set())
        for s in lib_syms:
            for query in symbols:
                if query in s:
                    lib_matches[lib_path].add(query)

    # Report per symbol
    for sym_idx, symbol in enumerate(symbols):
        if sym_idx > 0:
            print()
            print('=' * 60)

        print(f'\n--- Symbol: {symbol} ---')

        # provider_path -> set of target names that pull it in
        symbol_providers = defaultdict(set)
        for tl_name, closure in closures.items():
            for lib_path in closure:
                if symbol in lib_matches.get(lib_path, set()):
                    symbol_providers[lib_path].add(tl_name)

        if not symbol_providers:
            print(f'  NOT found in any closure.')
            continue

        print(f'  Found in {len(symbol_providers)} lib(s):')
        print()

        for provider, importers in sorted(symbol_providers.items(),
                                           key=lambda x: -len(x[1])):
            pname = os.path.relpath(provider, lib_dir)
            print(f'  {pname}')
            print(f'    pulled in by: {", ".join(sorted(importers))}')
            print()

        if len(symbol_providers) > 1:
            print('  DUPLICATE: symbol defined in multiple libs in the same load image')
            print('  If GUI dlopens multiple top-level libs whose closures overlap on')
            print('  different providers of this symbol, protobuf will double-register')
            print('  the descriptor and crash.')
            print()
            for provider, importers in sorted(symbol_providers.items(),
                                               key=lambda x: -len(x[1])):
                pname = os.path.relpath(provider, lib_dir)
                print(f'    {pname}  <--  {", ".join(sorted(importers))}')


if __name__ == '__main__':
    main()
