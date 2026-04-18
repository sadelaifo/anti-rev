#!/usr/bin/env python3
"""
missing_syms.py -- Find missing DT_NEEDED edges and circular dependencies.

Scans a project directory for all ELF executables and shared libraries,
then for each one:
  1. Finds undefined symbols not resolved by its transitive DT_NEEDED chain
  2. Locates the provider library on LD_LIBRARY_PATH
  3. Reports: "libA needs to link to libB for symbol xxx"

Also detects circular dependencies in the DT_NEEDED graph among project
libraries.

Prerequisites:
  - LD_LIBRARY_PATH must include all directories containing shared
    libraries that the project binaries might need.
  - ``readelf`` and optionally ``c++filt`` must be on PATH.

Usage:
    export LD_LIBRARY_PATH=/opt/proj/lib:/opt/third_party/lib
    python3 tools/missing_syms.py /opt/proj/

    # Additional search paths:
    python3 tools/missing_syms.py /opt/proj/ -L /opt/extra/lib

    # Demangle C++ symbols:
    python3 tools/missing_syms.py /opt/proj/ --demangle

    # JSON output for scripting:
    python3 tools/missing_syms.py /opt/proj/ --json

    # Only circular dependencies:
    python3 tools/missing_syms.py /opt/proj/ --cycles-only
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed


# -- Constants ---------------------------------------------------------------

ELF_MAGIC = b'\x7fELF'

# Boilerplate symbols present in virtually every ELF -- not meaningful.
IGNORE_SYMS = frozenset({
    '_init', '_fini', '__bss_start', '_edata', '_end',
    '__data_start', 'data_start', '_IO_stdin_used',
    '__dso_handle', '__TMC_END__',
})


# -- ELF helpers -------------------------------------------------------------

def is_elf(path):
    # type: (str) -> bool
    try:
        with open(path, 'rb') as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def classify_elf(path):
    # type: (str) -> str | None
    """Return 'exe', 'lib', or None."""
    try:
        with open(path, 'rb') as f:
            hdr = f.read(20)
            if len(hdr) < 20 or hdr[:4] != ELF_MAGIC:
                return None
            endian = '<' if hdr[5] == 1 else '>'
            e_type = struct.unpack_from(endian + 'H', hdr, 16)[0]
            if e_type == 2:          # ET_EXEC
                return 'exe'
            if e_type == 3:          # ET_DYN -- PIE exe or shared lib
                return 'lib' if '.so' in os.path.basename(path) else 'exe'
    except OSError:
        pass
    return None


def parse_elf(path):
    # type: (str) -> tuple[str, list[str], dict[str, str], set[str]]
    """Parse an ELF in one readelf invocation.

    Returns ``(soname, dt_needed, defined_syms, undefined_syms)`` where
    *defined_syms* is ``{sym_name: bind}`` (bind is ``'GLOBAL'``,
    ``'WEAK'``, or ``'UNIQUE'``).  WEAK undefined symbols are excluded
    (they are optional).  If the same symbol appears under multiple
    versions with different binds, GLOBAL wins over WEAK.
    """
    try:
        out = subprocess.check_output(
            ['readelf', '-d', '--dyn-syms', '-W', path],
            stderr=subprocess.DEVNULL, text=True, timeout=30)
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        return '', [], {}, set()

    soname = ''
    dt_needed = []  # type: list[str]
    defined = {}  # type: dict[str, str]
    undefined = set()  # type: set[str]

    for line in out.splitlines():
        m = re.search(r'\(SONAME\)\s+Library soname: \[(.+)\]', line)
        if m:
            soname = m.group(1)
            continue
        m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
        if m:
            dt_needed.append(m.group(1))
            continue
        # Symbol table line: Num Value Size Type Bind Vis Ndx Name
        # readelf also prints version-definition/need tables that share
        # many column widths; reject anything whose first field is not a
        # "N:" symbol index.
        parts = line.split()
        if len(parts) < 8:
            continue
        if not (parts[0].endswith(':') and parts[0][:-1].isdigit()):
            continue
        ndx, bind, sym_name = parts[6], parts[4], parts[7]
        if not sym_name:
            continue
        if ndx == 'UND':
            if bind != 'WEAK':
                clean = sym_name.split('@')[0]
                if clean and clean not in IGNORE_SYMS:
                    undefined.add(clean)
        else:
            if bind == 'LOCAL':
                continue
            clean = sym_name.split('@@')[0].split('@')[0]
            if not clean:
                continue
            # GLOBAL/UNIQUE wins over WEAK if the same name appears twice
            # (e.g. under two different symbol versions).
            prev = defined.get(clean)
            if prev is None or (prev == 'WEAK' and bind != 'WEAK'):
                defined[clean] = bind

    return soname, dt_needed, defined, undefined


# -- Library resolution ------------------------------------------------------

def build_search_dirs(extra_dirs):
    # type: (list[str]) -> list[str]
    """Merge *extra_dirs* + ``LD_LIBRARY_PATH`` into a search list."""
    dirs = []  # type: list[str]
    seen = set()  # type: set[str]
    for d in extra_dirs:
        d = d.strip()
        if d and os.path.isdir(d):
            rp = os.path.realpath(d)
            if rp not in seen:
                seen.add(rp)
                dirs.append(rp)
    for d in os.environ.get('LD_LIBRARY_PATH', '').split(':'):
        d = d.strip()
        if d and os.path.isdir(d):
            rp = os.path.realpath(d)
            if rp not in seen:
                seen.add(rp)
                dirs.append(rp)
    return dirs


def build_ldconfig_cache():
    # type: () -> dict[str, str]
    cache = {}  # type: dict[str, str]
    try:
        out = subprocess.check_output(
            ['ldconfig', '-p'], stderr=subprocess.DEVNULL, text=True,
            timeout=10)
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        return cache
    for line in out.splitlines():
        m = re.match(r'\s+(\S+)\s+\(.*\)\s+=>\s+(\S+)', line)
        if m:
            # Keep the first entry per soname — ldconfig lists the
            # native architecture (x86-64) before compat (i386), so
            # first-wins picks the right one for the host binaries.
            if m.group(1) not in cache:
                cache[m.group(1)] = m.group(2)
    return cache


class LibResolver:
    """Resolve DT_NEEDED sonames to file paths."""

    def __init__(self, search_dirs, ldcache, local_map):
        # type: (list[str], dict[str, str], dict[str, str]) -> None
        self.search_dirs = search_dirs
        self.ldcache = ldcache
        self.local_map = local_map   # soname/filename -> realpath
        self._cache = {}  # type: dict[str, str | None]

    def resolve(self, name):
        # type: (str) -> str | None
        if name in self._cache:
            return self._cache[name]

        result = None  # type: str | None

        # 1. Local map (parsed ELFs: soname + basename)
        if name in self.local_map:
            result = self.local_map[name]
        else:
            # 2. Filesystem search (LD_LIBRARY_PATH)
            for d in self.search_dirs:
                p = os.path.join(d, name)
                if os.path.isfile(p):
                    result = os.path.realpath(p)
                    break
            else:
                # 3. ldconfig
                if name in self.ldcache:
                    result = self.ldcache[name]

        self._cache[name] = result
        return result


# -- Deduplication -----------------------------------------------------------

def dedup_versioned(elfs, all_parsed):
    # type: (list[str], dict) -> list[str]
    """Collapse versioned copies to one representative per (dir, soname).

    Installations often ship ``libfoo.so``, ``libfoo.so.1``, and
    ``libfoo.so.1.2.3`` as real files (not symlinks).  They share the
    same DT_SONAME and identical symbols, so scanning all of them is
    redundant.  This keeps the shortest filename per group (typically
    the base ``.so``).  Files without a DT_SONAME are kept as-is.
    """
    groups = {}   # type: dict[tuple[str,str], str]
    no_soname = []  # type: list[str]

    for p in elfs:
        parsed = all_parsed.get(p)
        soname = parsed[0] if parsed else ''
        if not soname:
            no_soname.append(p)
            continue
        d = os.path.dirname(p)
        key = (d, soname)
        if key not in groups or \
                len(os.path.basename(p)) < len(os.path.basename(groups[key])):
            groups[key] = p

    return sorted(set(no_soname) | set(groups.values()))


# -- Blacklist ---------------------------------------------------------------

def parse_blacklist(path, proj_dir):
    # type: (str, str) -> list[str]
    """Parse a blacklist file and return a list of absolute directory/file paths.

    The file format is one path per line (relative to *proj_dir*).
    Blank lines and ``#`` comments are ignored.
    """
    entries = []  # type: list[str]
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            resolved = os.path.realpath(os.path.join(proj_dir, line))
            entries.append(resolved)
    return entries


def is_blacklisted(path, blacklist):
    # type: (str, list[str]) -> bool
    """Check if *path* is under (or equal to) any blacklisted entry."""
    for bl in blacklist:
        if path == bl or path.startswith(bl + '/'):
            return True
    return False


# -- Scanning ----------------------------------------------------------------

def scan_proj_dir(proj_dir):
    # type: (str) -> list[str]
    """Recursively find all ELF files in *proj_dir* (skip symlinks)."""
    elfs = []  # type: list[str]
    for root, _dirs, files in os.walk(proj_dir):
        for name in sorted(files):
            p = os.path.join(root, name)
            if os.path.islink(p):
                continue
            if os.path.isfile(p) and is_elf(p):
                elfs.append(os.path.realpath(p))
    return elfs


def scan_search_dirs(search_dirs, exclude_realpaths):
    # type: (list[str], set[str]) -> list[str]
    """Find .so ELF files on LD_LIBRARY_PATH (non-recursive).

    Follows symlinks to real files, deduplicates by realpath.
    Skips files already in *exclude_realpaths* (proj_dir files).
    """
    seen = set(exclude_realpaths)
    libs = []  # type: list[str]
    for d in search_dirs:
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for name in sorted(entries):
            if '.so' not in name:
                continue
            p = os.path.join(d, name)
            if not os.path.isfile(p):       # follows symlinks
                continue
            rp = os.path.realpath(p)
            if rp in seen:
                continue
            if is_elf(rp):
                seen.add(rp)
                libs.append(rp)
    return libs


# -- Analysis: missing symbols -----------------------------------------------

def compute_available_syms(target, all_parsed, resolver, verbose=False):
    # type: (str, dict, LibResolver, bool) -> set[str]
    """Collect all symbols available to *target* via transitive DT_NEEDED.

    Parses system libs on demand and adds them to *all_parsed*.
    """
    parsed = all_parsed.get(target)
    if not parsed:
        return set()

    available = set(parsed[2].keys())    # target's own defined syms
    visited = set()  # type: set[str]    # realpaths already walked
    queue = deque(parsed[1])             # DT_NEEDED names to resolve

    while queue:
        name = queue.popleft()
        resolved = resolver.resolve(name)
        if not resolved:
            if verbose:
                print('  [resolve] UNRESOLVED: %s (needed by %s)' %
                      (name, os.path.basename(target)), file=sys.stderr)
            continue
        if resolved in visited:
            continue
        visited.add(resolved)

        dep_parsed = all_parsed.get(resolved)
        if dep_parsed is None:
            # System lib not in initial parallel parse -- parse now
            dep_parsed = parse_elf(resolved)
            all_parsed[resolved] = dep_parsed
            # Add to resolver's local map so future lookups are fast
            dep_soname = dep_parsed[0]
            dep_basename = os.path.basename(resolved)
            if dep_basename not in resolver.local_map:
                resolver.local_map[dep_basename] = resolved
            if dep_soname and dep_soname not in resolver.local_map:
                resolver.local_map[dep_soname] = resolved

        if verbose and not dep_parsed[2]:
            print('  [resolve] EMPTY parse: %s -> %s (0 defined syms)' %
                  (name, resolved), file=sys.stderr)

        available.update(dep_parsed[2].keys())   # defined syms

        for dep_name in dep_parsed[1]:   # DT_NEEDED
            queue.append(dep_name)

    return available


def find_missing_symbols(proj_elfs, all_parsed, resolver, verbose=False):
    # type: (list[str], dict, LibResolver, bool) -> list[tuple[str, set[str]]]
    """For each proj ELF, find undefined syms not in transitive DT_NEEDED.

    Returns list of ``(target_path, missing_syms_set)``.
    Side-effect: *all_parsed* may be extended with on-demand parsed libs.
    """
    results = []  # type: list[tuple[str, set[str]]]
    for target in proj_elfs:
        parsed = all_parsed.get(target)
        if not parsed:
            continue
        undef = parsed[3]
        if not undef:
            continue
        available = compute_available_syms(
            target, all_parsed, resolver, verbose=verbose)
        missing = undef - available
        if missing:
            results.append((target, missing))
    return results


def build_sym_index(all_parsed):
    # type: (dict) -> dict[str, list[str]]
    """Build symbol -> [provider_realpath, ...] index from all parsed ELFs."""
    idx = defaultdict(list)  # type: defaultdict[str, list[str]]
    for path, (soname, needed, defined, undef) in all_parsed.items():
        for s in defined.keys():
            idx[s].append(path)
    return dict(idx)


def match_providers(missing_results, sym_index, proj_set, all_parsed):
    # type: (list[tuple[str, set[str]]], dict[str, list[str]], set[str], dict) -> list[dict]
    """For each missing symbol, find the best provider library.

    Prefers providers inside the project over external (system) libs.
    Returns structured results for output.
    """
    output = []  # type: list[dict]
    for target, missing in missing_results:
        entries = []  # type: list[dict]
        for sym in sorted(missing):
            providers = [p for p in sym_index.get(sym, []) if p != target]
            provider = None  # type: str | None
            provider_soname = None  # type: str | None

            # Prefer a project-local provider
            proj_providers = [p for p in providers if p in proj_set]
            ext_providers = [p for p in providers if p not in proj_set]
            ordered = proj_providers + ext_providers

            if ordered:
                provider = ordered[0]
                p_parsed = all_parsed.get(provider)
                if p_parsed and p_parsed[0]:
                    provider_soname = p_parsed[0]
                else:
                    provider_soname = os.path.basename(provider)

            entries.append({
                'symbol': sym,
                'provider': provider,
                'provider_soname': provider_soname,
            })

        output.append({
            'consumer': target,
            'consumer_type': classify_elf(target) or 'unknown',
            'missing': entries,
        })
    return output


# -- Analysis: duplicate symbols --------------------------------------------

# C++ vague-linkage prefixes.  These symbols are emitted WEAK in every TU
# that instantiates the type; duplicates across DSOs are expected and
# dedup'd by the resolver, so they are noise by default.
#   _ZTV = vtable, _ZTI = typeinfo, _ZTS = typeinfo-name,
#   _ZTC = construction-vtable, _ZTT = VTT (virtual table table)
CXX_VAGUE_PREFIXES = ('_ZTV', '_ZTI', '_ZTS', '_ZTC', '_ZTT')


def is_cxx_vague(sym):
    # type: (str) -> bool
    return sym.startswith(CXX_VAGUE_PREFIXES)


def find_duplicate_symbols_for_target(target, all_parsed, resolver,
                                      filter_cxx_vague=True,
                                      proj_set=None):
    # type: (str, dict, LibResolver, bool, set[str] | None) -> list[dict]
    """Find symbols defined by more than one DSO in target's load image.

    Walks target's transitive DT_NEEDED closure (including target itself),
    collects every defined symbol with its originating (dso_path, bind),
    and returns entries where multiple DSOs define the same symbol.

    Severity:
      * STRONG x STRONG (any non-WEAK binds) -> 'error'
      * WEAK x WEAK                          -> 'warn'
      * STRONG x WEAK                        -> 'warn'

    If *proj_set* is provided, only duplicates with at least one provider
    inside the project are kept — system-lib-only duplicates (e.g. libc
    vs ld-linux) are filtered out as non-actionable noise.
    """
    parsed = all_parsed.get(target)
    if not parsed:
        return []

    providers = defaultdict(list)  # type: defaultdict[str, list[tuple[str, str]]]

    def _collect(path, defined):
        # type: (str, dict[str, str]) -> None
        for sym, bind in defined.items():
            if sym in IGNORE_SYMS:
                continue
            if filter_cxx_vague and is_cxx_vague(sym):
                continue
            providers[sym].append((path, bind))

    _collect(target, parsed[2])

    # Seed visited with target so a DT_NEEDED cycle back to target doesn't
    # double-count its symbols.
    visited = {target}  # type: set[str]
    queue = deque(parsed[1])

    while queue:
        name = queue.popleft()
        resolved = resolver.resolve(name)
        if not resolved or resolved in visited:
            continue
        visited.add(resolved)

        dep_parsed = all_parsed.get(resolved)
        if dep_parsed is None:
            dep_parsed = parse_elf(resolved)
            all_parsed[resolved] = dep_parsed

        _collect(resolved, dep_parsed[2])

        for dep_name in dep_parsed[1]:
            queue.append(dep_name)

    dups = []  # type: list[dict]
    for sym, provs in providers.items():
        if len(provs) < 2:
            continue
        if proj_set is not None and not any(p in proj_set for p, _ in provs):
            continue
        binds = {b for _, b in provs}
        if 'WEAK' in binds and len(binds) == 1:
            severity = 'warn'          # all weak
        elif 'WEAK' in binds:
            severity = 'warn'          # mixed strong + weak
        else:
            severity = 'error'         # all strong
        dups.append({
            'symbol': sym,
            'providers': provs,
            'severity': severity,
        })

    dups.sort(key=lambda d: (d['severity'] != 'error', d['symbol']))
    return dups


def find_duplicate_symbols(scan_elfs, all_parsed, resolver,
                           filter_cxx_vague=True, proj_set=None):
    # type: (list[str], dict, LibResolver, bool, set[str] | None) -> list[dict]
    """Run duplicate-symbol detection for every scan target.

    Returns list of per-target records (only targets with ≥1 duplicate).
    """
    results = []  # type: list[dict]
    for target in scan_elfs:
        dups = find_duplicate_symbols_for_target(
            target, all_parsed, resolver,
            filter_cxx_vague=filter_cxx_vague, proj_set=proj_set)
        if dups:
            results.append({
                'consumer': target,
                'consumer_type': classify_elf(target) or 'unknown',
                'duplicates': dups,
            })
    return results


# -- Analysis: circular dependencies ----------------------------------------

def build_proj_edges(proj_elfs, all_parsed, resolver):
    # type: (list[str], dict, LibResolver) -> tuple[dict[str, list[str]], dict[str, str]]
    """Build DT_NEEDED edge graph restricted to project libraries.

    Returns ``(edges, path_to_name)`` where edges maps
    ``soname/basename -> [soname/basename, ...]``.
    """
    proj_set = set(proj_elfs)

    # Map realpath -> display name (soname preferred)
    path_to_name = {}  # type: dict[str, str]
    for p in proj_elfs:
        parsed = all_parsed.get(p)
        if parsed and parsed[0]:
            path_to_name[p] = parsed[0]
        else:
            path_to_name[p] = os.path.basename(p)

    edges = defaultdict(list)  # type: defaultdict[str, list[str]]
    for p in proj_elfs:
        parsed = all_parsed.get(p)
        if not parsed:
            continue
        src = path_to_name[p]
        for dep_name in parsed[1]:
            resolved = resolver.resolve(dep_name)
            if resolved and resolved in proj_set:
                dst = path_to_name.get(resolved, dep_name)
                edges[src].append(dst)

    return dict(edges), path_to_name


def find_cycles_tarjan(edges):
    # type: (dict[str, list[str]]) -> list[list[str]]
    """Find all SCCs with size > 1 (= cycles).  Iterative Tarjan's."""
    index_counter = [0]
    stack = []  # type: list[str]
    on_stack = set()  # type: set[str]
    index = {}  # type: dict[str, int]
    lowlink = {}  # type: dict[str, int]
    sccs = []  # type: list[list[str]]

    all_nodes = set(edges.keys())
    for children in edges.values():
        all_nodes.update(children)

    def strongconnect(v):
        # type: (str) -> None
        call_stack = [(v, iter(edges.get(v, [])))]
        index[v] = lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack.add(v)

        while call_stack:
            node, children_iter = call_stack[-1]
            pushed = False
            for w in children_iter:
                if w not in index:
                    index[w] = lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack.add(w)
                    call_stack.append((w, iter(edges.get(w, []))))
                    pushed = True
                    break
                elif w in on_stack:
                    lowlink[node] = min(lowlink[node], index[w])

            if not pushed:
                call_stack.pop()
                if call_stack:
                    parent_node = call_stack[-1][0]
                    lowlink[parent_node] = min(
                        lowlink[parent_node], lowlink[node])

                if lowlink[node] == index[node]:
                    scc = []  # type: list[str]
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        scc.append(w)
                        if w == node:
                            break
                    if len(scc) > 1:
                        sccs.append(scc[::-1])

    for node in all_nodes:
        if node not in index:
            strongconnect(node)

    return sccs


def find_cycle_path(edges, scc):
    # type: (dict[str, list[str]], list[str]) -> list[str]
    """Find one concrete cycle through *scc* for display."""
    scc_set = set(scc)
    start = scc[0]
    visited = set()  # type: set[str]
    queue = deque([(start, [start])])
    while queue:
        node, path = queue.popleft()
        for child in edges.get(node, []):
            if child not in scc_set:
                continue
            if child == start and len(path) > 1:
                return path + [start]
            if child not in visited:
                visited.add(child)
                queue.append((child, path + [child]))
    return scc + [scc[0]]


def find_path_bfs(edges, start, target):
    # type: (dict[str, list[str]], str, str) -> list[str] | None
    """BFS shortest path from *start* to *target*.  Returns the path
    (including both endpoints) or ``None``."""
    if start == target:
        return [start]
    visited = set()  # type: set[str]
    queue = deque([(start, [start])])
    while queue:
        node, path = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        for child in edges.get(node, []):
            new_path = path + [child]
            if child == target:
                return new_path
            if child not in visited:
                queue.append((child, new_path))
    return None


def detect_latent_cycles(results, proj_edges, path_to_name):
    # type: (list[dict], dict[str, list[str]], dict[str, str]) -> list[dict]
    """Detect cases where adding a suggested missing link would create a cycle.

    For each "consumer needs to link to provider" suggestion, checks whether
    *provider* can already reach *consumer* via existing DT_NEEDED edges.
    If so, adding the link consumer -> provider closes a loop.

    Modifies *results* in-place (sets ``entry['latent_cycle']``).
    Returns a deduplicated list of latent cycle records.
    """
    path_cache = {}   # type: dict[tuple[str,str], list[str] | None]
    latent_pairs = {} # type: dict[tuple[str,str], dict]

    for r in results:
        consumer_path = r['consumer']
        consumer_name = path_to_name.get(consumer_path)
        if not consumer_name:
            for entry in r['missing']:
                entry['latent_cycle'] = None
            continue

        for entry in r['missing']:
            entry['latent_cycle'] = None

            provider_path = entry['provider']
            if not provider_path:
                continue
            provider_name = path_to_name.get(provider_path)
            if not provider_name:
                # Provider is external — no latent cycle risk
                continue

            pair = (consumer_name, provider_name)
            if pair not in path_cache:
                # Can provider already reach consumer?
                path_cache[pair] = find_path_bfs(
                    proj_edges, provider_name, consumer_name)

            path = path_cache[pair]
            if path is not None:
                # consumer -> provider -> ... -> consumer
                cycle = [consumer_name] + path
                entry['latent_cycle'] = cycle

                if pair not in latent_pairs:
                    latent_pairs[pair] = {
                        'consumer': consumer_name,
                        'provider': provider_name,
                        'cycle': cycle,
                        'symbols': [],
                    }
                latent_pairs[pair]['symbols'].append(entry['symbol'])

    return list(latent_pairs.values())


# -- Demangling --------------------------------------------------------------

def demangle_batch(syms):
    # type: (list[str]) -> dict[str, str]
    """Batch-demangle C++ symbols with a single c++filt call."""
    mangled = [s for s in syms if s.startswith('_Z')]
    result = {s: s for s in syms}
    if not mangled:
        return result
    try:
        proc = subprocess.run(
            ['c++filt'], input='\n'.join(mangled),
            capture_output=True, text=True, timeout=10)
        for m, d in zip(mangled, proc.stdout.strip().splitlines()):
            if d and d != m:
                result[m] = d
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


# -- Output ------------------------------------------------------------------

def soname_to_lflag(soname):
    # type: (str) -> str
    """``libfoo.so.1`` -> ``foo`` (for ``-lfoo``)."""
    name = soname
    if name.startswith('lib'):
        name = name[3:]
    idx = name.find('.so')
    if idx >= 0:
        name = name[:idx]
    return name


def print_missing_report(results, proj_dir, do_demangle=False):
    # type: (list[dict], str, bool) -> None
    if not results:
        print('\n  No missing symbols found -- '
              'all DT_NEEDED chains are complete.\n')
        return

    demangled = {}  # type: dict[str, str]
    if do_demangle:
        all_syms = []  # type: list[str]
        for r in results:
            all_syms.extend(e['symbol'] for e in r['missing'])
        demangled = demangle_batch(all_syms)

    total_missing = 0
    total_no_provider = 0
    total_latent_links = 0

    for r in results:
        consumer = r['consumer']
        rel = os.path.relpath(consumer, proj_dir)
        ctype = r['consumer_type']
        n = len(r['missing'])
        total_missing += n
        consumer_basename = os.path.basename(consumer)

        # Group missing symbols by provider soname (None = not found)
        by_provider = defaultdict(list)  # provider_soname -> [entry, ...]
        for entry in r['missing']:
            by_provider[entry['provider_soname']].append(entry)

        print('\n  %s  (%s, %d missing symbol%s):' %
              (rel, ctype, n, 's' if n != 1 else ''))

        for provider_soname, entries in by_provider.items():
            if provider_soname is None:
                # Symbols with no provider
                total_no_provider += len(entries)
                for entry in entries:
                    sym = entry['symbol']
                    if do_demangle and demangled.get(sym, sym) != sym:
                        print('    %s  [%s]' % (demangled[sym], sym))
                    else:
                        print('    %s' % sym)
                print('      -> NOT FOUND in any scanned library')
                continue

            # Print provider header with patchelf hint
            print('    from %s  '
                  '(patchelf --add-needed %s %s):' %
                  (provider_soname, provider_soname, consumer_basename))

            # Check if this provider link would create a latent cycle
            latent = entries[0].get('latent_cycle')
            if latent:
                total_latent_links += 1
                print('      !! WARN: creates cycle: %s' %
                      ' -> '.join(latent))

            # List symbols
            for entry in entries:
                sym = entry['symbol']
                if do_demangle and demangled.get(sym, sym) != sym:
                    print('      %s  [%s]' % (demangled[sym], sym))
                else:
                    print('      %s' % sym)

    print()
    print('-' * 60)
    print('  Total: %d missing symbol%s in %d ELF%s' %
          (total_missing, 's' if total_missing != 1 else '',
           len(results), 's' if len(results) != 1 else ''))
    if total_no_provider:
        print('  %d symbol%s not found anywhere -- check LD_LIBRARY_PATH' %
              (total_no_provider, 's' if total_no_provider != 1 else ''))
    if total_latent_links:
        print('  %d link%s would create circular dependencies' %
              (total_latent_links, 's' if total_latent_links != 1 else ''))
    print()


def print_cycle_report(sccs, edges):
    # type: (list[list[str]], dict[str, list[str]]) -> None
    print('=' * 60)
    print('  Circular dependencies')
    print('=' * 60)

    if not sccs:
        print('\n  No circular dependencies found.\n')
        return

    print('\n  %d circular dependency group%s found:\n' %
          (len(sccs), 's' if len(sccs) != 1 else ''))

    for i, scc in enumerate(sccs):
        cycle_path = find_cycle_path(edges, scc)
        chain = ' -> '.join(cycle_path)
        print('  [%d] %s' % (i + 1, chain))
        print('       (%d libraries in cycle)' % len(scc))

    print()


def print_latent_cycle_report(latent_cycles):
    # type: (list[dict]) -> None
    """Print latent circular dependency report."""
    print('=' * 60)
    print('  Latent circular dependencies')
    print('  (adding the suggested link would create a cycle)')
    print('=' * 60)

    if not latent_cycles:
        print('\n  None -- all suggested links are safe.\n')
        return

    print('\n  %d latent cycle%s found:\n' %
          (len(latent_cycles), 's' if len(latent_cycles) != 1 else ''))

    for i, lc in enumerate(latent_cycles):
        chain = ' -> '.join(lc['cycle'])
        n_syms = len(lc['symbols'])
        print('  [%d] %s' % (i + 1, chain))
        print('       %s needs %s for: %s' %
              (lc['consumer'], lc['provider'],
               ', '.join(lc['symbols'][:5])))
        if n_syms > 5:
            print('       ... and %d more symbol(s)' % (n_syms - 5))

    print()


def _bind_label(bind):
    # type: (str) -> str
    return 'WEAK' if bind == 'WEAK' else 'STRONG'


def print_duplicate_report(dup_results, proj_dir, do_demangle=False):
    # type: (list[dict], str, bool) -> None
    print('=' * 60)
    print('  Duplicate symbols in per-target DT_NEEDED closures')
    print('=' * 60)

    if not dup_results:
        print('\n  No duplicate symbols found.\n')
        return

    demangled = {}  # type: dict[str, str]
    if do_demangle:
        all_syms = []  # type: list[str]
        for r in dup_results:
            all_syms.extend(d['symbol'] for d in r['duplicates'])
        demangled = demangle_batch(all_syms)

    total_err = 0
    total_warn = 0

    for r in dup_results:
        consumer = r['consumer']
        rel = os.path.relpath(consumer, proj_dir)
        ctype = r['consumer_type']
        errors = [d for d in r['duplicates'] if d['severity'] == 'error']
        warns = [d for d in r['duplicates'] if d['severity'] == 'warn']
        total_err += len(errors)
        total_warn += len(warns)

        print('\n  %s  (%s, %d error%s, %d warning%s):' %
              (rel, ctype,
               len(errors), 's' if len(errors) != 1 else '',
               len(warns), 's' if len(warns) != 1 else ''))

        def _fmt_dup(d):
            # type: (dict) -> None
            sym = d['symbol']
            display = sym
            if do_demangle and demangled.get(sym, sym) != sym:
                display = '%s  [%s]' % (demangled[sym], sym)
            provs = ', '.join(
                '%s:%s' % (os.path.basename(p), _bind_label(b))
                for p, b in d['providers'])
            print('      %s' % display)
            print('        in: %s' % provs)

        if errors:
            print('    ERRORS (STRONG x STRONG):')
            for d in errors:
                _fmt_dup(d)
        if warns:
            print('    WARNINGS (WEAK or mixed):')
            for d in warns:
                _fmt_dup(d)

    print()
    print('-' * 60)
    print('  Total: %d duplicate-symbol error%s, %d warning%s '
          'in %d consumer%s' %
          (total_err, 's' if total_err != 1 else '',
           total_warn, 's' if total_warn != 1 else '',
           len(dup_results), 's' if len(dup_results) != 1 else ''))
    print()


def print_patchelf_commands(results, proj_edges, path_to_name):
    # type: (list[dict], dict[str, list[str]], dict[str, str]) -> None
    """Print safe patchelf commands and warn about unsafe ones.

    Builds a combined graph (existing edges + ALL suggested edges at once)
    and runs Tarjan's SCC to find which suggested edges participate in
    cycles.  This catches transitive cycles where no single edge alone
    creates a cycle but the combination does.
    """
    # Collect unique patchelf commands, mapping to graph edge names
    cmds = []   # type: list[tuple[str, str, str | None, str | None]]
    seen = set()  # type: set[tuple[str, str]]

    for r in results:
        consumer_path = r['consumer']
        consumer_name = path_to_name.get(consumer_path)
        for entry in r['missing']:
            provider_soname = entry['provider_soname']
            if not provider_soname:
                continue
            cmd_key = (provider_soname, consumer_path)
            if cmd_key in seen:
                continue
            seen.add(cmd_key)

            provider_path = entry['provider']
            provider_name = path_to_name.get(provider_path) \
                if provider_path else None

            cmds.append((provider_soname, consumer_path,
                         consumer_name, provider_name))

    # Build combined graph: existing DT_NEEDED + all suggested edges
    combined = defaultdict(list)  # type: defaultdict[str, list[str]]
    for src, dsts in proj_edges.items():
        combined[src] = list(dsts)

    suggested_edges = set()  # type: set[tuple[str, str]]
    for _, _, cname, pname in cmds:
        if cname and pname:
            edge = (cname, pname)
            if edge not in suggested_edges:
                suggested_edges.add(edge)
                combined[cname].append(pname)

    # Find SCCs in the combined graph
    sccs = find_cycles_tarjan(dict(combined))

    # Any suggested edge with both endpoints in the same SCC is unsafe
    unsafe_edges = set()  # type: set[tuple[str, str]]
    edge_to_cycle = {}    # type: dict[tuple[str, str], list[str]]
    for scc in sccs:
        scc_set = set(scc)
        cycle_path = find_cycle_path(dict(combined), scc)
        for edge in suggested_edges:
            if edge[0] in scc_set and edge[1] in scc_set:
                unsafe_edges.add(edge)
                edge_to_cycle[edge] = cycle_path

    # Classify commands
    safe = []     # type: list[tuple[str, str]]
    unsafe = []   # type: list[tuple[str, str, list[str]]]

    for provider_soname, consumer_path, cname, pname in cmds:
        edge = (cname, pname) if cname and pname else None
        if edge and edge in unsafe_edges:
            unsafe.append((provider_soname, consumer_path,
                           edge_to_cycle[edge]))
        else:
            safe.append((provider_soname, consumer_path))

    # Print
    print('=' * 60)
    print('  Patchelf commands')
    print('=' * 60)

    if safe:
        print('\n  # Safe — run these:\n')
        for provider_soname, consumer_path in safe:
            print('  patchelf --add-needed %s %s' %
                  (provider_soname, consumer_path))

    if unsafe:
        print('\n  # WARNING — these would create circular dependencies:\n')
        for provider_soname, consumer_path, cycle in unsafe:
            print('  # patchelf --add-needed %s %s' %
                  (provider_soname, consumer_path))
            print('  #   cycle: %s' % ' -> '.join(cycle))

    if not safe and not unsafe:
        print('\n  No patchelf commands needed.\n')
    else:
        print()


def print_json_output(results, sccs, edges, proj_dir, latent_cycles=None,
                      dup_results=None):
    # type: (list[dict], list[list[str]], dict[str, list[str]], str, list[dict] | None, list[dict] | None) -> None
    cycles = []  # type: list[dict]
    for scc in sccs:
        cycle_path = find_cycle_path(edges, scc)
        cycles.append({
            'members': scc,
            'example_cycle': cycle_path,
        })

    missing_out = []  # type: list[dict]
    for r in results:
        entry = {
            'consumer': os.path.relpath(r['consumer'], proj_dir),
            'consumer_type': r['consumer_type'],
            'missing': [],
        }  # type: dict
        for m in r['missing']:
            e = {'symbol': m['symbol']}  # type: dict
            if m['provider']:
                e['provider'] = os.path.relpath(m['provider'], proj_dir)
                e['provider_soname'] = m['provider_soname']
            else:
                e['provider'] = None
                e['provider_soname'] = None
            lc = m.get('latent_cycle')
            e['latent_cycle'] = lc if lc else None
            entry['missing'].append(e)
        missing_out.append(entry)

    latent_out = []  # type: list[dict]
    for lc in (latent_cycles or []):
        latent_out.append({
            'consumer': lc['consumer'],
            'provider': lc['provider'],
            'cycle': lc['cycle'],
            'symbols': lc['symbols'],
        })

    dup_out = []  # type: list[dict]
    for r in (dup_results or []):
        entry = {
            'consumer': os.path.relpath(r['consumer'], proj_dir),
            'consumer_type': r['consumer_type'],
            'duplicates': [],
        }  # type: dict
        for d in r['duplicates']:
            entry['duplicates'].append({
                'symbol': d['symbol'],
                'severity': d['severity'],
                'providers': [
                    {
                        'path': os.path.relpath(p, proj_dir)
                                if p.startswith(proj_dir) else p,
                        'bind': b,
                    }
                    for p, b in d['providers']
                ],
            })
        dup_out.append(entry)

    output = {
        'proj_dir': proj_dir,
        'missing_symbols': missing_out,
        'circular_dependencies': cycles,
        'latent_circular_dependencies': latent_out,
        'duplicate_symbols': dup_out,
    }
    print(json.dumps(output, indent=2))


# -- Main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='Find missing DT_NEEDED edges and circular dependencies '
                    'in a project directory.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument('proj_dir',
                    help='Directory containing ELF binaries to scan')
    ap.add_argument('-L', '--lib-dir', action='append', default=[],
                    help='Additional library search directory (repeatable)')
    ap.add_argument('--json', action='store_true',
                    help='Output JSON for scripting')
    ap.add_argument('--cycles-only', action='store_true',
                    help='Only report circular dependencies')
    ap.add_argument('--demangle', action='store_true',
                    help='Demangle C++ symbols via c++filt')
    ap.add_argument('--all-cxx', action='store_true',
                    help='Include C++ vague-linkage symbols (vtables, '
                         'typeinfo) in the duplicate-symbol report.  These '
                         'are filtered by default as they are benign '
                         'ODR-dedup noise.')
    ap.add_argument('--no-duplicates', action='store_true',
                    help='Skip duplicate-symbol detection (runs by default).')
    ap.add_argument('--system-dups', action='store_true',
                    help='Include duplicates whose providers are all system '
                         'libs (e.g. libc vs ld-linux).  By default only '
                         'duplicates touching at least one project ELF are '
                         'reported.')
    ap.add_argument('--blacklist', metavar='FILE',
                    help='File listing paths (relative to proj_dir) whose '
                         'ELFs are indexed as symbol providers but not '
                         'scanned for missing symbols or cycles.  '
                         'One path per line, # comments.')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Show progress details')
    args = ap.parse_args()

    proj_dir = os.path.realpath(args.proj_dir)
    if not os.path.isdir(proj_dir):
        sys.exit('[error] not a directory: %s' % args.proj_dir)

    is_json = args.json

    def log(msg):
        # type: (str) -> None
        dest = sys.stderr if is_json else sys.stdout
        print(msg, file=dest)

    # -- Build search dirs ---------------------------------------------------
    search_dirs = build_search_dirs(args.lib_dir)
    if not search_dirs:
        log('[warning] LD_LIBRARY_PATH is empty and no -L dirs given')

    ldcache = build_ldconfig_cache()

    # -- Blacklist (if any) ---------------------------------------------------
    blacklist = []  # type: list[str]
    if args.blacklist:
        if not os.path.isfile(args.blacklist):
            sys.exit('[error] blacklist file not found: %s' % args.blacklist)
        blacklist = parse_blacklist(args.blacklist, proj_dir)
        log('[blacklist] %d path(s) loaded from %s' %
            (len(blacklist), args.blacklist))

    # -- Discover ELFs -------------------------------------------------------
    log('[scan] Scanning %s ...' % proj_dir)
    all_proj_elfs = scan_proj_dir(proj_dir)
    if not all_proj_elfs:
        sys.exit('[error] no ELF files found in %s' % proj_dir)

    log('[scan] Found %d ELF file(s) in project' % len(all_proj_elfs))

    # Scan LD_LIBRARY_PATH for external libs (symbol provider search)
    all_proj_set = set(all_proj_elfs)
    ext_libs = scan_search_dirs(search_dirs, all_proj_set)
    log('[scan] External: %d lib(s) on LD_LIBRARY_PATH' % len(ext_libs))

    all_elfs = all_proj_elfs + ext_libs

    # -- Parallel parse ------------------------------------------------------
    log('[parse] Parsing %d ELF files ...' % len(all_elfs))
    all_parsed = {}  # type: dict[str, tuple]

    n_workers = min(os.cpu_count() or 4, len(all_elfs), 64)
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(parse_elf, p): p for p in all_elfs}
        done = 0
        for fut in as_completed(futures):
            p = futures[fut]
            all_parsed[p] = fut.result()
            done += 1
            if args.verbose and done % 200 == 0:
                log('[parse] ... %d / %d' % (done, len(all_elfs)))

    log('[parse] Done.')

    # -- Build resolution map (uses ALL files for soname lookup) -------------
    local_map = {}  # type: dict[str, str]
    for p in all_elfs:
        parsed = all_parsed[p]
        basename = os.path.basename(p)
        if basename not in local_map:
            local_map[basename] = p
        soname = parsed[0]
        if soname and soname not in local_map:
            local_map[soname] = p

    resolver = LibResolver(search_dirs, ldcache, local_map)

    # -- Deduplicate versioned copies ----------------------------------------
    proj_elfs = dedup_versioned(all_proj_elfs, all_parsed)
    n_deduped = len(all_proj_elfs) - len(proj_elfs)
    if n_deduped:
        log('[dedup] %d -> %d unique ELFs '
            '(%d versioned copies collapsed)' %
            (len(all_proj_elfs), len(proj_elfs), n_deduped))

    # -- Blacklist: split into scan vs provider-only -------------------------
    if blacklist:
        scan_elfs = [p for p in proj_elfs
                     if not is_blacklisted(p, blacklist)]
        n_bl = len(proj_elfs) - len(scan_elfs)
        log('[blacklist] %d ELF(s) blacklisted (providers only)' % n_bl)
    else:
        scan_elfs = proj_elfs

    n_exe = sum(1 for p in scan_elfs if classify_elf(p) == 'exe')
    n_lib = len(scan_elfs) - n_exe
    log('[scan] Scanning: %d executable(s), %d shared lib(s)' %
        (n_exe, n_lib))

    # proj_set includes ALL project files (even deduped-out and blacklisted)
    # so provider-preference in match_providers works correctly.
    proj_set = set(all_proj_elfs)

    # -- Cycle detection (always computed) -----------------------------------
    log('[cycles] Building DT_NEEDED graph ...')
    proj_edges, path_to_name = build_proj_edges(
        scan_elfs, all_parsed, resolver)
    sccs = find_cycles_tarjan(proj_edges)

    if args.cycles_only:
        if is_json:
            print_json_output([], sccs, proj_edges, proj_dir)
        else:
            print_cycle_report(sccs, proj_edges)
        sys.exit(1 if sccs else 0)

    # -- Missing symbol analysis ---------------------------------------------
    log('[analyze] Checking symbol resolution ...')
    missing_results = find_missing_symbols(
        scan_elfs, all_parsed, resolver, verbose=args.verbose)

    # Build sym index AFTER analysis (includes on-demand parsed system libs)
    sym_index = build_sym_index(all_parsed)

    # Match providers
    results = match_providers(
        missing_results, sym_index, proj_set, all_parsed)

    # -- Latent cycle detection ----------------------------------------------
    latent_cycles = detect_latent_cycles(results, proj_edges, path_to_name)

    # -- Duplicate-symbol detection ------------------------------------------
    dup_results = []  # type: list[dict]
    if not args.no_duplicates:
        log('[analyze] Scanning for duplicate symbols ...')
        dup_proj_set = None if args.system_dups else proj_set
        dup_results = find_duplicate_symbols(
            scan_elfs, all_parsed, resolver,
            filter_cxx_vague=not args.all_cxx,
            proj_set=dup_proj_set)

    dup_errors = sum(
        1 for r in dup_results for d in r['duplicates']
        if d['severity'] == 'error')

    # -- Output --------------------------------------------------------------
    if is_json:
        print_json_output(results, sccs, proj_edges, proj_dir,
                          latent_cycles, dup_results)
    else:
        print()
        print('=' * 60)
        print('  Missing symbol report: %s' % proj_dir)
        print('  %d executables, %d shared libraries scanned' %
              (n_exe, n_lib))
        print('=' * 60)
        print_missing_report(results, proj_dir, do_demangle=args.demangle)
        print_cycle_report(sccs, proj_edges)
        print_latent_cycle_report(latent_cycles)
        if not args.no_duplicates:
            print_duplicate_report(
                dup_results, proj_dir, do_demangle=args.demangle)
        print_patchelf_commands(results, proj_edges, path_to_name)

    has_issues = bool(results) or bool(sccs) or dup_errors > 0
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
