#!/usr/bin/env python3
"""
depgraph.py — Visualize ELF dependency graph in topological order.

Usage:
    python3 depgraph.py <elf_or_dir> [options]

Examples:
    python3 depgraph.py /usr/bin/ls
    python3 depgraph.py ./my_app -o deps.png
    python3 depgraph.py ./my_app -L /opt/mylibs/lib --highlight libfoo.so,libbar.so
    python3 depgraph.py ./my_app --topo-only   # text only, no image
    python3 depgraph.py ./my_app --cycles       # detect cyclic dependencies
    python3 depgraph.py ./my_app --scan-dlopen  # include hidden dlopen deps
    python3 depgraph.py ./my_app --borrowed     # find symbols that break under dlopen
    python3 depgraph.py /opt/myapp/ --no-undefined   # scan dir for missing deps
    python3 depgraph.py ./libfoo.so --no-undefined   # scan single lib
    python3 depgraph.py /opt/myapp/ --find-unresolved                # find locally-defined but unreachable symbols
    python3 depgraph.py /opt/myapp/ --find-unresolved --blacklist vendor  # skip vendor/ subdirectory
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ELF_MAGIC = b'\x7fELF'

# Directory basenames to exclude from --find-unresolved scanning.
# Add third-party / vendored library directories here.
BLACKLISTED_DIRS: set[str] = set((
    # "third_party",
    # "vendor",
    # "external",
))


# ── ELF parsing via readelf ──────────────────────────────────────────

def get_dt_needed(path: str) -> list[str]:
    """Get DT_NEEDED library names from an ELF file."""
    try:
        out = subprocess.check_output(
            ["readelf", "-d", path], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    needed = []
    for line in out.splitlines():
        m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
        if m:
            needed.append(m.group(1))
    return needed


def get_dt_soname(path: str) -> str:
    """Get DT_SONAME from a shared library."""
    try:
        out = subprocess.check_output(
            ["readelf", "-d", path], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    for line in out.splitlines():
        m = re.search(r'\(SONAME\)\s+Library soname: \[(.+)\]', line)
        if m:
            return m.group(1)
    return ""


# ── Symbol extraction ───────────────────────────────────────────────

def get_undefined_syms(path: str) -> set[str]:
    """Get undefined (UND) dynamic symbols from an ELF.

    These are symbols the library needs but doesn't define itself.
    """
    try:
        out = subprocess.check_output(
            ["readelf", "--dyn-syms", "-W", path],
            stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()
    syms = set()
    for line in out.splitlines():
        # Format: Num Value Size Type Bind Vis Ndx Name
        # UND symbols have Ndx == "UND"
        parts = line.split()
        if len(parts) >= 8 and parts[6] == "UND" and parts[7] != "":
            name = parts[7]
            # Skip weak undefined (they're optional)
            if parts[4] == "WEAK":
                continue
            syms.add(name)
    return syms


def get_defined_syms(path: str) -> set[str]:
    """Get defined (exported) dynamic symbols from an ELF.

    These are symbols the library provides to others.
    """
    try:
        out = subprocess.check_output(
            ["readelf", "--dyn-syms", "-W", path],
            stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()
    syms = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[6] != "UND" and parts[7] != "":
            # Skip LOCAL binding
            if parts[4] == "LOCAL":
                continue
            name = parts[7]
            # Strip version suffix (e.g. "printf@@GLIBC_2.2.5" -> "printf")
            if "@@" in name:
                name = name.split("@@")[0]
            elif "@" in name:
                name = name.split("@")[0]
            syms.add(name)
    return syms


# ── Combined ELF parser (single readelf call per file) ──────────────

def parse_elf_all(path: str) -> tuple[str, list[str], set[str], set[str]]:
    """Parse soname, DT_NEEDED, defined syms, and undefined syms in one shot.

    Runs a single ``readelf -d --dyn-syms -W`` invocation, which is ~3x
    faster than three separate calls.

    Returns (soname, dt_needed, defined_syms, undefined_syms).
    """
    try:
        out = subprocess.check_output(
            ["readelf", "-d", "--dyn-syms", "-W", path],
            stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "", [], set(), set()

    soname = ""
    dt_needed: list[str] = []
    defined: set[str] = set()
    undefined: set[str] = set()

    for line in out.splitlines():
        # Dynamic section entries
        m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
        if m:
            dt_needed.append(m.group(1))
            continue
        m = re.search(r'\(SONAME\)\s+Library soname: \[(.+)\]', line)
        if m:
            soname = m.group(1)
            continue
        # Symbol table entries
        # Format: Num Value Size Type Bind Vis Ndx Name
        parts = line.split()
        if len(parts) >= 8:
            ndx, bind, name = parts[6], parts[4], parts[7]
            if not name:
                continue
            if ndx == "UND":
                if bind != "WEAK":
                    undefined.add(name)
            else:
                if bind != "LOCAL":
                    clean = name
                    if "@@" in clean:
                        clean = clean.split("@@")[0]
                    elif "@" in clean:
                        clean = clean.split("@")[0]
                    defined.add(clean)

    return soname, dt_needed, defined, undefined


# ── ELF discovery ───────────────────────────────────────────────────

def is_elf(path: str) -> bool:
    """Check if a file starts with the ELF magic."""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def scan_elfs(directory: str) -> list[str]:
    """Recursively find all ELF files in a directory."""
    elfs = []
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            p = os.path.join(root, name)
            if os.path.islink(p):
                continue
            if os.path.isfile(p) and is_elf(p):
                elfs.append(os.path.realpath(p))
    return elfs


def scan_elfs_filtered(directory: str,
                       blacklist: set[str] | None = None) -> list[str]:
    """Recursively find all ELF files, skipping blacklisted directories."""
    bl = (blacklist or set()) | BLACKLISTED_DIRS
    elfs = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in bl]
        for name in sorted(files):
            p = os.path.join(root, name)
            if os.path.islink(p):
                continue
            if os.path.isfile(p) and is_elf(p):
                elfs.append(os.path.realpath(p))
    return elfs


def _demangle_batch(syms: list[str]) -> dict[str, str]:
    """Batch-demangle C++ symbols via a single c++filt invocation."""
    mangled = [s for s in syms if s.startswith("_Z")]
    result = {s: s for s in syms}
    if not mangled:
        return result
    try:
        proc = subprocess.run(
            ["c++filt"], input="\n".join(mangled),
            capture_output=True, text=True, timeout=10)
        for m, d in zip(mangled, proc.stdout.strip().splitlines()):
            if d and d != m:
                result[m] = d
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


# ── Library resolution ───────────────────────────────────────────────

def build_ldconfig_cache() -> dict[str, str]:
    """Parse ldconfig -p to map library names to paths."""
    cache = {}
    try:
        out = subprocess.check_output(
            ["ldconfig", "-p"], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return cache
    for line in out.splitlines():
        m = re.match(r'\s+(\S+)\s+\(.*\)\s+=>\s+(\S+)', line)
        if m:
            cache[m.group(1)] = m.group(2)
    return cache


def resolve_lib(name: str, search_dirs: list[str],
                ldcache: dict[str, str]) -> str :
    """Resolve a library name to a file path."""
    # Direct path
    if '/' in name and os.path.isfile(name):
        return os.path.realpath(name)

    # Search dirs (LD_LIBRARY_PATH, RPATH, etc.)
    for d in search_dirs:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return os.path.realpath(p)

    # ldconfig cache
    if name in ldcache:
        return ldcache[name]

    return None


# ── Recursive dependency graph builder ───────────────────────────────

def build_dep_graph(root: str, search_dirs: list[str],
                    ldcache: dict[str, str],
                    max_depth: int = 50,
                    scan_dlopen: bool = False
                    ) -> tuple[dict[str, list[str]], dict[str, str],
                               dict[str, list[str]]]:
    """
    BFS from root, resolving DT_NEEDED recursively.

    Returns:
        edges:        {parent_name: [child_name, ...]}  (DT_NEEDED only)
        paths:        {name: resolved_path}  (None if unresolved)
        dlopen_edges: {parent_name: [child_name, ...]}  (dlopen targets)
    """
    edges = defaultdict(list)
    dlopen_edges = defaultdict(list)
    paths = {}

    root_path = os.path.realpath(root)
    root_name = os.path.basename(root)
    paths[root_name] = root_path

    queue = deque([(root_name, root_path, 0)])
    visited = {root_name}

    while queue:
        parent_name, parent_path, depth = queue.popleft()
        if depth >= max_depth:
            continue

        needed = get_dt_needed(parent_path)
        for lib_name in needed:
            edges[parent_name].append(lib_name)

            if lib_name in visited:
                continue
            visited.add(lib_name)

            lib_path = resolve_lib(lib_name, search_dirs, ldcache)
            paths[lib_name] = lib_path

            if lib_path:
                queue.append((lib_name, lib_path, depth + 1))

        # Scan for dlopen targets in the binary's string tables
        if scan_dlopen:
            targets = scan_dlopen_targets(parent_path)
            for lib_name in targets:
                dlopen_edges[parent_name].append(lib_name)

                if lib_name in visited:
                    continue
                visited.add(lib_name)

                lib_path = resolve_lib(lib_name, search_dirs, ldcache)
                paths[lib_name] = lib_path

                if lib_path:
                    queue.append((lib_name, lib_path, depth + 1))

    return dict(edges), paths, dict(dlopen_edges)


# ── dlopen string scanner ───────────────────────────────────────────

def scan_dlopen_targets(path: str) -> list[str]:
    """Extract probable dlopen targets from an ELF's string tables.

    Scans .rodata and .dynstr for strings matching *.so* patterns.
    These are heuristic — the string may exist but never be dlopen'd.
    """
    try:
        out = subprocess.check_output(
            ["strings", path], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    targets = []
    for line in out.splitlines():
        line = line.strip()
        # Match: libfoo.so, libfoo.so.1, ./libfoo.so, /path/to/libfoo.so
        if not re.match(r'^[./\w-]*\.so(\.\d+)*$', line):
            continue
        # Skip the file's own soname
        basename = os.path.basename(line)
        if basename == os.path.basename(path):
            continue
        # Skip libc/ld/libdl (noise)
        if basename.startswith(('ld-linux', 'linux-vdso')):
            continue
        targets.append(basename)
    return list(dict.fromkeys(targets))  # dedupe preserving order


# ── Cycle detection (Tarjan's SCC) ─────────────────────────────────

def find_cycles(edges: dict[str, list[str]]) -> list[list[str]]:
    """Find all strongly connected components with size > 1 (= cycles).

    Uses iterative Tarjan's algorithm to avoid stack overflow on deep
    dependency trees.
    """
    index_counter = [0]
    stack = []
    on_stack = set()
    index = {}
    lowlink = {}
    sccs = []

    all_nodes = set(edges.keys())
    for children in edges.values():
        all_nodes.update(children)

    def strongconnect(v):
        # Iterative Tarjan using an explicit call stack.
        # Each frame: (node, iterator_over_children, is_root_call)
        call_stack = [(v, iter(edges.get(v, [])), True)]
        index[v] = lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack.add(v)

        while call_stack:
            node, children_iter, _ = call_stack[-1]
            pushed = False
            for w in children_iter:
                if w not in index:
                    # Recurse
                    index[w] = lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack.add(w)
                    call_stack.append((w, iter(edges.get(w, [])), True))
                    pushed = True
                    break
                elif w in on_stack:
                    lowlink[node] = min(lowlink[node], index[w])

            if not pushed:
                # All children processed — pop this frame
                call_stack.pop()
                if call_stack:
                    parent = call_stack[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[node])

                if lowlink[node] == index[node]:
                    scc = []
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


def find_cycle_paths(edges: dict[str, list[str]],
                     sccs: list[list[str]]) -> list[list[str]]:
    """For each SCC, find one concrete cycle path for display."""
    paths = []
    for scc in sccs:
        scc_set = set(scc)
        # BFS/DFS from first node to find a cycle back to itself
        start = scc[0]
        visited = {}
        queue = deque([(start, [start])])
        found = False
        while queue and not found:
            node, path = queue.popleft()
            for child in edges.get(node, []):
                if child not in scc_set:
                    continue
                if child == start and len(path) > 1:
                    paths.append(path + [start])
                    found = True
                    break
                if child not in visited:
                    visited[child] = True
                    queue.append((child, path + [child]))
        if not found:
            # Fallback: just show the SCC members
            paths.append(scc + [scc[0]])
    return paths


# ── Topological sort ─────────────────────────────────────────────────

def _find_cycle(edges: dict[str, list[str]], nodes: set[str]) -> list[str]:
    """DFS to find one cycle among *nodes*.  Returns the cycle as a list, or None."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in nodes}
    parent = {}

    def dfs(u):
        color[u] = GRAY
        for v in edges.get(u, []):
            if v not in color:
                continue
            if color[v] == GRAY:
                # back-edge → extract cycle
                cycle = [v, u]
                p = u
                while p != v:
                    p = parent.get(p)
                    if p is None:
                        break
                    cycle.append(p)
                cycle.reverse()
                return cycle
            if color[v] == WHITE:
                parent[v] = u
                cyc = dfs(v)
                if cyc:
                    return cyc
        color[u] = BLACK
        return None

    for n in nodes:
        if color[n] == WHITE:
            cyc = dfs(n)
            if cyc:
                return cyc
    return None


def topo_sort(edges: dict[str, list[str]], root: str) -> list[str]:
    """Kahn's algorithm. Returns libs in dependency-first order.
    Raises ValueError if the graph contains a cycle."""
    all_nodes = set(edges.keys())
    for children in edges.values():
        all_nodes.update(children)

    in_degree = defaultdict(int)
    for parent, children in edges.items():
        for c in children:
            in_degree[c] += 1

    queue = deque()
    for n in all_nodes:
        if in_degree[n] == 0:
            queue.append(n)

    result = []
    while queue:
        node = queue.popleft()
        result.append(node)
        for child in edges.get(node, []):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    if len(result) < len(all_nodes):
        cycle_nodes = all_nodes - set(result)
        cycle = _find_cycle(edges, cycle_nodes)
        cycle_str = " → ".join(cycle + [cycle[0]]) if cycle else ", ".join(sorted(cycle_nodes))
        raise ValueError(f"dependency cycle detected: {cycle_str}")

    # Reverse: dependencies first (leaf libs first)
    result.reverse()
    return result


# ── Depth assignment for layered layout ──────────────────────────────

def assign_depths(edges: dict[str, list[str]], root: str) -> dict[str, int]:
    """BFS depth from root."""
    depths = {root: 0}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        for child in edges.get(node, []):
            if child not in depths:
                depths[child] = depths[node] + 1
                queue.append(child)
    return depths


# ── Visualization ────────────────────────────────────────────────────

def plot_graph(edges: dict[str, list[str]], paths: dict[str, str],
               root: str, highlight: set[str], output: str,
               topo_order: list[str]):
    """Render dependency graph using matplotlib + networkx."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import networkx as nx

    G = nx.DiGraph()
    for parent, children in edges.items():
        for child in children:
            G.add_edge(parent, child)

    # Add isolated root if no edges
    if root not in G:
        G.add_node(root)

    # Layout: hierarchical (top-down)
    depths = assign_depths(edges, root)
    # For nodes not reachable from root, assign max_depth + 1
    max_d = max(depths.values()) if depths else 0
    for n in G.nodes():
        if n not in depths:
            depths[n] = max_d + 1

    # Group nodes by depth
    layers = defaultdict(list)
    for n, d in depths.items():
        if n in G.nodes():
            layers[d].append(n)

    # Sort each layer for consistent ordering
    for d in layers:
        layers[d].sort()

    # Compute positions: x = spread within layer, y = -depth (top-down)
    pos = {}
    for d, nodes in layers.items():
        width = len(nodes)
        for i, n in enumerate(nodes):
            x = (i - (width - 1) / 2) * 2.5
            y = -d * 2.0
            pos[n] = (x, y)

    # Node colors
    node_colors = []
    for n in G.nodes():
        if n == root:
            node_colors.append("#4A90D9")      # blue: root
        elif n in highlight:
            node_colors.append("#E8A838")      # orange: highlighted
        elif paths.get(n) is None:
            node_colors.append("#D94A4A")      # red: unresolved
        else:
            node_colors.append("#6BBF6B")      # green: resolved

    # Figure size scales with graph
    n_nodes = len(G.nodes())
    fig_w = max(12, max(len(v) for v in layers.values()) * 3) if layers else 12
    fig_h = max(8, (max_d + 1) * 2.2)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))

    # Draw
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#888888",
                           arrows=True, arrowsize=15, width=1.2,
                           connectionstyle="arc3,rad=0.05",
                           node_size=2000, min_source_margin=15,
                           min_target_margin=15)

    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors,
                           node_size=2000, edgecolors="#333333",
                           linewidths=1.5)

    # Labels: shorten long names
    labels = {}
    for n in G.nodes():
        label = n
        # Add topo index
        if n in topo_order:
            idx = topo_order.index(n)
            label = f"[{idx}] {n}"
        labels[n] = label

    nx.draw_networkx_labels(G, pos, labels, ax=ax, font_size=7,
                            font_weight="bold")

    # Legend
    legend = [
        mpatches.Patch(color="#4A90D9", label="Root binary"),
        mpatches.Patch(color="#6BBF6B", label="Resolved lib"),
        mpatches.Patch(color="#D94A4A", label="Unresolved"),
    ]
    if highlight:
        legend.append(mpatches.Patch(color="#E8A838", label="Highlighted"))
    ax.legend(handles=legend, loc="upper left", fontsize=9,
              framealpha=0.9)

    ax.set_title(f"Dependency graph: {root}\n({n_nodes} nodes, "
                 f"arrows = DT_NEEDED)", fontsize=12, fontweight="bold")
    ax.margins(0.15)
    ax.axis("off")

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight",
                facecolor="white", edgecolor="none")
    plt.close()
    return output


# ── Text output ──────────────────────────────────────────────────────

def print_tree(edges: dict[str, list[str]], paths: dict[str, str],
               root: str, highlight: set[str]):
    """Print a tree view to stdout."""
    printed = set()

    def _walk(node, prefix="", is_last=True):
        connector = "\\-- " if is_last else "|-- "
        resolved = paths.get(node)
        marker = ""
        if node in highlight:
            marker = " [*]"
        elif resolved is None:
            marker = " [NOT FOUND]"

        if prefix:
            print(f"{prefix}{connector}{node}{marker}")
        else:
            print(f"{node}{marker}")

        children = edges.get(node, [])
        if node in printed:
            if children:
                new_prefix = prefix + ("    " if is_last else "|   ")
                print(f"{new_prefix}(... already shown ...)")
            return
        printed.add(node)

        for i, child in enumerate(children):
            new_prefix = prefix + ("    " if is_last else "|   ")
            _walk(child, new_prefix, i == len(children) - 1)

    _walk(root)


def print_topo(topo_order: list[str], paths: dict[str, str],
               highlight: set[str]):
    """Print topological order (dependencies first = correct LD_PRELOAD order)."""
    print("\n--- Topological order (dependencies first / LD_PRELOAD order) ---")
    for i, name in enumerate(topo_order):
        resolved = paths.get(name)
        flags = []
        if name in highlight:
            flags.append("HIGHLIGHT")
        if resolved is None:
            flags.append("NOT FOUND")
        suffix = f"  ({', '.join(flags)})" if flags else ""
        print(f"  [{i:3d}] {name}{suffix}")
    print(f"\nTotal: {len(topo_order)} libraries")


def print_cycles(edges: dict[str, list[str]], paths: dict[str, str],
                 dlopen_edges: dict[str, list[str]] | None = None):
    """Detect and print cyclic dependencies.

    Checks cycles in:
    1. DT_NEEDED graph alone
    2. Combined DT_NEEDED + dlopen graph (if dlopen_edges provided)
    """
    print("\n--- Cycle detection ---")

    # Check DT_NEEDED graph
    sccs = find_cycles(edges)
    if sccs:
        print(f"\n  CYCLES in DT_NEEDED graph: {len(sccs)}")
        cycle_paths = find_cycle_paths(edges, sccs)
        for i, path in enumerate(cycle_paths):
            chain = " -> ".join(path)
            print(f"  [{i+1}] {chain}")
    else:
        print("\n  No cycles in DT_NEEDED graph.")

    # Check combined graph (DT_NEEDED + dlopen)
    if dlopen_edges:
        combined = defaultdict(list)
        for parent, children in edges.items():
            combined[parent].extend(children)
        for parent, children in dlopen_edges.items():
            combined[parent].extend(children)
        # dedupe
        combined = {k: list(dict.fromkeys(v)) for k, v in combined.items()}

        sccs_combined = find_cycles(combined)
        if sccs_combined:
            print(f"\n  CYCLES in combined (DT_NEEDED + dlopen) graph: "
                  f"{len(sccs_combined)}")
            cycle_paths = find_cycle_paths(combined, sccs_combined)
            for i, path in enumerate(cycle_paths):
                parts = []
                for j in range(len(path) - 1):
                    a, b = path[j], path[j+1]
                    is_dlopen = (b in dlopen_edges.get(a, [])
                                 and b not in edges.get(a, []))
                    arrow = " =dlopen=> " if is_dlopen else " -> "
                    parts.append(a + arrow)
                parts.append(path[-1])
                print(f"  [{i+1}] {''.join(parts)}")
        else:
            print("\n  No cycles in combined graph either.")

    if not sccs and not (dlopen_edges and sccs_combined):
        print("\n  All clear — no cyclic dependencies found.")


# ── Borrowed symbol detection ───────────────────────────────────────

def get_transitive_deps(node: str, edges: dict[str, list[str]]) -> set[str]:
    """Get all transitive DT_NEEDED dependencies of a node."""
    visited = set()
    queue = deque(edges.get(node, []))
    while queue:
        n = queue.popleft()
        if n in visited:
            continue
        visited.add(n)
        queue.extend(edges.get(n, []))
    return visited


def find_borrowed_syms(edges: dict[str, list[str]],
                       paths: dict[str, str]
                       ) -> list[tuple[str, str, str, str]]:
    """Find symbols that resolve by accident via the global scope.

    For each library, checks if it has undefined symbols that are NOT
    provided by any of its transitive DT_NEEDED deps — meaning they
    only resolve because some unrelated library happens to be loaded.

    Returns list of (consumer, symbol, provider, provider_path) tuples.
    These are the symbols that WILL break under dlopen/encrypted mode.
    """
    # Build symbol tables for all resolved libraries
    defined_by: dict[str, set[str]] = {}   # lib_name -> defined syms
    undefined_in: dict[str, set[str]] = {} # lib_name -> undefined syms

    for name, path in paths.items():
        if path is None:
            continue
        defined_by[name] = get_defined_syms(path)
        undefined_in[name] = get_undefined_syms(path)

    # For each lib, check if its undefined syms are satisfied by its
    # transitive DT_NEEDED chain
    borrowed = []
    for consumer in undefined_in:
        trans_deps = get_transitive_deps(consumer, edges)
        undef = undefined_in[consumer]

        # Collect symbols provided by transitive deps
        available = set()
        for dep in trans_deps:
            available |= defined_by.get(dep, set())
        # Also include the consumer's own defined symbols
        available |= defined_by.get(consumer, set())

        # Find unsatisfied symbols
        missing = undef - available

        # Now check: are these provided by ANY other loaded library?
        all_providers = set(defined_by.keys())
        for sym in sorted(missing):
            for provider in all_providers:
                if provider == consumer:
                    continue
                if provider in trans_deps:
                    continue
                if sym in defined_by[provider]:
                    borrowed.append((
                        consumer, sym, provider,
                        paths.get(provider, "?")))
                    break  # one provider is enough to report

    return borrowed


def _demangle(sym: str) -> str:
    """Demangle a C++ symbol. Returns original if not mangled."""
    if not sym.startswith("_Z"):
        return sym
    try:
        out = subprocess.check_output(
            ["c++filt", sym], stderr=subprocess.DEVNULL, text=True).strip()
        return out if out != sym else sym
    except (subprocess.CalledProcessError, FileNotFoundError):
        return sym


def print_borrowed(borrowed: list[tuple[str, str, str, str]],
                   edges: dict[str, list[str]]):
    """Print borrowed symbol analysis."""
    print("\n--- Borrowed symbol detection ---")
    print("  (symbols that resolve via global scope but break under dlopen)")

    if not borrowed:
        print("\n  All clear — no borrowed symbols found.")
        return

    # Group by consumer
    by_consumer: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for consumer, sym, provider, ppath in borrowed:
        by_consumer[consumer].append((sym, provider, ppath))

    # Filter out system lib noise: only show if consumer or provider
    # is a non-system library
    SYSTEM_PREFIXES = ('libc.so', 'libdl.so', 'libpthread.so', 'libm.so',
                       'librt.so', 'ld-linux', 'libgcc_s.so',
                       'libstdc++.so')

    total = 0
    for consumer, entries in sorted(by_consumer.items()):
        # Skip if consumer is a system lib borrowing from system libs
        if consumer.startswith(SYSTEM_PREFIXES):
            if all(p.startswith(SYSTEM_PREFIXES) for _, p, _ in entries):
                continue

        print(f"\n  {consumer}:")
        for sym, provider, ppath in entries:
            demangled = _demangle(sym)
            label = f"{sym}  ({demangled})" if demangled != sym else sym
            print(f"    {label}")
            print(f"      defined in: {provider}")
            # Show the missing link
            print(f"      FIX: {consumer} should DT_NEED {provider} "
                  f"(or link with -l{_soname_to_lflag(provider)})")
        total += len(entries)

    if total:
        print(f"\n  Total: {total} borrowed symbol(s)")
        print(f"  These WILL fail when loaded via dlopen/memfd "
              f"(encrypted mode).")
    else:
        print("\n  All clear — no borrowed symbols (ignoring system libs).")


def _soname_to_lflag(soname: str) -> str:
    """Convert soname to -l flag: libfoo.so.1 -> foo"""
    name = soname
    # Strip .so and version suffix
    if name.startswith("lib"):
        name = name[3:]
    idx = name.find(".so")
    if idx >= 0:
        name = name[:idx]
    return name


# ── --no-undefined scan ─────────────────────────────────────────────

def _resolve_transitive(path: str, visited: set[str],
                        search_dirs: list[str],
                        local_map: dict[str, str],
                        ldcache: dict[str, str]):
    """Recursively resolve all transitive DT_NEEDED deps of an ELF.

    Populates `visited` with the realpath of every transitive dep.
    Uses local_map (soname/filename → realpath within the project dir)
    first, falls back to search_dirs and ldcache for system libs.
    """
    for name in get_dt_needed(path):
        resolved = local_map.get(name)
        if not resolved:
            resolved = resolve_lib(name, search_dirs, ldcache)
        if not resolved:
            continue
        resolved = os.path.realpath(resolved)
        if resolved in visited:
            continue
        visited.add(resolved)
        _resolve_transitive(resolved, visited, search_dirs,
                            local_map, ldcache)


def run_no_undefined(targets: list[str],
                     top_dir: str,
                     search_dirs: list[str],
                     ldcache: dict[str, str]
                     ) -> tuple[list, int]:
    """Scan ELFs for undefined symbols not covered by DT_NEEDED.

    For each target, finds undefined symbols whose provider lives in
    top_dir but is NOT in the target's transitive DT_NEEDED chain.
    These are "borrowed" symbols that work by accident in normal mode
    but break under dlopen/encrypted mode.

    Args:
        targets:     ELF file paths to check
        top_dir:     root directory for the provider symbol index
        search_dirs: dirs for DT_NEEDED resolution
        ldcache:     ldconfig cache

    Returns:
        (results, n_dir_elfs) where results is a list of
        (target_path, [(sym, [provider_path, ...]), ...])
    """
    top_dir = os.path.realpath(top_dir)

    # Discover all ELFs in top_dir — these form the provider index
    all_dir_elfs = scan_elfs(top_dir)

    # ── Parallel parse: one readelf call per ELF, all in parallel ───
    print(f"[no-undefined] Indexing {len(all_dir_elfs)} ELF files "
          f"in {top_dir} ...")

    # Cache: realpath → (soname, dt_needed, defined, undefined)
    _elf_cache: dict[str, tuple[str, list[str], set[str], set[str]]] = {}

    n_workers = min(os.cpu_count() or 4, len(all_dir_elfs), 64)
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(parse_elf_all, p): p for p in all_dir_elfs}
        for fut in as_completed(futures):
            p = futures[fut]
            _elf_cache[p] = fut.result()

    # soname/filename → realpath for local DT_NEEDED resolution
    local_map: dict[str, str] = {}
    for p in all_dir_elfs:
        local_map[os.path.basename(p)] = p
        soname = _elf_cache[p][0]
        if soname:
            local_map[soname] = p

    # Build provider index: sym → [realpath, ...] within top_dir
    sym_providers: dict[str, list[str]] = defaultdict(list)
    for p in all_dir_elfs:
        for s in _elf_cache[p][2]:  # defined syms
            sym_providers[s].append(p)

    def cached_defined(p: str) -> set[str]:
        if p in _elf_cache:
            return _elf_cache[p][2]
        # Fallback for system libs outside top_dir (parse + cache)
        _elf_cache[p] = parse_elf_all(p)
        return _elf_cache[p][2]

    def cached_needed(p: str) -> list[str]:
        if p in _elf_cache:
            return _elf_cache[p][1]
        _elf_cache[p] = parse_elf_all(p)
        return _elf_cache[p][1]

    def cached_undefined(p: str) -> set[str]:
        if p in _elf_cache:
            return _elf_cache[p][3]
        _elf_cache[p] = parse_elf_all(p)
        return _elf_cache[p][3]

    def resolve_transitive_cached(path: str, visited: set[str]):
        """Walk DT_NEEDED chain using cached data (no subprocess calls)."""
        for name in cached_needed(path):
            resolved = local_map.get(name)
            if not resolved:
                resolved = resolve_lib(name, search_dirs, ldcache)
            if not resolved:
                continue
            resolved = os.path.realpath(resolved)
            if resolved in visited:
                continue
            visited.add(resolved)
            resolve_transitive_cached(resolved, visited)

    # Check each target
    results = []

    for target in targets:
        target = os.path.realpath(target)
        undef = cached_undefined(target)
        if not undef:
            continue

        # Resolve full transitive DT_NEEDED chain
        trans_paths: set[str] = set()
        resolve_transitive_cached(target, trans_paths)

        # Symbols available through the DT_NEEDED chain
        available = cached_defined(target).copy()
        for dep_path in trans_paths:
            available |= cached_defined(dep_path)

        # Missing: undefined but not provided by the DT_NEEDED chain
        missing = undef - available

        # For each missing sym, find providers within top_dir
        problems = []
        for sym in sorted(missing):
            providers = [p for p in sym_providers.get(sym, [])
                         if p != target]
            if providers:
                problems.append((sym, providers))

        if problems:
            results.append((target, problems))

    return results, len(all_dir_elfs)


def print_no_undefined(results: list, top_dir: str,
                       n_targets: int, n_dir_elfs: int):
    """Print --no-undefined scan results."""
    top_dir = os.path.realpath(top_dir)

    print(f"\n{'='*60}")
    print(f"  --no-undefined: {top_dir}")
    print(f"  {n_dir_elfs} ELF files in directory, "
          f"{n_targets} scanned")
    print(f"{'='*60}")

    if not results:
        print(f"\n  ALL PASS — no borrowed symbols found.\n")
        return 0

    # Collect all symbols for batch demangling
    all_syms = []
    for _, problems in results:
        all_syms.extend(sym for sym, _ in problems)
    demangled = _demangle_batch(all_syms)

    total_syms = 0
    for target, problems in results:
        rel = os.path.relpath(target, top_dir)
        n = len(problems)
        total_syms += n
        print(f"\n  FAIL  {rel}  ({n} symbol{'s' if n != 1 else ''})")

        for sym, providers in problems:
            dm = demangled.get(sym, sym)
            label = f"{dm}  [{sym}]" if dm != sym else sym
            print(f"        {label}")
            for prov in providers:
                prov_rel = os.path.relpath(prov, top_dir)
                print(f"          <- {prov_rel}")

    print(f"\n{'─'*60}")
    print(f"  {len(results)}/{n_targets} FAIL  "
          f"({total_syms} borrowed symbol{'s' if total_syms != 1 else ''} "
          f"total)")
    print(f"  These resolve via global scope but WILL BREAK under "
          f"dlopen/encrypted mode.")
    print(f"  Fix: add missing DT_NEEDED or link with the provider "
          f"(-l<lib>).")
    print(f"  Quick fix: patchelf --add-needed <provider.so> <consumer.so>")
    print()
    return len(results)


# ── --find-unresolved scan ─────────────────────────────────────────

def _parse_dynamic(path: str) -> tuple[list[str], str]:
    """Parse DT_NEEDED and DT_SONAME from a single readelf -d call."""
    try:
        out = subprocess.check_output(
            ["readelf", "-d", path], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [], ""
    needed = []
    soname = ""
    for line in out.splitlines():
        m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
        if m:
            needed.append(m.group(1))
            continue
        m = re.search(r'\(SONAME\)\s+Library soname: \[(.+)\]', line)
        if m:
            soname = m.group(1)
    return needed, soname


def _parse_dynsyms(path: str) -> tuple[set[str], set[str]]:
    """Parse defined and undefined dynamic symbols from one readelf call."""
    try:
        out = subprocess.check_output(
            ["readelf", "--dyn-syms", "-W", path],
            stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set(), set()
    defined = set()
    undefined = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[7] == "":
            continue
        name = parts[7]
        if parts[6] == "UND":
            if parts[4] != "WEAK":
                undefined.add(name)
        else:
            if parts[4] != "LOCAL":
                if "@@" in name:
                    name = name.split("@@")[0]
                elif "@" in name:
                    name = name.split("@")[0]
                defined.add(name)
    return defined, undefined


def find_unresolved_syms(directory: str,
                         search_dirs: list[str],
                         ldcache: dict[str, str],
                         blacklist: set[str] | None = None
                         ) -> tuple[list, int]:
    """Find ELFs whose undefined symbols exist locally but are unreachable.

    Scans all ELFs in *directory* (skipping blacklisted sub-dirs).
    For each ELF, finds undefined symbols NOT satisfied by its transitive
    DT_NEEDED chain, then checks whether a *different* ELF in the
    directory defines the symbol.  Those are symbols that will fail at
    load time under dlopen / encrypted mode even though the provider is
    right next to the consumer.

    Optimised: each local ELF is parsed with only 2 readelf invocations
    (instead of 4), and all invocations run in parallel via threads.

    Returns:
        (results, n_elfs) where results is a list of
        (elf_path, [(sym, [provider_path, ...]), ...])
    """
    from concurrent.futures import ThreadPoolExecutor

    directory = os.path.realpath(directory)
    all_elfs = scan_elfs_filtered(directory, blacklist)

    if not all_elfs:
        return [], 0

    print(f"[find-unresolved] Indexing {len(all_elfs)} ELF files "
          f"in {directory} ...")

    # ── Phase 1: parse every local ELF in parallel ─────────────────
    # Two readelf calls per ELF (dynamic + dynsyms) instead of four
    # separate calls (soname, needed, defined, undefined).

    def _parse_elf(path):
        needed, soname = _parse_dynamic(path)
        defined, undefined = _parse_dynsyms(path)
        return path, needed, soname, defined, undefined

    with ThreadPoolExecutor() as pool:
        parsed = list(pool.map(_parse_elf, all_elfs))

    # ── Phase 2: populate caches from parsed results ───────────────
    needed_cache: dict[str, list[str]] = {}
    def_cache: dict[str, set[str]] = {}
    undef_cache: dict[str, set[str]] = {}
    local_map: dict[str, str] = {}

    for path, needed, soname, defined, undefined in parsed:
        needed_cache[path] = needed
        def_cache[path] = defined
        undef_cache[path] = undefined
        local_map[os.path.basename(path)] = path
        if soname:
            local_map[soname] = path

    # On-demand cache accessors for non-local (system) libs
    def cached_needed(p: str) -> list[str]:
        if p not in needed_cache:
            needed_cache[p] = get_dt_needed(p)
        return needed_cache[p]

    def cached_defined(p: str) -> set[str]:
        if p not in def_cache:
            def_cache[p] = get_defined_syms(p)
        return def_cache[p]

    # Provider index: sym → [local realpath, ...]
    sym_providers: dict[str, list[str]] = defaultdict(list)
    for path in all_elfs:
        for s in def_cache[path]:
            sym_providers[s].append(path)

    # ── Phase 3: resolve transitive deps and check symbols ─────────

    def resolve_transitive(target: str) -> set[str]:
        """Walk DT_NEEDED tree using cached data (no extra subprocesses
        for already-parsed ELFs)."""
        visited: set[str] = set()
        queue: deque[str] = deque()
        for name in cached_needed(target):
            resolved = local_map.get(name)
            if not resolved:
                resolved = resolve_lib(name, search_dirs, ldcache)
            if resolved:
                queue.append(os.path.realpath(resolved))
        while queue:
            p = queue.popleft()
            if p in visited:
                continue
            visited.add(p)
            for name in cached_needed(p):
                r = local_map.get(name)
                if not r:
                    r = resolve_lib(name, search_dirs, ldcache)
                if r:
                    r = os.path.realpath(r)
                    if r not in visited:
                        queue.append(r)
        return visited

    results = []
    for target in all_elfs:
        undef = undef_cache[target]
        if not undef:
            continue

        trans_paths = resolve_transitive(target)

        # Symbols available through the DT_NEEDED chain
        available = cached_defined(target).copy()
        for dep_path in trans_paths:
            available |= cached_defined(dep_path)

        # Missing: undefined but not provided by DT_NEEDED chain
        missing = undef - available

        # For each missing sym, find providers within directory
        problems = []
        for sym in sorted(missing):
            providers = [p for p in sym_providers.get(sym, [])
                         if p != target]
            if providers:
                problems.append((sym, providers))

        if problems:
            results.append((target, problems))

    return results, len(all_elfs)


def print_unresolved(results: list, directory: str, n_elfs: int):
    """Print --find-unresolved scan results."""
    directory = os.path.realpath(directory)

    print(f"\n{'='*60}")
    print(f"  --find-unresolved: {directory}")
    print(f"  {n_elfs} ELF files scanned")
    print(f"{'='*60}")

    if not results:
        print(f"\n  ALL PASS — no unresolved symbols found.\n")
        return 0

    # Collect all symbols for batch demangling
    all_syms = []
    for _, problems in results:
        all_syms.extend(sym for sym, _ in problems)
    demangled = _demangle_batch(all_syms)

    total_syms = 0
    for target, problems in results:
        rel = os.path.relpath(target, directory)
        n = len(problems)
        total_syms += n
        print(f"\n  FAIL  {rel}  ({n} symbol{'s' if n != 1 else ''})")

        for sym, providers in problems:
            dm = demangled.get(sym, sym)
            label = f"{dm}  [{sym}]" if dm != sym else sym
            print(f"        {label}")
            for prov in providers:
                prov_rel = os.path.relpath(prov, directory)
                prov_soname = get_dt_soname(prov) or os.path.basename(prov)
                print(f"          <- {prov_rel}  "
                      f"(link with -l{_soname_to_lflag(prov_soname)})")

    print(f"\n{'─'*60}")
    print(f"  {len(results)}/{n_elfs} FAIL  "
          f"({total_syms} unresolved symbol{'s' if total_syms != 1 else ''} "
          f"total)")
    print(f"  These symbols exist in the folder but are NOT reachable")
    print(f"  via DT_NEEDED — they will fail under dlopen/encrypted mode.")
    print(f"  Fix: patchelf --add-needed <provider.so> <consumer>")
    print()
    return len(results)


# ── Main ─────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Visualize ELF dependency graph in topological order.")
    p.add_argument("elf", help="ELF binary or directory to analyze")
    p.add_argument("-o", "--output", default=None,
                   help="Output image file (default: <name>_deps.png)")
    p.add_argument("-L", "--lib-dir", action="append", default=[],
                   help="Additional library search directory (repeatable)")
    p.add_argument("--highlight", default="",
                   help="Comma-separated lib names to highlight")
    p.add_argument("--topo-only", action="store_true",
                   help="Print topological order only (no image)")
    p.add_argument("--cycles", action="store_true",
                   help="Detect and report cyclic dependencies")
    p.add_argument("--scan-dlopen", action="store_true",
                   help="Scan strings for dlopen targets (heuristic)")
    p.add_argument("--borrowed", action="store_true",
                   help="Find symbols that resolve via global scope but "
                        "break under dlopen/encrypted mode")
    p.add_argument("--no-undefined", action="store_true",
                   help="Scan file or directory for ELFs with undefined "
                        "symbols not covered by DT_NEEDED (borrowed from "
                        "siblings in the same directory)")
    p.add_argument("--find-unresolved", action="store_true",
                   help="Scan directory for ELFs with undefined symbols "
                        "that exist locally but are unreachable via "
                        "DT_NEEDED (will fail under dlopen/encrypted mode)")
    p.add_argument("--blacklist", action="append", default=[],
                   help="Directory names to exclude from "
                        "--find-unresolved scanning (repeatable, "
                        "added to built-in BLACKLISTED_DIRS)")
    p.add_argument("--max-depth", type=int, default=50,
                   help="Max recursion depth (default: 50)")
    args = p.parse_args()

    elf_path = args.elf

    # ── --no-undefined mode: standalone scan ────────────────────────
    if args.no_undefined:
        is_dir = os.path.isdir(elf_path)
        if not is_dir and not os.path.isfile(elf_path):
            sys.exit(f"[error] not found: {elf_path}")

        # Determine top_dir and targets
        if is_dir:
            top_dir = os.path.realpath(elf_path)
            targets = scan_elfs(top_dir)
            if not targets:
                sys.exit(f"[error] no ELF files found in {top_dir}")
        else:
            top_dir = os.path.dirname(os.path.realpath(elf_path))
            targets = [os.path.realpath(elf_path)]

        # Search dirs for DT_NEEDED resolution
        search_dirs = list(args.lib_dir)
        if "LD_LIBRARY_PATH" in os.environ:
            search_dirs.extend(os.environ["LD_LIBRARY_PATH"].split(":"))
        search_dirs.append(top_dir)

        ldcache = build_ldconfig_cache()
        results, n_dir_elfs = run_no_undefined(
            targets, top_dir, search_dirs, ldcache)
        n_fail = print_no_undefined(
            results, top_dir, len(targets), n_dir_elfs)
        sys.exit(1 if n_fail else 0)

    # ── --find-unresolved mode ─────────────────────────────────────
    if args.find_unresolved:
        if not os.path.isdir(elf_path):
            sys.exit(f"[error] --find-unresolved requires a directory: "
                     f"{elf_path}")

        search_dirs = list(args.lib_dir)
        if "LD_LIBRARY_PATH" in os.environ:
            search_dirs.extend(os.environ["LD_LIBRARY_PATH"].split(":"))
        search_dirs.append(os.path.realpath(elf_path))

        blacklist = set(args.blacklist) if args.blacklist else None
        ldcache = build_ldconfig_cache()
        results, n_elfs = find_unresolved_syms(
            elf_path, search_dirs, ldcache, blacklist)
        n_fail = print_unresolved(results, elf_path, n_elfs)
        sys.exit(1 if n_fail else 0)

    # ── Normal dep-graph mode ───────────────────────────────────────
    if not os.path.isfile(elf_path):
        sys.exit(f"[error] file not found: {elf_path}")

    # Build search dirs: explicit + LD_LIBRARY_PATH + binary's dir
    search_dirs = list(args.lib_dir)
    if "LD_LIBRARY_PATH" in os.environ:
        search_dirs.extend(os.environ["LD_LIBRARY_PATH"].split(":"))
    search_dirs.append(os.path.dirname(os.path.realpath(elf_path)))

    highlight = set(h.strip() for h in args.highlight.split(",") if h.strip())

    print(f"[depgraph] Analyzing: {elf_path}")
    print(f"[depgraph] Search dirs: {search_dirs}")

    ldcache = build_ldconfig_cache()
    edges, paths, dlopen_edges = build_dep_graph(
        elf_path, search_dirs, ldcache,
        max_depth=args.max_depth,
        scan_dlopen=args.scan_dlopen)

    root = os.path.basename(elf_path)
    topo_order = topo_sort(edges, root)

    # Print dlopen discoveries
    if args.scan_dlopen and dlopen_edges:
        print("\n--- dlopen targets (heuristic, from strings) ---")
        for parent, targets in dlopen_edges.items():
            for t in targets:
                resolved = paths.get(t)
                status = "resolved" if resolved else "NOT FOUND"
                print(f"  {parent} =dlopen=> {t}  ({status})")

    # Always print tree + topo
    print()
    print_tree(edges, paths, root, highlight)
    print_topo(topo_order, paths, highlight)

    # Cycle detection
    if args.cycles:
        print_cycles(edges, paths,
                     dlopen_edges if args.scan_dlopen else None)

    # Borrowed symbol detection
    if args.borrowed:
        borrowed = find_borrowed_syms(edges, paths)
        print_borrowed(borrowed, edges)

    # Check for silently dropped nodes (in cycles)
    all_nodes = set(edges.keys())
    for children in edges.values():
        all_nodes.update(children)
    dropped = all_nodes - set(topo_order)
    if dropped:
        print(f"\n[warning] {len(dropped)} node(s) dropped from topo sort "
              f"(in cycles): {', '.join(sorted(dropped))}")
        if not args.cycles:
            print("[hint] Run with --cycles to see cycle details")

    if args.topo_only or args.cycles or args.borrowed:
        return

    # Plot
    try:
        import matplotlib
        import networkx
    except ImportError:
        print("\n[depgraph] Install matplotlib + networkx for visualization:")
        print("  pip install matplotlib networkx")
        return

    output = args.output or f"{Path(elf_path).stem}_deps.png"
    plot_graph(edges, paths, root, highlight, output, topo_order)
    print(f"\n[depgraph] Graph saved to: {output}")


if __name__ == "__main__":
    main()
