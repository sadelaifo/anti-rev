#!/usr/bin/env python3
"""
depgraph.py — Visualize ELF dependency graph in topological order.

Usage:
    python3 depgraph.py <elf_file> [options]

Examples:
    python3 depgraph.py /usr/bin/ls
    python3 depgraph.py ./my_app -o deps.png
    python3 depgraph.py ./my_app -L /opt/mylibs/lib --highlight libfoo.so,libbar.so
    python3 depgraph.py ./my_app --topo-only   # text only, no image
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path


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
                    max_depth: int = 50
                    ) -> tuple[dict[str, list[str]], dict[str, str]]:
    """
    BFS from root, resolving DT_NEEDED recursively.

    Returns:
        edges: {parent_name: [child_name, ...]}
        paths: {name: resolved_path}  (None if unresolved)
    """
    edges = defaultdict(list)
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

    return dict(edges), paths


# ── Topological sort ─────────────────────────────────────────────────

def topo_sort(edges: dict[str, list[str]], root: str) -> list[str]:
    """Kahn's algorithm. Returns libs in dependency-first order."""
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


# ── Main ─────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Visualize ELF dependency graph in topological order.")
    p.add_argument("elf", help="ELF binary to analyze")
    p.add_argument("-o", "--output", default=None,
                   help="Output image file (default: <name>_deps.png)")
    p.add_argument("-L", "--lib-dir", action="append", default=[],
                   help="Additional library search directory (repeatable)")
    p.add_argument("--highlight", default="",
                   help="Comma-separated lib names to highlight")
    p.add_argument("--topo-only", action="store_true",
                   help="Print topological order only (no image)")
    p.add_argument("--max-depth", type=int, default=50,
                   help="Max recursion depth (default: 50)")
    args = p.parse_args()

    elf_path = args.elf
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
    edges, paths = build_dep_graph(elf_path, search_dirs, ldcache,
                                   max_depth=args.max_depth)

    root = os.path.basename(elf_path)
    topo_order = topo_sort(edges, root)

    # Always print tree + topo
    print()
    print_tree(edges, paths, root, highlight)
    print_topo(topo_order, paths, highlight)

    if args.topo_only:
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
