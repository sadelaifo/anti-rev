#!/usr/bin/env python3
"""
antirev-pack — config-driven batch protector

Usage:
    antirev-pack.py --config <config.yaml>

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

    libs: encrypt                      # optional: encrypt|skip (default: encrypt)

    lrxd: lrxd                          # optional: daemon binary base name (default: lrxd)
    version: "1.1.0"                    # optional: package version (recorded in manifest)
    patchelf: /usr/bin/patchelf         # optional: path to patchelf (default: found on PATH)

    encrypt_libs:                      # optional whitelist: only encrypt these libs
      - libsecret.so                   #   all other libs/.elf are copied as plaintext
      - lib/crypto/                    #   supports same patterns as blacklist
      - pg_*.elf                       #   .elf PG binaries use the same filters

    plaintext_libs:                    # optional blacklist: don't encrypt these libs/.elf
      - libcrypto.so*                  #   all other libs/.elf are encrypted
      - lib/3rd/                       #   (mutually exclusive with encrypt_libs)
      - pg_debug.elf                   #   e.g. keep a specific PG binary plaintext

    copy:                              # optional: non-ELF files to copy as-is
      - etc/                           # copy entire config directory
      - bin/start.sh                   # copy a specific file
      - *.conf                         # copy by pattern

Path fields (install_dir, output_dir, key, stub, stubs.*, lrxd, patchelf)
expand ~ and $VAR / ${VAR} from the environment, e.g. install_dir: $HOME/myapp.

CLI overrides: --install-dir, --output-dir, --key, --stub, --lrxd, --version,
--patchelf each take priority over the same field in config.yaml
(CLI > config > default).
A CLI-supplied --key/--stub path is resolved relative to the current working
directory; the config equivalents stay relative to the config file.

What it does:
  - Recursively scans install_dir for all ELF files (executables and libraries)
  - Classifies each as executable (ET_EXEC/ET_DYN without .so/.elf) or lib-category
    asset (.so libraries and .elf PG binaries both go through the lib pipeline)
  - Skips blacklisted ELF files entirely (not copied, not encrypted)
  - Only copies non-ELF files that match the 'copy' list (if omitted, nothing copied)
  - Protects executables with the stub
  - libs=encrypt: encrypts libs individually, served via daemon at runtime
  - libs=skip: ignores libs entirely
  - Uses parallel workers for encryption, protection, and file copies
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import sys
import time
from collections import deque
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

sys.path.insert(0, str(Path(__file__).parent))
from protect import (load_or_create_key, encrypt_data, MAGIC,
                     BFLAG_HAS_MAIN, BFLAG_DAEMON_LIBS)

def _resolve_field(cli_val, cfg, key, default=None):
    """Merge a single config field with CLI override precedence.

    User CLI input wins over config.yaml, which wins over the default.
    ``cli_val`` is the argparse value (``None`` when the flag was not
    given); ``cfg`` is the parsed YAML dict.
    """
    if cli_val is not None:
        return cli_val
    return cfg.get(key, default)


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
      - 'lib'  — filename contains '.so' (shared library) OR ends with
                 '.elf' (ANTI_LoadProcess PG binary / firmware blob).  These
                 go into the daemon asset pool.
      - 'exe'  — any other ET_EXEC / ET_DYN ELF.  Gets wrapped by the
                 protect-exe flow into a standalone stub binary.
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

            # .elf suffix = ANTI_LoadProcess-style PG binary / firmware blob.
            # These are data-like assets served by the daemon, NEVER
            # wrapped as standalone protected executables even when
            # ET_EXEC, so treat the suffix as a lib-category marker.
            # The encrypt_libs / plaintext_libs filters then apply to
            # .elf just like they apply to .so.
            is_so  = '.so'  in path.name
            is_elf = path.name.endswith('.elf')
            if is_elf:
                kind = 'lib'
            elif e_type == ET_EXEC:
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
        elif kind == 'dir_any':
            # Match directory name anywhere in path using fnmatch.
            # "*helf/" matches exact "helf", "*helf*/" matches "shelf", "myhelf" etc.
            dir_pattern = pattern.rstrip('/')
            for part in rel_normalized.split('/')[:-1]:  # check each dir component
                if fnmatch.fnmatch(part, dir_pattern):
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
    """Pre-classify blacklist entries once instead of per-file.

    Entry types:
      'dir'      — "bin/"        matches paths starting with bin/
      'dir_any'  — "*helf/"      matches paths containing /helf/ anywhere
      'path'     — "L3/bin/3rd"  matches exact path or children
      'name'     — "libfoo.so*"  matches filename with glob
    """
    compiled = []
    for entry in raw:
        if not entry:
            continue
        entry = entry.replace('\\', '/')
        if entry.startswith('*') and entry.endswith('/'):
            # *helf/ → match directory name anywhere in path
            compiled.append((entry[1:], 'dir_any'))
        elif entry.endswith('/'):
            compiled.append((entry, 'dir'))
        elif '/' in entry:
            compiled.append((entry, 'path'))
        else:
            compiled.append((entry, 'name'))
    return compiled


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


def _parse_readelf_dynamic(path: Path) -> list[str]:
    """Run readelf -d and return raw output lines."""
    try:
        result = subprocess.run(
            ['readelf', '-d', str(path)],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _parse_dynamic_one(path: str) -> tuple[str, str, list[str]]:
    """Parse DT_SONAME and DT_NEEDED from a single ELF in one readelf call.

    Returns (path, soname, needed_list).
    """
    try:
        result = subprocess.run(
            ['readelf', '-d', path],
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return path, '', []

    soname = ''
    needed = []
    for line in out.splitlines():
        m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
        if m:
            needed.append(m.group(1))
            continue
        m = re.search(r'\(SONAME\)\s+Library soname: \[(.+)\]', line)
        if m:
            soname = m.group(1)
    return path, soname, needed


# ── Bulk parallel ELF parser ────────────────────────────────────────

class _ElfCache:
    """Cache soname + DT_NEEDED for many ELFs, parsed in parallel."""

    def __init__(self):
        self._soname = {}    # abs-path-str → soname
        self._needed = {}    # abs-path-str → [needed, ...]

    def bulk_parse(self, paths):
        """Parse all *paths* in parallel using ThreadPoolExecutor."""
        str_paths = [str(p) for p in paths]
        n_workers = min(os.cpu_count() or 4, len(str_paths), 64)
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            for p, soname, needed in pool.map(_parse_dynamic_one, str_paths):
                self._soname[p] = soname
                self._needed[p] = needed

    def get_soname(self, path) -> str:
        key = str(path)
        if key not in self._soname:
            _, soname, needed = _parse_dynamic_one(key)
            self._soname[key] = soname
            self._needed[key] = needed
        return self._soname[key]

    def get_needed(self, path) -> list[str]:
        key = str(path)
        if key not in self._needed:
            _, soname, needed = _parse_dynamic_one(key)
            self._soname[key] = soname
            self._needed[key] = needed
        return self._needed[key]


def get_dt_needed(path: Path) -> list[str]:
    """Get DT_NEEDED library names from an ELF binary using readelf."""
    needed = []
    for line in _parse_readelf_dynamic(path):
        m = re.search(r'\(NEEDED\)\s+Shared library: \[(.+)\]', line)
        if m:
            needed.append(m.group(1))
    return needed


def get_dt_soname(path: Path) -> str:
    """Get DT_SONAME from a shared library. Returns '' if not set."""
    for line in _parse_readelf_dynamic(path):
        m = re.search(r'\(SONAME\)\s+Library soname: \[(.+)\]', line)
        if m:
            return m.group(1)
    return ''


def build_soname_maps(lib_files: list, cache: _ElfCache) -> tuple[dict, dict]:
    """Build bidirectional soname <-> filename mappings for encrypted libs.

    Uses *cache* (pre-populated via bulk_parse) so no subprocess calls.

    Returns (soname_to_filename, lib_by_lookup) where lib_by_lookup maps
    both sonames and filenames to the source Path for DT_NEEDED traversal.
    """
    soname_to_filename = {}   # soname -> filename
    lib_by_lookup = {}        # soname or filename -> Path

    for src in lib_files:
        fname = src.name
        lib_by_lookup[fname] = src

        soname = cache.get_soname(src)
        if soname and soname != fname:
            soname_to_filename[soname] = fname
            lib_by_lookup[soname] = src

    return soname_to_filename, lib_by_lookup


def get_transitive_needed(path: Path, encrypted_names: set[str],
                          soname_to_filename: dict[str, str],
                          lib_by_lookup: dict[str, 'Path'],
                          cache: _ElfCache,
                          ldcache: dict) -> list[str]:
    """Get transitive closure of encrypted libs needed by an ELF binary.

    Phase 1: BFS from path's DT_NEEDED, following through ALL libs —
    including unencrypted intermediaries — to discover every encrypted
    lib reachable from this exe.

    Phase 2: Build a dependency graph among those encrypted libs and
    topologically sort (Kahn's algorithm) so leaf dependencies come
    first.  This ensures correct LD_PRELOAD ordering: when glibc loads
    each entry, its DT_NEEDED are already available.

    Previous approach (BFS-reverse) failed for diamond dependencies:
        exe -> A -> B, exe -> C -> D -> B
    BFS-reverse gave D,B,C,A — D before its dep B.  Topo sort gives
    B,D,A,C (or B,D,C,A) — B always before D and A.
    """
    # ── Phase 1: BFS discovery ───────────────────────────────────────
    encrypted_needed = set()
    visited = set()
    queue = list(cache.get_needed(path))

    while queue:
        name = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)

        filename = soname_to_filename.get(name, name)

        if filename in encrypted_names:
            encrypted_needed.add(filename)
            lib_path = lib_by_lookup.get(name) or lib_by_lookup.get(filename)
            if lib_path:
                for dep in cache.get_needed(lib_path):
                    if dep not in visited:
                        queue.append(dep)
        else:
            lib_path = ldcache.get(name)
            if lib_path:
                for dep in cache.get_needed(lib_path):
                    if dep not in visited:
                        queue.append(dep)

    if not encrypted_needed:
        return []

    # ── Phase 2: build edge graph among encrypted libs ───────────────
    # edges[A] = [B, C] means A depends on encrypted libs B and C.
    edges = {fn: [] for fn in encrypted_needed}

    for filename in encrypted_needed:
        lib_path = lib_by_lookup.get(filename)
        if not lib_path:
            for sn, fn in soname_to_filename.items():
                if fn == filename:
                    lib_path = lib_by_lookup.get(sn)
                    break
        if not lib_path:
            continue
        for dep_name in cache.get_needed(lib_path):
            dep_filename = soname_to_filename.get(dep_name, dep_name)
            if dep_filename in encrypted_needed and dep_filename != filename:
                edges[filename].append(dep_filename)

    # ── Phase 3: Kahn's topological sort ─────────────────────────────
    all_nodes = set(edges.keys())
    for children in edges.values():
        all_nodes.update(children)

    in_degree = {n: 0 for n in all_nodes}
    for parent, children in edges.items():
        for c in children:
            in_degree[c] += 1

    q = deque(n for n in sorted(all_nodes) if in_degree[n] == 0)
    result = []
    while q:
        node = q.popleft()
        result.append(node)
        for child in edges.get(node, []):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                q.append(child)

    if len(result) < len(all_nodes):
        cycle_nodes = all_nodes - set(result)
        print("[pack] WARNING: dependency cycle among encrypted libs: "
              "{}".format(', '.join(sorted(cycle_nodes))),
              file=sys.stderr)
        result.extend(sorted(cycle_nodes))

    # Kahn's gives parents first → reverse for leaf-deps-first LD_PRELOAD order
    result.reverse()
    return [n for n in result if n in encrypted_needed]


# ── Worker functions (run in child processes) ─────────────────────────

def _encrypt_lib_worker(src: str, dst: str, key: bytes,
                        patchelf: str = "patchelf") -> str:
    """Encrypt a single .so file (or .elf PG binary). Returns status string.

    ``patchelf`` is the path to (or name of) the patchelf binary used to
    inject a DT_SONAME into libs that lack one.

    If a .so has no DT_SONAME, patch a copy with patchelf first so that
    glibc can match the LD_PRELOAD'd memfd to DT_NEEDED entries at
    runtime.  .elf PG binaries are looked up by basename at runtime
    (aarch64_extend_shim → OP_GET_LIB), never go through DT_NEEDED resolution,
    and usually have no SONAME — skip patchelf for them.

    .debug files (separate-debug-info ELFs produced by `objcopy
    --only-keep-debug`, e.g. libfoo.so.debug) are not loaded as
    runtime shared libs at all — they live next to the stripped .so
    and gdb pulls them in via .gnu_debuglink.  patchelf chokes on
    them ("strange: no string table") because the dynsym/dynstr
    sections are gutted by the strip.  Skip patchelf for them; the
    encryption itself still runs if the user listed them.
    """
    src_p, dst_p = Path(src), Path(dst)
    patched = None
    soname_note = ""

    is_elf_asset = src_p.name.endswith('.elf')
    is_debug_file = src_p.suffix == '.debug'

    # Check if SONAME is missing (.so only — .elf and .debug files
    # don't need one and would crash patchelf).
    if not is_elf_asset and not is_debug_file and not get_dt_soname(src_p):
        # Pack-time only — runs on the build machine, not deployed.
        # Still rename to avoid the "antirev_" brand showing up in
        # /tmp/ during builds shared with other tools/users.
        tmp_dir = tempfile.mkdtemp(prefix=".lrx_patch_")
        patched = Path(tmp_dir) / src_p.name
        shutil.copy2(src_p, patched)
        try:
            subprocess.run(
                [patchelf, "--set-soname", src_p.name, str(patched)],
                check=True, capture_output=True, text=True)
            soname_note = " [patched SONAME]"
        except FileNotFoundError:
            sys.exit(f"[error] patchelf not found at '{patchelf}' — required for "
                     "libs without DT_SONAME. Install it "
                     "(https://github.com/NixOS/patchelf) or set --patchelf / "
                     "the 'patchelf' config field to its path.")
        except subprocess.CalledProcessError as e:
            sys.exit(f"[error] patchelf failed on {src_p.name}: {e.stderr}")

    data = (patched or src_p).read_bytes()

    # Clean up temp file
    if patched:
        shutil.rmtree(patched.parent, ignore_errors=True)

    iv, tag, ct = encrypt_data(data, key)
    dst_p.parent.mkdir(parents=True, exist_ok=True)
    dst_p.write_bytes(MAGIC + iv + tag + ct)
    out_size = dst_p.stat().st_size
    return (f"[pack] Encrypted  lib: {src_p.name:<30}  "
            f"{len(data):>10,} -> {out_size:>10,} bytes{soname_note}")


def _protect_exe_worker(src: str, stub: str, dst: str, key: bytes,
                        daemon_libs: bool = False,
                        needed_libs: list[str] = None) -> str:
    """Encrypt an executable and wrap it in the stub launcher."""
    src_p  = Path(src)
    stub_p = Path(stub)
    dst_p  = Path(dst)

    # Main exe entry
    data = src_p.read_bytes()
    iv, tag, ct = encrypt_data(data, key)
    name_b = src_p.name.encode()

    entry  = struct.pack("<H", len(name_b))
    entry += name_b
    entry += iv
    entry += tag
    entry += struct.pack("<Q", len(ct))
    entry += ct

    flags = BFLAG_HAS_MAIN
    if daemon_libs:
        flags |= BFLAG_DAEMON_LIBS

    # Needed-libs section: tells stub which daemon libs this exe DT_NEEDs
    needed_section = b""
    if daemon_libs:
        needed_section = struct.pack("<H", len(needed_libs or []))
        for name in (needed_libs or []):
            nb = name.encode()
            needed_section += struct.pack("<H", len(nb)) + nb

    bundle = struct.pack("<B", flags) + entry \
           + needed_section

    stub_data     = stub_p.read_bytes()
    bundle_offset = len(stub_data)
    trailer       = struct.pack("<Q", bundle_offset) + key + MAGIC

    dst_p.parent.mkdir(parents=True, exist_ok=True)
    dst_p.write_bytes(stub_data + bundle + trailer)
    os.chmod(str(dst_p), 0o755)

    out_size = dst_p.stat().st_size
    need_info = f" (needs {len(needed_libs)})" if needed_libs else ""
    return (f"[pack] Protected  exe: {src_p.name:<30}  "
            f"{len(data):>10,} -> {out_size:>10,} bytes{need_info}")


def _copy_worker(items: list[tuple[str, str]]) -> int:
    """Copy a batch of files. Returns count."""
    for src, dst in items:
        dst_p = Path(dst)
        dst_p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst_p)
    return len(items)


def main():
    ap = argparse.ArgumentParser(description="antirev config-driven batch protector")
    ap.add_argument("--config", required=True, metavar="FILE",
                    help="YAML config file")
    ap.add_argument("-j", "--jobs", type=int, default=0,
                    help="Number of parallel workers (default: CPU count)")
    # CLI overrides — each takes priority over the same field in config.yaml.
    ap.add_argument("--install-dir", help="override config install_dir")
    ap.add_argument("--output-dir", help="override config output_dir")
    ap.add_argument("--key", help="override config key (hex keyfile path)")
    ap.add_argument("--stub",
                    help="override config stub/stubs (single stub ELF for all arches)")
    ap.add_argument("--lrxd",
                    help="daemon binary base name (overrides config 'lrxd', default: lrxd)")
    ap.add_argument("--patchelf",
                    help="path to the patchelf binary used to inject DT_SONAME "
                         "(overrides config 'patchelf', default: patchelf)")
    ap.add_argument("--version", dest="pkg_version",
                    help="package version string (overrides config 'version'); "
                         "recorded in the pack manifest and summary")
    args = ap.parse_args()

    t_start = time.monotonic()

    config_path = Path(args.config)
    if not config_path.exists():
        sys.exit(f"[error] config not found: {config_path}")

    with open(config_path) as f:
        cfg = yaml.safe_load(f) or {}   # empty YAML -> {} so CLI-only runs work

    def _expand(p: str) -> str:
        return os.path.expanduser(os.path.expandvars(p))

    # ── Merge fields: CLI input > config.yaml > default ───────────────
    install_raw = _resolve_field(args.install_dir, cfg, 'install_dir')
    output_raw  = _resolve_field(args.output_dir,  cfg, 'output_dir')
    stub_cli    = args.stub  # CLI --stub overrides config stub/stubs entirely

    # ── Validate required fields (after the CLI/config merge) ─────────
    if install_raw is None:
        sys.exit("[error] missing required field 'install_dir' "
                 "(set it in config or pass --install-dir)")
    if output_raw is None:
        sys.exit("[error] missing required field 'output_dir' "
                 "(set it in config or pass --output-dir)")
    if stub_cli is None and 'stub' not in cfg and 'stubs' not in cfg:
        sys.exit("[error] config must have 'stub' or 'stubs' field "
                 "(or pass --stub)")

    install_dir = Path(_expand(install_raw)).resolve()
    output_dir  = Path(_expand(output_raw)).resolve()

    # key path: CWD-relative when supplied on the CLI, config-relative
    # when read from config.yaml (preserves existing config semantics).
    if args.key is not None:
        key_path = (Path.cwd() / _expand(args.key)).resolve()
    else:
        key_path = (config_path.parent
                    / _expand(cfg.get('key', 'antirev.key'))).resolve()

    blacklist = compile_blacklist(cfg.get('blacklist', []))
    workers   = args.jobs if args.jobs > 0 else (os.cpu_count() or 4)

    # Daemon binary base name + package version (CLI > config > default).
    lrxd_name = _expand(_resolve_field(args.lrxd, cfg, 'lrxd', 'lrxd')) or 'lrxd'
    pkg_version = str(_resolve_field(args.pkg_version, cfg, 'version', '') or '').strip()
    # patchelf binary path (CLI > config > default). Left as a command name
    # when unset so it is resolved on PATH; env vars / ~ expanded otherwise.
    patchelf_path = _expand(_resolve_field(args.patchelf, cfg, 'patchelf',
                                           'patchelf')) or 'patchelf'

    # Build arch -> stub mapping.  CLI --stub (CWD-relative) overrides the
    # config stub/stubs entirely; otherwise use config 'stubs' or 'stub'
    # (config-relative).
    stubs: dict[str, Path] = {}
    if stub_cli is not None:
        single = (Path.cwd() / _expand(stub_cli)).resolve()
        elf_info = classify_elf(single)
        if elf_info:
            stubs[elf_info[1]] = single
        else:
            stubs['x86_64'] = single
            stubs['aarch64'] = single
    elif 'stubs' in cfg:
        for arch, p in cfg['stubs'].items():
            stubs[arch] = (config_path.parent / _expand(p)).resolve()
    elif 'stub' in cfg:
        single = (config_path.parent / _expand(cfg['stub'])).resolve()
        elf_info = classify_elf(single)
        if elf_info:
            stubs[elf_info[1]] = single
        else:
            stubs['x86_64'] = single
            stubs['aarch64'] = single

    if not install_dir.exists():
        sys.exit(f"[error] install_dir not found: {install_dir}")

    # If a configured stub is missing on disk, drop that arch from the
    # mapping rather than aborting the whole pack.  The existing
    # "unsupported arch" fallback then catches every ELF of that arch
    # below (copied verbatim with a per-arch WARNING summary).  Lets
    # you ship an x86-only or aarch64-only build without rebuilding
    # the YAML.
    for arch in list(stubs.keys()):
        stub = stubs[arch]
        if not stub.exists():
            print(f"[pack] WARNING: stub for {arch} not found at {stub} "
                  f"— skipping {arch} packing (ELFs of this arch will be "
                  f"copied as plaintext)", file=sys.stderr)
            del stubs[arch]
    if not stubs:
        sys.exit("[error] no usable stub: every configured stub was missing")

    key = load_or_create_key(key_path)
    copylist = compile_blacklist(cfg.get('copy', []))

    # ── Lib encryption filter ────────────────────────────────────────
    # encrypt_libs (whitelist): only these libs get encrypted, rest copied as-is
    # plaintext_libs (blacklist): these libs stay plaintext, rest get encrypted
    # If neither is set, all libs are encrypted (original behavior).
    # Only one of encrypt_libs / plaintext_libs may be specified.
    raw_encrypt_libs   = cfg.get('encrypt_libs',   []) or []
    raw_plaintext_libs = cfg.get('plaintext_libs',  []) or []
    if raw_encrypt_libs and raw_plaintext_libs:
        sys.exit("[error] 'encrypt_libs' and 'plaintext_libs' are mutually "
                 "exclusive — use one or the other")

    lib_whitelist = compile_blacklist(raw_encrypt_libs) if raw_encrypt_libs else []
    lib_blacklist = compile_blacklist(raw_plaintext_libs) if raw_plaintext_libs else []

    # ── Scan all files ────────────────────────────────────────────────
    exe_files          = []   # (rel_path, arch, abs_path)
    lib_files          = []   # abs_path — libs to encrypt
    plain_libs         = []   # abs_path — libs to copy as plaintext
    unsupported_arch   = []   # (rel, arch, src) — ELF whose arch is not in stubs
    copy_files         = []   # abs_path — non-ELF files to copy
    symlinks           = []   # (abs_path, target) — symlinks to recreate in output
    skipped            = []   # rel_path
    ignored            = 0    # non-ELF files not in copy list

    for src in sorted(install_dir.rglob('*')):
        if src.is_symlink():
            symlinks.append((src, os.readlink(src)))
            continue
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

        # Out-of-scope arch: user only configured stubs for some arches,
        # so this ELF gets copied through verbatim (the install tree
        # stays complete; runtime just won't see encryption for it).
        # A summary is printed below so a typo'd / missing stub config
        # is still visible.
        if arch not in stubs:
            unsupported_arch.append((rel, arch, src))
            continue

        if kind == 'exe':
            exe_files.append((rel, arch, src))
        else:
            # Determine if this lib should be encrypted or stay plaintext
            if lib_whitelist:
                # Whitelist mode: only encrypt if it matches
                if is_blacklisted(rel, lib_whitelist):
                    lib_files.append(src)
                else:
                    plain_libs.append(src)
            elif lib_blacklist:
                # Blacklist mode: encrypt unless it matches
                if is_blacklisted(rel, lib_blacklist):
                    plain_libs.append(src)
                else:
                    lib_files.append(src)
            else:
                # No filter: encrypt all libs
                lib_files.append(src)

    # ── Report scan results ───────────────────────────────────────────
    print(f"[pack] Scanned {install_dir}")
    print(f"[pack]   Executables:    {len(exe_files)}")
    print(f"[pack]   Libs (encrypt): {len(lib_files)}")
    if plain_libs:
        print(f"[pack]   Libs (plain):   {len(plain_libs)}")
    print(f"[pack]   Copy:           {len(copy_files)}")
    if symlinks:
        print(f"[pack]   Symlinks:       {len(symlinks)}")
    print(f"[pack]   Ignored:        {ignored}")
    print(f"[pack]   Workers:        {workers}")
    if skipped:
        print(f"[pack]   Blacklisted:   {len(skipped)}")
        for rel in skipped:
            print(f"[pack]     skip: {rel}")
    if unsupported_arch:
        # Group per arch so the warning is concise even if there are many.
        per_arch: dict[str, list[str]] = {}
        for rel, arch, _src in unsupported_arch:
            per_arch.setdefault(arch, []).append(rel)
        configured = ", ".join(sorted(stubs.keys())) or "<none>"
        for arch, rels in sorted(per_arch.items()):
            print(f"[pack]   WARNING: {len(rels)} ELF(s) with arch '{arch}' "
                  f"have no configured stub (configured: {configured}) — "
                  f"copying as plaintext")
            for rel in rels:
                print(f"[pack]     plain (arch={arch}): {rel}")
    print()

    # ── Lib handling mode ────────────────────────────────────────────────
    # libs: encrypt (default) — encrypt libs individually, serve via daemon
    # libs: skip              — ignore libs entirely (exe-only protection)
    libs_mode = cfg.get('libs', 'encrypt')
    if libs_mode not in ('encrypt', 'skip'):
        sys.exit(f"[error] invalid libs mode '{libs_mode}' "
                 f"(must be 'encrypt' or 'skip')")

    print(f"[pack] Libs mode: {libs_mode}")

    # Encrypt libs individually to output_dir as standalone encrypted files,
    # and create a lightweight daemon binary (stub + key, no bundled libs)
    # that reads encrypted libs from disk at runtime
    if libs_mode == 'encrypt' and lib_files:
        print(f"[pack] Encrypting {len(lib_files)} lib(s) individually...")
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _encrypt_lib_worker,
                    str(src),
                    str(output_dir / src.relative_to(install_dir)),
                    key,
                    patchelf_path,
                ): src.name
                for src in lib_files
            }
            for fut in as_completed(futures):
                try:
                    print(fut.result())
                except Exception as e:
                    sys.exit(f"[error] encrypt lib failed for {futures[fut]}: {e}")

        # Build lightweight daemon per architecture.  Multi-arch deploys
        # get suffixed filenames (lrxd-x86_64 / -aarch64); single-arch
        # builds keep the unsuffixed lrxd.  Renamed from ".antirev-libd*"
        # so `ls /opt/biz/` / `ps aux` doesn't fingerprint the daemon as
        # antirev's.  No leading dot: a hidden executable is itself
        # suspicious, and dotfiles get skipped by glob/rsync copies;
        # plain "lrxd" blends in.  No wrapper binary — wrapper mode retired.
        for arch, stub_path in stubs.items():
            stub_data = stub_path.read_bytes()
            suffix = f'-{arch}' if len(stubs) > 1 else ''

            daemon_path = output_dir / f'{lrxd_name}{suffix}'
            bundle = struct.pack("<IB", 0, 0)  # 0 files, no flags
            bundle_offset = len(stub_data)
            trailer = struct.pack("<Q", bundle_offset) + key + MAGIC
            daemon_path.parent.mkdir(parents=True, exist_ok=True)
            daemon_path.write_bytes(stub_data + bundle + trailer)
            os.chmod(str(daemon_path), 0o755)
            print(f"[pack] Daemon binary: {daemon_path.name}  "
                  f"({daemon_path.stat().st_size:,} bytes, {arch})")
        print()

    if exe_files:
        print(f"[pack] Protecting {len(exe_files)} executable(s)...")
        # Arch-vs-stubs mismatch is filtered out earlier in the scan
        # phase (see 'unsupported_arch'), so every entry here has a
        # matching stub by construction.

        exe_daemon_libs = libs_mode == 'encrypt' and bool(lib_files)

        # Determine which encrypted libs each exe transitively DT_NEEDs
        encrypted_names = {src.name for src in lib_files}
        exe_needed = {}
        if exe_daemon_libs and encrypted_names:
            # Parallel bulk-parse: one readelf per ELF, all in parallel
            elf_cache = _ElfCache()
            all_parse = [src for src in lib_files] + [src for _, _, src in exe_files]
            t0 = time.monotonic()
            print("[pack] Parsing {} ELFs in parallel...".format(len(all_parse)))
            elf_cache.bulk_parse(all_parse)
            print("[pack]   done in {:.1f}s".format(time.monotonic() - t0))

            print("[pack] Building soname map for encrypted libs...")
            soname_to_filename, lib_by_lookup = build_soname_maps(
                lib_files, elf_cache)
            if soname_to_filename:
                for sn, fn in soname_to_filename.items():
                    print("[pack]   soname {} -> {}".format(sn, fn))
            ldcache = _build_ldconfig_cache()
            print("[pack] Analyzing DT_NEEDED per executable (transitive)...")
            for rel, arch, src in exe_files:
                needed = get_transitive_needed(
                    src, encrypted_names, soname_to_filename, lib_by_lookup,
                    elf_cache, ldcache)
                exe_needed[rel] = needed

        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _protect_exe_worker,
                    str(src),
                    str(stubs[arch]),
                    str(output_dir / rel),
                    key,
                    exe_daemon_libs,
                    exe_needed.get(rel, []),
                ): rel
                for rel, arch, src in exe_files
            }
            for fut in as_completed(futures):
                try:
                    print(fut.result())
                except Exception as e:
                    sys.exit(f"[error] protect failed for {futures[fut]}: {e}")
        print()

    # ── Copy plaintext libs + other files (parallel, batched) ─────────
    # Merge plain_libs and unsupported-arch ELFs into copy_files —
    # they all just go to output_dir verbatim.
    unsupported_paths = [src for _rel, _arch, src in unsupported_arch]
    all_copy = copy_files + plain_libs + unsupported_paths
    if plain_libs:
        print(f"[pack] Copying {len(plain_libs)} plaintext "
              f"librar{'y' if len(plain_libs) == 1 else 'ies'} as-is...")
    if unsupported_paths:
        print(f"[pack] Copying {len(unsupported_paths)} unsupported-arch "
              f"ELF(s) as plaintext...")
    if all_copy:
        pairs = [
            (str(src), str(output_dir / src.relative_to(install_dir)))
            for src in all_copy
        ]
        # Split into batches — one per worker, minimum 1
        batch_size = max(1, len(pairs) // workers)
        batches = [pairs[i:i + batch_size]
                   for i in range(0, len(pairs), batch_size)]

        with ProcessPoolExecutor(max_workers=min(workers, len(batches))) as pool:
            total = sum(pool.map(_copy_worker, batches))
        print(f"[pack] Copied {total} file(s) as-is")
        print()

    # ── Recreate symlinks in output directory ────────────────────────
    if symlinks:
        for src, target in symlinks:
            dst = output_dir / src.relative_to(install_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            os.symlink(target, dst)
        print(f"[pack] Recreated {len(symlinks)} symlink(s)")
        print()

    # ── Pack manifest (written NEXT TO the config, never inside the
    #    shipped output tree — a file named *manifest* under output_dir
    #    would fingerprint the deployment).  Records the version + the
    #    key parameters used for this pack.
    manifest = {
        'version': pkg_version,
        'lrxd': lrxd_name,
        'patchelf': patchelf_path,
        'install_dir': str(install_dir),
        'output_dir': str(output_dir),
        'arches': sorted(stubs.keys()),
        'libs_mode': libs_mode,
    }
    manifest_path = config_path.parent / 'antirev-pack-manifest.json'
    with open(manifest_path, 'w') as mf:
        json.dump(manifest, mf, indent=2)
        mf.write('\n')

    elapsed = time.monotonic() - t_start
    print(f"[pack] Done in {elapsed:.1f}s")
    if pkg_version:
        print(f"[pack]   Version  -> {pkg_version}")
    print(f"[pack]   Output   -> {output_dir}")
    print(f"[pack]   Daemon   -> {lrxd_name}")
    print(f"[pack]   Manifest -> {manifest_path}")
    print(f"[pack]   Key      -> {key_path}  (keep secret)")


if __name__ == '__main__':
    main()
