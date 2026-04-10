#!/usr/bin/env python3
"""
Build script to compile Python source files using Nuitka or Cython.

Usage:
    python build.py nuitka              # compile main programs with Nuitka
    python build.py cython              # compile libraries with Cython
    python build.py all                 # Nuitka for mains + Cython for libs
    python build.py clean               # remove build artifacts

Nuitka strategies:
    shared      (default) One shared runtime + compiled modules.
                          Output: ~300MB total instead of ~300GB.
                          Build time: ~15-30 min instead of ~2 hours.
    per-script  Legacy mode: standalone build per script (slow, large).

Configure MAINS_DIR, LIBS_DIR, and other settings below.
"""

import argparse
import ast
import glob
import hashlib
import json
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

# ============================================================
# Configuration — adjust these to match your project structure
# ============================================================

# Directory containing your main entry-point scripts
MAINS_DIR = "mains"

# Directory containing your library packages/modules
LIBS_DIR = "libs"

# Output directory for compiled results
OUTPUT_DIR = "dist"

# Number of parallel workers (0 = auto-detect)
WORKERS = 0

# Files/directories to exclude from compilation
EXCLUDE_PATTERNS = [
    "__pycache__",
    "*.pyc",
    "test_*.py",
    "*_test.py",
    "setup.py",
    "build.py",
    "conftest.py",
]

# Nuitka extra flags (add your own as needed)
NUITKA_EXTRA_FLAGS = [
    # "--include-package=your_package",
    # "--include-data-dir=data=data",
    # "--enable-plugin=numpy",
]

# Whether to remove .py source files from output after Cython compilation
REMOVE_SOURCE_AFTER_CYTHON = True

# Nuitka build strategy: "shared" (fast, small) or "per-script" (legacy)
NUITKA_STRATEGY = "shared"

# ============================================================


def get_workers():
    if WORKERS > 0:
        return WORKERS
    return max(1, multiprocessing.cpu_count() - 1)


def find_py_files(directory, exclude_patterns=None):
    """Recursively find all .py files in directory, respecting exclusions."""
    exclude_patterns = exclude_patterns or EXCLUDE_PATTERNS
    py_files = []
    for path in Path(directory).rglob("*.py"):
        name = path.name
        skip = False
        for pat in exclude_patterns:
            if pat.startswith("*"):
                if name.endswith(pat[1:]):
                    skip = True
                    break
            elif name == pat:
                skip = True
                break
            elif pat in str(path):
                skip = True
                break
        if not skip:
            py_files.append(path)
    return sorted(py_files)


def check_tool(name):
    """Check if a command-line tool is available."""
    result = shutil.which(name)
    if not result:
        print(f"[ERROR] '{name}' not found. Install it first:")
        if name == "nuitka":
            print("    pip install nuitka")
        elif name == "cython" or name == "cythonize":
            print("    pip install cython")
        sys.exit(1)


# ============================================================
# Import scanning (for shared strategy)
# ============================================================

def scan_imports(py_files):
    """Scan Python files and return all top-level imported package names."""
    imports = set()
    for f in py_files:
        try:
            source = Path(f).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(f))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split(".")[0])
        except Exception:
            pass
    imports.discard("__future__")
    return imports


def get_lib_module_names(libs_dir):
    """Get top-level module/package names from the libs directory."""
    libs_path = Path(libs_dir)
    if not libs_path.is_dir():
        return set()
    names = set()
    for item in libs_path.iterdir():
        if item.is_dir() and (item / "__init__.py").exists():
            names.add(item.name)
        elif item.is_file() and item.suffix == ".py" and item.name != "__init__.py":
            names.add(item.stem)
    return names


# ============================================================
# Incremental build support
# ============================================================

HASH_MANIFEST = ".nuitka_hashes.json"


def _file_hash(path):
    """Return SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_hash_manifest(output_dir):
    """Load the previous build's file-hash manifest."""
    manifest_path = Path(output_dir) / HASH_MANIFEST
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_hash_manifest(output_dir, manifest):
    """Persist the current build's file-hash manifest."""
    manifest_path = Path(output_dir) / HASH_MANIFEST
    manifest_path.write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def needs_rebuild(source_path, output_dir, manifest):
    """Check if a source file has changed since the last build."""
    key = str(source_path)
    current_hash = _file_hash(source_path)
    return current_hash != manifest.get(key), current_hash


# ============================================================
# Nuitka compilation — per-script (legacy) strategy
# ============================================================

def nuitka_compile_one(main_file, output_dir):
    """Compile a single main script with Nuitka --standalone."""
    main_file = Path(main_file)
    name = main_file.stem

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--follow-imports",
        f"--output-dir={output_dir}",
        "--lto=no",

        "--assume-yes-for-downloads",
        "--python-flag=no_docstrings",
    ]
    cmd.extend(NUITKA_EXTRA_FLAGS)
    cmd.append(str(main_file))

    print(f"  [nuitka] Compiling {main_file} ...")
    t0 = time.time()
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"  [nuitka] FAILED {main_file} ({elapsed:.1f}s)")
        log_path = Path(output_dir) / f"{name}.nuitka.log"
        log_path.write_text(result.stdout)
        print(f"           Log: {log_path}")
        return False, str(main_file)

    print(f"  [nuitka] OK     {main_file} ({elapsed:.1f}s)")
    return True, str(main_file)


def build_nuitka_per_script(mains_dir, output_dir):
    """Legacy: compile each main script as a standalone Nuitka binary."""
    check_tool("nuitka")

    mains = find_py_files(mains_dir)
    if not mains:
        print(f"[WARN] No .py files found in '{mains_dir}'")
        return

    print(f"\n{'='*60}")
    print(f"[Nuitka] Per-script mode: {len(mains)} main program(s)")
    print(f"         Workers: {get_workers()}")
    print(f"{'='*60}\n")

    os.makedirs(output_dir, exist_ok=True)
    ok_count = 0
    fail_count = 0
    failed = []

    workers = get_workers()
    if workers == 1:
        for f in mains:
            success, name = nuitka_compile_one(f, output_dir)
            if success:
                ok_count += 1
            else:
                fail_count += 1
                failed.append(name)
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(nuitka_compile_one, f, output_dir): f
                for f in mains
            }
            for fut in as_completed(futures):
                success, name = fut.result()
                if success:
                    ok_count += 1
                else:
                    fail_count += 1
                    failed.append(name)

    print(f"\n[Nuitka] Done: {ok_count} succeeded, {fail_count} failed")
    if failed:
        print("[Nuitka] Failed files:")
        for f in failed:
            print(f"  - {f}")


# ============================================================
# Nuitka compilation — shared runtime strategy
# ============================================================

def qualified_module_name(source_path, mains_dir):
    """Derive a dotted module name relative to mains_dir.

    e.g. mains/pkg1/__init__.py -> pkg1.__init__
         mains/foo.py           -> foo
    """
    rel = Path(source_path).relative_to(mains_dir)
    parts = list(rel.parts)
    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    return ".".join(parts)


def preprocess_main_for_module(source_path, temp_dir, mains_dir):
    """Preprocess a main script for module compilation.

    Replaces ``if __name__ == "__main__":`` with ``if True:`` so that
    entry-point code executes when the launcher imports the module.

    Preserves directory structure under temp_dir so that Nuitka sees the
    correct package layout (avoids collisions between e.g. two __init__.py).
    """
    source = Path(source_path).read_text(encoding="utf-8", errors="replace")
    processed = re.sub(
        r"""if\s+__name__\s*==\s*['"]__main__['"]\s*:""",
        "if True:",
        source,
    )
    rel = Path(source_path).relative_to(mains_dir)
    dest = Path(temp_dir) / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(processed, encoding="utf-8")
    return dest


def nuitka_compile_module(main_file, output_dir, jobs=1):
    """Compile a single script as a Nuitka module (.so/.pyd)."""
    main_file = Path(main_file)
    name = main_file.stem

    cmd = [
        sys.executable, "-m", "nuitka",
        "--module",
        f"--output-dir={output_dir}",
        "--no-pyi-file",
        "--lto=no",
        f"--jobs={jobs}",

        "--assume-yes-for-downloads",
        "--python-flag=no_docstrings",
    ]
    cmd.extend(NUITKA_EXTRA_FLAGS)
    cmd.append(str(main_file))

    print(f"  [nuitka] Compiling module {name} ...")
    t0 = time.time()
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"  [nuitka] FAILED module {name} ({elapsed:.1f}s)")
        log_path = Path(output_dir) / f"{name}.nuitka.log"
        log_path.write_text(result.stdout)
        return False, str(main_file)

    print(f"  [nuitka] OK     module {name} ({elapsed:.1f}s)")
    return True, str(main_file)


def build_nuitka_shared(mains_dir, libs_dir, output_dir):
    """Shared-runtime strategy: one standalone launcher + N compiled modules.

    Instead of 1000 × standalone (each ~300MB = 300GB total), this builds:
      - 1 standalone launcher with shared runtime (~300MB)
      - 1000 compiled modules (~10KB-1MB each)
    Total output: ~300MB-1GB instead of ~300GB.
    Build time: ~15-30 min instead of ~2 hours.
    """
    check_tool("nuitka")

    mains = find_py_files(mains_dir)
    if not mains:
        print(f"[WARN] No .py files found in '{mains_dir}'")
        return

    # Check for duplicate qualified module names
    seen = {}
    for f in mains:
        qname = qualified_module_name(f, mains_dir)
        if qname in seen:
            print(f"[ERROR] Duplicate module name '{qname}':")
            print(f"        {seen[qname]}")
            print(f"        {f}")
            print(f"        Rename one of them to avoid module name conflicts.")
            sys.exit(1)
        seen[qname] = f

    print(f"\n{'='*60}")
    print(f"[Nuitka] Shared-runtime mode: {len(mains)} main program(s)")
    print(f"         Workers: {get_workers()}")
    print(f"{'='*60}")

    os.makedirs(output_dir, exist_ok=True)
    shared_dist = Path(output_dir) / "shared_dist"

    # --- Step 1: Scan imports ---
    print(f"\n  Step 1/4: Scanning imports across {len(mains)} scripts ...")
    all_imports = scan_imports(mains)
    lib_modules = get_lib_module_names(libs_dir)
    third_party = all_imports - lib_modules
    print(f"           {len(all_imports)} unique imports "
          f"({len(third_party)} to bundle, "
          f"{len(all_imports & lib_modules)} from libs)")

    # --- Step 2: Build shared standalone runtime ---
    print(f"\n  Step 2/4: Building shared runtime (one-time standalone) ...")

    launcher_src = Path(output_dir) / "_launcher.py"
    import_lines = []
    for imp in sorted(third_party):
        import_lines.append(
            f"try:\n    import {imp}\nexcept ImportError:\n    pass"
        )

    launcher_code = (
        "import sys\n"
        "import importlib\n\n"
        + "\n".join(import_lines)
        + "\n\nif __name__ == '__main__':\n"
        "    if len(sys.argv) < 2:\n"
        "        print('Usage: _launcher <module_name> [args...]')\n"
        "        sys.exit(1)\n"
        "    _mod_name = sys.argv[1]\n"
        "    sys.argv = sys.argv[1:]  # shift so module sees correct argv\n"
        "    importlib.import_module(_mod_name)\n"
    )
    launcher_src.write_text(launcher_code, encoding="utf-8")

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--follow-imports",
        f"--output-dir={output_dir}",
        "--lto=no",
        f"--jobs={get_workers()}",

        "--assume-yes-for-downloads",
        "--python-flag=no_docstrings",
    ]
    for lib_mod in lib_modules:
        cmd.append(f"--nofollow-import-to={lib_mod}")
    cmd.extend(NUITKA_EXTRA_FLAGS)
    cmd.append(str(launcher_src))

    t0 = time.time()
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"  [nuitka] Shared runtime FAILED ({elapsed:.1f}s)")
        log_path = Path(output_dir) / "_launcher.nuitka.log"
        log_path.write_text(result.stdout)
        print(f"           Log: {log_path}")
        launcher_src.unlink(missing_ok=True)
        return

    print(f"  [nuitka] Shared runtime OK ({elapsed:.1f}s)")

    # Move launcher dist to shared_dist
    launcher_dist = Path(output_dir) / "_launcher.dist"
    if shared_dist.exists():
        shutil.rmtree(shared_dist)
    launcher_dist.rename(shared_dist)

    # Clean build artifacts
    launcher_build = Path(output_dir) / "_launcher.build"
    if launcher_build.exists():
        shutil.rmtree(launcher_build)
    launcher_src.unlink(missing_ok=True)

    # --- Step 3: Compile all mains as modules (incremental) ---
    manifest = load_hash_manifest(output_dir)
    new_manifest = dict(manifest)

    temp_dir = Path(output_dir) / "_temp_preprocess"
    module_output = Path(output_dir) / "_modules"
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(module_output, exist_ok=True)

    # Preprocess and filter unchanged modules
    preprocessed = []
    skipped = 0
    for f in mains:
        qname = qualified_module_name(f, mains_dir)
        changed, file_hash = needs_rebuild(f, output_dir, manifest)
        if not changed:
            # Check that the compiled output still exists
            ext = ".pyd" if sys.platform == "win32" else ".so"
            # Nuitka names output after the top-level package or module
            search_stem = qname.split(".")[0]
            compiled = list(shared_dist.glob(f"{search_stem}*{ext}"))
            if compiled:
                skipped += 1
                new_manifest[str(f)] = file_hash
                continue
        prep = preprocess_main_for_module(f, temp_dir, mains_dir)
        preprocessed.append((prep, f, file_hash, qname))

    print(f"\n  Step 3/4: Compiling {len(preprocessed)} modules "
          f"({skipped} unchanged, skipped) ...")

    ok_count = 0
    fail_count = 0
    failed = []
    total_cores = get_workers()
    parallel_procs = max(1, min(total_cores // 2, 4))
    jobs_per_proc = max(1, total_cores // parallel_procs)

    if preprocessed:
        if parallel_procs <= 1:
            for prep, orig, file_hash, qname in preprocessed:
                success, name = nuitka_compile_module(
                    prep, str(module_output), jobs=total_cores
                )
                if success:
                    ok_count += 1
                    new_manifest[str(orig)] = file_hash
                else:
                    fail_count += 1
                    failed.append(name)
        else:
            with ProcessPoolExecutor(max_workers=parallel_procs) as pool:
                futures = {}
                for prep, orig, file_hash, qname in preprocessed:
                    fut = pool.submit(
                        nuitka_compile_module, prep, str(module_output),
                        jobs=jobs_per_proc,
                    )
                    futures[fut] = (orig, file_hash)
                for fut in as_completed(futures):
                    orig, file_hash = futures[fut]
                    success, name = fut.result()
                    if success:
                        ok_count += 1
                        new_manifest[str(orig)] = file_hash
                    else:
                        fail_count += 1
                        failed.append(name)

    save_hash_manifest(output_dir, new_manifest)
    print(f"  [nuitka] Modules: {ok_count} compiled, {skipped} skipped, "
          f"{fail_count} failed")

    # --- Step 4: Assemble output ---
    print(f"\n  Step 4/4: Assembling output ...")

    # Copy compiled modules (.so / .pyd) into shared_dist, preserving structure
    copied = 0
    for ext in ("*.so", "*.pyd"):
        for f in module_output.rglob(ext):
            rel = f.relative_to(module_output)
            dest = shared_dist / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            copied += 1
    print(f"           Copied {copied} compiled modules into shared_dist/")

    # Create per-main wrapper scripts
    scripts_dir = Path(output_dir) / "bin"
    os.makedirs(scripts_dir, exist_ok=True)

    for main_file in mains:
        qname = qualified_module_name(main_file, mains_dir)
        # Use the relative path as wrapper name (e.g. pkg1/foo -> pkg1_foo)
        wrapper_name = qname.replace(".", "_")
        if wrapper_name.endswith("___init__"):
            # pkg.__init__ -> just use pkg name
            wrapper_name = wrapper_name[:-len("___init__")]

        # Unix wrapper
        wrapper = scripts_dir / wrapper_name
        wrapper.write_text(
            f'#!/bin/sh\n'
            f'DIR="$(cd "$(dirname "$0")" && pwd)"\n'
            f'exec "$DIR/../shared_dist/_launcher" {qname} "$@"\n'
        )
        wrapper.chmod(0o755)

        # Windows wrapper
        wrapper_bat = scripts_dir / f"{wrapper_name}.bat"
        wrapper_bat.write_text(
            f'@echo off\r\n'
            f'"%~dp0\\..\\shared_dist\\_launcher.exe" {qname} %*\r\n'
        )

    print(f"           Created {len(mains)} wrappers in bin/")

    # Cleanup temp dirs
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    if module_output.exists():
        shutil.rmtree(module_output)
    # Clean per-module .build dirs that Nuitka leaves behind
    for d in Path(output_dir).glob("*.build"):
        if d.is_dir():
            shutil.rmtree(d)

    print(f"\n[Nuitka] Done: {ok_count} succeeded, {fail_count} failed")
    print(f"         Runtime:  {shared_dist}/")
    print(f"         Wrappers: {scripts_dir}/")
    if failed:
        print("[Nuitka] Failed files:")
        for f in failed:
            print(f"  - {f}")


def integrate_libs_to_shared(output_dir):
    """Copy Cython-compiled libs into the shared Nuitka dist.

    Called automatically in 'all' mode so the shared_dist is self-contained.
    """
    shared_dist = Path(output_dir) / "shared_dist"
    libs_compiled = Path(output_dir) / "libs_compiled"

    if not shared_dist.exists() or not libs_compiled.exists():
        return

    copied = 0
    for f in libs_compiled.rglob("*"):
        if f.is_file():
            rel = f.relative_to(libs_compiled)
            dest = shared_dist / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            copied += 1

    print(f"\n  [integrate] Copied {copied} compiled lib files into shared_dist/")


# ============================================================
# Cython compilation
# ============================================================

def generate_setup_py(py_files, build_dir):
    """Generate a temporary setup.py for Cython compilation."""
    setup_path = Path(build_dir) / "_cython_setup.py"
    ext_modules = []
    for f in py_files:
        module_name = str(f).replace(os.sep, ".").replace("/", ".")
        if module_name.endswith(".py"):
            module_name = module_name[:-3]
        ext_modules.append((module_name, str(f)))

    lines = [
        "from setuptools import setup",
        "from Cython.Build import cythonize",
        "from setuptools import Extension",
        "",
        "extensions = [",
    ]
    for mod_name, src_path in ext_modules:
        lines.append(f'    Extension("{mod_name}", ["{src_path}"]),')
    lines.append("]")
    lines.append("")
    lines.append("setup(")
    lines.append('    name="compiled_libs",')
    lines.append("    ext_modules=cythonize(")
    lines.append("        extensions,")
    lines.append("        compiler_directives={")
    lines.append("            'language_level': '3',")
    lines.append("            'boundscheck': False,")
    lines.append("            'wraparound': False,")
    lines.append("        },")
    lines.append(f"        nthreads={get_workers()},")
    lines.append("    ),")
    lines.append(")")

    setup_path.write_text("\n".join(lines))
    return setup_path


def cython_compile_batch(py_files, libs_dir, output_dir):
    """Compile all library files with Cython using a generated setup.py."""
    build_dir = Path(output_dir) / "_cython_build"
    os.makedirs(build_dir, exist_ok=True)

    setup_py = generate_setup_py(py_files, build_dir)

    print(f"  [cython] Running setup.py build_ext ...")
    t0 = time.time()
    result = subprocess.run(
        [
            sys.executable, str(setup_py),
            "build_ext",
            "--inplace",
            f"--build-temp={build_dir}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"  [cython] Build FAILED ({elapsed:.1f}s)")
        log_path = build_dir / "cython_build.log"
        log_path.write_text(result.stdout)
        print(f"           Log: {log_path}")
        print(f"           Last 20 lines:")
        for line in result.stdout.strip().splitlines()[-20:]:
            print(f"           {line}")
        return False

    print(f"  [cython] Build OK ({elapsed:.1f}s)")
    return True


def copy_compiled_to_output(libs_dir, output_dir):
    """Copy compiled .so/.pyd files to output, preserving directory structure."""
    libs_path = Path(libs_dir)
    out_path = Path(output_dir) / "libs_compiled"

    # Find compiled extensions
    so_files = list(libs_path.rglob("*.so")) + list(libs_path.rglob("*.pyd"))

    if not so_files:
        print("  [cython] WARNING: No compiled .so/.pyd files found")
        return

    for so in so_files:
        rel = so.relative_to(libs_path)
        dest = out_path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(so, dest)

    # Copy __init__.py files (needed for packages) and non-.py files
    for f in libs_path.rglob("*"):
        if f.is_file():
            rel = f.relative_to(libs_path)
            dest = out_path / rel
            if f.name == "__init__.py":
                # Keep __init__.py but can optionally compile it too
                if not dest.exists():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(f, dest)
            elif f.suffix not in (".py", ".pyc", ".c", ".so", ".pyd"):
                # Copy non-Python resource files
                if not dest.exists():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(f, dest)

    print(f"  [cython] Copied {len(so_files)} compiled files to {out_path}")


def cleanup_cython_artifacts(libs_dir):
    """Remove .c and .so/.pyd files generated in-place by Cython."""
    libs_path = Path(libs_dir)
    removed = 0
    for pattern in ("*.c", "*.so", "*.pyd"):
        for f in libs_path.rglob(pattern):
            f.unlink()
            removed += 1
    # Remove build directories
    for d in libs_path.rglob("__pycache__"):
        if d.is_dir():
            shutil.rmtree(d)
    return removed


def build_cython(libs_dir, output_dir):
    """Compile all library files with Cython."""
    check_tool("cython")

    py_files = find_py_files(libs_dir)
    if not py_files:
        print(f"[WARN] No .py files found in '{libs_dir}'")
        return

    print(f"\n{'='*60}")
    print(f"[Cython] Compiling {len(py_files)} library file(s)")
    print(f"         Workers: {get_workers()}")
    print(f"{'='*60}\n")

    os.makedirs(output_dir, exist_ok=True)

    success = cython_compile_batch(py_files, libs_dir, output_dir)
    if success:
        copy_compiled_to_output(libs_dir, output_dir)

    # Clean up .c and .so files generated in the source tree
    cleaned = cleanup_cython_artifacts(libs_dir)
    print(f"  [cython] Cleaned {cleaned} build artifact(s) from source tree")

    # Clean up temporary setup.py and build dir
    build_dir = Path(output_dir) / "_cython_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)


# ============================================================
# Clean
# ============================================================

def clean(output_dir):
    """Remove all build artifacts."""
    targets = [
        output_dir,
        "build",
        "*.egg-info",
    ]
    removed = 0
    for target in targets:
        for p in glob.glob(target):
            p = Path(p)
            if p.is_dir():
                shutil.rmtree(p)
                print(f"  Removed directory: {p}")
                removed += 1
            elif p.is_file():
                p.unlink()
                print(f"  Removed file: {p}")
                removed += 1

    # Clean stray .c, .so, .pyd in source dirs
    for d in [MAINS_DIR, LIBS_DIR]:
        if Path(d).exists():
            for pattern in ("*.c", "*.so", "*.pyd"):
                for f in Path(d).rglob(pattern):
                    f.unlink()
                    print(f"  Removed: {f}")
                    removed += 1

    print(f"\n  Cleaned {removed} item(s)")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Compile Python source with Nuitka and/or Cython",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python build.py nuitka                # shared-runtime mode (fast, small)
    python build.py nuitka -s per-script  # legacy standalone-per-script mode
    python build.py cython                # compile libs/ with Cython
    python build.py all                   # both (shared Nuitka + Cython)
    python build.py clean                 # remove build artifacts
    python build.py nuitka -m src/        # custom mains directory
    python build.py cython -l pkg/        # custom libs directory
        """,
    )
    parser.add_argument(
        "mode",
        choices=["nuitka", "cython", "all", "clean"],
        help="Build mode",
    )
    parser.add_argument(
        "-m", "--mains-dir",
        default=MAINS_DIR,
        help=f"Directory with main scripts (default: {MAINS_DIR})",
    )
    parser.add_argument(
        "-l", "--libs-dir",
        default=LIBS_DIR,
        help=f"Directory with library modules (default: {LIBS_DIR})",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=OUTPUT_DIR,
        help=f"Output directory (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=0,
        help="Number of parallel workers (default: auto)",
    )
    parser.add_argument(
        "-s", "--strategy",
        choices=["shared", "per-script"],
        default=NUITKA_STRATEGY,
        help=f"Nuitka build strategy (default: {NUITKA_STRATEGY})",
    )
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Ignore incremental cache and rebuild all modules",
    )

    args = parser.parse_args()

    global WORKERS
    if args.jobs > 0:
        WORKERS = args.jobs

    if args.mode == "clean":
        print("[Clean] Removing build artifacts ...")
        clean(args.output_dir)
        return

    # Clear incremental cache if forced
    if args.force_rebuild:
        manifest_path = Path(args.output_dir) / HASH_MANIFEST
        if manifest_path.exists():
            manifest_path.unlink()
            print("[Info] Cleared incremental build cache")

    # Validate directories exist
    if args.mode in ("nuitka", "all"):
        if not Path(args.mains_dir).is_dir():
            print(f"[ERROR] Mains directory not found: {args.mains_dir}")
            print(f"        Create it or use -m to specify a different path")
            sys.exit(1)

    if args.mode in ("cython", "all"):
        if not Path(args.libs_dir).is_dir():
            print(f"[ERROR] Libs directory not found: {args.libs_dir}")
            print(f"        Create it or use -l to specify a different path")
            sys.exit(1)

    t_start = time.time()

    if args.mode in ("nuitka", "all"):
        if args.strategy == "shared":
            build_nuitka_shared(args.mains_dir, args.libs_dir, args.output_dir)
        else:
            build_nuitka_per_script(args.mains_dir, args.output_dir)

    if args.mode in ("cython", "all"):
        build_cython(args.libs_dir, args.output_dir)

    # In 'all' + 'shared' mode, integrate Cython libs into shared_dist
    if args.mode == "all" and args.strategy == "shared":
        integrate_libs_to_shared(args.output_dir)

    elapsed = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"Total build time: {elapsed:.1f}s")
    print(f"Output directory:  {args.output_dir}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
