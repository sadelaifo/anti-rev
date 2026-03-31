#!/usr/bin/env python3
"""
Build script to compile Python source files using Nuitka or Cython.

Usage:
    python build.py nuitka              # compile main programs with Nuitka
    python build.py cython              # compile libraries with Cython
    python build.py all                 # Nuitka for mains + Cython for libs
    python build.py clean               # remove build artifacts

Configure MAINS_DIR, LIBS_DIR, and other settings below.
"""

import argparse
import glob
import multiprocessing
import os
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
# Nuitka compilation
# ============================================================

def nuitka_compile_one(main_file, output_dir):
    """Compile a single main script with Nuitka."""
    main_file = Path(main_file)
    name = main_file.stem
    target_dir = Path(output_dir) / f"{name}.dist"

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--follow-imports",
        f"--output-dir={output_dir}",
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


def build_nuitka(mains_dir, output_dir):
    """Compile all main scripts with Nuitka."""
    check_tool("nuitka")

    mains = find_py_files(mains_dir)
    if not mains:
        print(f"[WARN] No .py files found in '{mains_dir}'")
        return

    print(f"\n{'='*60}")
    print(f"[Nuitka] Compiling {len(mains)} main program(s)")
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
    python build.py nuitka          # compile mains/ with Nuitka
    python build.py cython          # compile libs/ with Cython
    python build.py all             # both
    python build.py clean           # remove build artifacts
    python build.py nuitka -m src/  # custom mains directory
    python build.py cython -l pkg/  # custom libs directory
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

    args = parser.parse_args()

    global WORKERS
    if args.jobs > 0:
        WORKERS = args.jobs

    if args.mode == "clean":
        print("[Clean] Removing build artifacts ...")
        clean(args.output_dir)
        return

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
        build_nuitka(args.mains_dir, args.output_dir)

    if args.mode in ("cython", "all"):
        build_cython(args.libs_dir, args.output_dir)

    elapsed = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"Total build time: {elapsed:.1f}s")
    print(f"Output directory:  {args.output_dir}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
