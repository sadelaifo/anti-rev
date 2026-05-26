#!/usr/bin/env python3
"""Compile antirev_client.py into a native extension module (.so on
Linux, .pyd on Windows) via Cython.

Why this exists
---------------
Shipping ``antirev_client.py`` as plain Python on the target host
exposes the daemon protocol, the import/ctypes hook strategy, and the
internal magic strings to anyone with read access — `cat
antirev_client.py` and the integration surface is yours to see.

Compiling to a native extension does two things:

  1. Removes the .py file entirely (deployment ships only the .so).
  2. Pushes the reverse-engineering work from "read 700 lines of Python"
     to "disassemble a .so" — not bullet-proof, but a meaningful step
     up from plaintext source.

This is the same trick the project uses for the customer's own Python
code via ``encryptor/build.py``; this script is the equivalent for
antirev's own client.

Requirements
------------
  - cython (``pip install cython``)
  - a C compiler reachable on PATH (gcc/clang on Linux, MSVC or MinGW
    on Windows)
  - Python development headers (e.g., ``python3-dev`` apt package)

The compiled .so is arch-specific — run this script on each target
architecture you ship to (or use cross-compilation toolchains
explicitly).

Usage
-----
  python tools/build_antirev_client.py
  python tools/build_antirev_client.py --out /path/to/output_dir
  python tools/build_antirev_client.py --clean

Output (default):
  tools/antirev_client.cpython-3X-<arch>-linux-gnu.so   (Linux)
  tools/antirev_client.cp3X-<arch>.pyd                  (Windows)

Deploy by copying the produced .so + tools/antirev.pth into the target
Python's site-packages directory.  The .py source is no longer needed
at runtime once the .so is in place — Python prefers compiled
extensions over .py with the same base name.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "antirev_client.py"
DEFAULT_OUT = HERE
BUILD_TEMP_NAME = "_cython_build"


def check_prereqs() -> None:
    try:
        import Cython  # noqa: F401
    except ImportError:
        sys.exit(
            "error: cython is not installed.\n"
            "  pip install cython"
        )
    if not SOURCE.exists():
        sys.exit("error: source not found: {}".format(SOURCE))


def write_setup(setup_path: Path, source: Path, build_temp: Path) -> None:
    """Write a temporary setup.py invoking cythonize() on antirev_client.py.

    Kept as a generated file rather than an inline module so build_ext
    can find a real script.  We tear it down after the build.
    """
    setup_path.write_text(
        (
            "from setuptools import setup\n"
            "from Cython.Build import cythonize\n"
            "setup(\n"
            "    ext_modules=cythonize(\n"
            "        [r{src!r}],\n"
            "        compiler_directives={{\n"
            "            'language_level': '3',\n"
            "            'boundscheck': False,\n"
            "            'wraparound': False,\n"
            "        }},\n"
            "        build_dir=r{build_dir!r},\n"
            "    ),\n"
            ")\n"
        ).format(src=str(source), build_dir=str(build_temp)),
        encoding="utf-8",
    )


def run_compile(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    build_temp = out_dir / BUILD_TEMP_NAME
    build_temp.mkdir(parents=True, exist_ok=True)
    setup_path = build_temp / "_setup.py"
    write_setup(setup_path, SOURCE, build_temp)

    # Cython's setup.py drops the .so beside the source in --inplace mode.
    # We tell setuptools to build_temp into our scratch dir so the build
    # leaves nothing intermediate in tools/.
    cmd = [
        sys.executable,
        str(setup_path),
        "build_ext",
        "--inplace",
        "--build-temp={}".format(build_temp),
    ]
    print("[build] " + " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(out_dir), capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        sys.exit("error: cython build failed (rc={})".format(proc.returncode))

    # Find the produced extension.  Cython names it after the source
    # module + ABI tag.
    exts = list(out_dir.glob("antirev_client*.so")) + \
        list(out_dir.glob("antirev_client*.pyd"))
    if not exts:
        sys.exit("error: build succeeded but no .so/.pyd produced")
    return exts[0]


def cleanup_build_artifacts(out_dir: Path) -> None:
    """Remove the temp setup.py, build dir, and any .c/.html that
    cythonize() drops next to the source."""
    build_temp = out_dir / BUILD_TEMP_NAME
    if build_temp.exists():
        shutil.rmtree(build_temp, ignore_errors=True)
    # cythonize may also drop antirev_client.c beside the source — we
    # don't want it shipped or committed.
    for stray in (HERE / "antirev_client.c",
                  HERE / "antirev_client.html"):
        if stray.exists():
            stray.unlink()
    # And the build/ scratch dir setuptools sometimes makes.
    build_scratch = out_dir / "build"
    if build_scratch.exists() and build_scratch.is_dir():
        shutil.rmtree(build_scratch, ignore_errors=True)


def cmd_clean(out_dir: Path) -> None:
    cleanup_build_artifacts(out_dir)
    removed = 0
    for ext in ("*.so", "*.pyd"):
        for f in out_dir.glob("antirev_client" + ext.lstrip("*")):
            f.unlink()
            removed += 1
            print("[clean] removed {}".format(f.name))
    print("[clean] done ({} ext modules removed)".format(removed))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT,
                   help="output directory (default: tools/)")
    p.add_argument("--clean", action="store_true",
                   help="remove produced .so/.pyd and build artifacts, then exit")
    p.add_argument("--keep-build", action="store_true",
                   help="don't delete the intermediate _cython_build/ dir "
                        "(useful for debugging build failures)")
    args = p.parse_args()

    out_dir = args.out.resolve()
    if args.clean:
        cmd_clean(out_dir)
        return

    check_prereqs()
    ext = run_compile(out_dir)
    if not args.keep_build:
        cleanup_build_artifacts(out_dir)

    size = ext.stat().st_size
    print()
    print("[OK] compiled: {}".format(ext))
    print("     size:     {:,} bytes".format(size))
    print()
    print("Deploy:")
    print("  cp {ext} <target-site-packages>/".format(ext=ext))
    print("  cp {pth} <target-site-packages>/".format(pth=HERE / "antirev.pth"))
    print()
    print("Then any Python script under any directory listed in the")
    print("ANTIREV_DIRS env var will auto-activate antirev with no")
    print("source change.  See PYTHON_PROTECTION.md for details.")


if __name__ == "__main__":
    main()
