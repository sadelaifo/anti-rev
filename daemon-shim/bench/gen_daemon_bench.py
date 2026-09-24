#!/usr/bin/env python3
"""
Generate a daemon-mode benchmark with 500 libs and 130 exes, each ~5MB.

Creates bench/daemon_project/ with:
  libs/lib_0001.so .. lib_0500.so   (each ~5MB)
  exes/exe_0001    .. exe_0130      (each ~5MB)

Each lib exports a trivial function; bulk comes from an embedded binary blob.
Each exe is a noop (immediate exit) to isolate startup overhead.
"""

import os
import subprocess
import sys
import tempfile
import shutil

N_LIBS = 500
N_EXES = 130
PAD_MB = 5        # target size per file in MB
PAD_BYTES = PAD_MB * 1024 * 1024

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "daemon_project")
LIBS_DIR = os.path.join(BASE, "libs")
EXES_DIR = os.path.join(BASE, "exes")
SRC_DIR  = os.path.join(BASE, "src")


def generate_padding_object():
    """Create a ~5MB ELF object from random data, reusable across all targets."""
    pad_bin = os.path.join(BASE, "padding.bin")
    pad_obj = os.path.join(BASE, "padding.o")

    print(f"[gen] Creating {PAD_MB}MB padding blob...")
    # Use /dev/urandom for realistic encryption workload (incompressible)
    with open(pad_bin, 'wb') as f:
        f.write(os.urandom(PAD_BYTES))

    subprocess.check_call([
        'objcopy', '-I', 'binary', '-O', 'elf64-x86-64', '-B', 'i386',
        pad_bin, pad_obj
    ])
    os.remove(pad_bin)
    return pad_obj


def generate_libs(pad_obj):
    """Generate 500 shared libraries, each ~5MB."""
    print(f"[gen] Generating {N_LIBS} library sources...")
    lib_src_dir = os.path.join(SRC_DIR, "libs")
    os.makedirs(lib_src_dir, exist_ok=True)

    # Write all C sources first
    for i in range(1, N_LIBS + 1):
        src = os.path.join(lib_src_dir, f"lib_{i:04d}.c")
        with open(src, 'w') as f:
            f.write(f'int lib_{i:04d}_func(int x) {{ return x + {i}; }}\n')

    # Compile all in parallel using make
    makefile = os.path.join(lib_src_dir, "Makefile")
    targets = []
    rules = []
    for i in range(1, N_LIBS + 1):
        so = f"../../libs/lib_{i:04d}.so"
        src = f"lib_{i:04d}.c"
        targets.append(so)
        rules.append(
            f'{so}: {src}\n'
            f'\t$(CC) -shared -fPIC -Wl,-soname,lib_{i:04d}.so '
            f'-o $@ $< {pad_obj}\n'
        )

    with open(makefile, 'w') as f:
        f.write(f'CC = gcc\n\n')
        f.write(f'all: {" ".join(targets)}\n\n')
        for r in rules:
            f.write(r + '\n')

    print(f"[gen] Compiling {N_LIBS} shared libraries (parallel)...")
    subprocess.check_call(
        ['make', '-j', str(os.cpu_count()), '-f', makefile],
        cwd=lib_src_dir, stdout=subprocess.DEVNULL)


def generate_exes(pad_obj):
    """Generate 130 executables, each ~5MB. Noop mains for pure startup measurement."""
    print(f"[gen] Generating {N_EXES} executable sources...")
    exe_src_dir = os.path.join(SRC_DIR, "exes")
    os.makedirs(exe_src_dir, exist_ok=True)

    for i in range(1, N_EXES + 1):
        src = os.path.join(exe_src_dir, f"exe_{i:04d}.c")
        with open(src, 'w') as f:
            # Large static array to bulk up the exe to ~5MB
            # Use 'used' attribute so the linker keeps it
            f.write(
                f'__attribute__((used)) static const char padding[{PAD_BYTES}];\n'
                'int main(void) { return 0; }\n'
            )

    makefile = os.path.join(exe_src_dir, "Makefile")
    targets = []
    rules = []
    for i in range(1, N_EXES + 1):
        exe = f"../../exes/exe_{i:04d}"
        src = f"exe_{i:04d}.c"
        targets.append(exe)
        rules.append(
            f'{exe}: {src}\n'
            f'\t$(CC) -O2 -o $@ $<\n'
        )

    with open(makefile, 'w') as f:
        f.write(f'CC = gcc\n\n')
        f.write(f'all: {" ".join(targets)}\n\n')
        for r in rules:
            f.write(r + '\n')

    print(f"[gen] Compiling {N_EXES} executables (parallel)...")
    subprocess.check_call(
        ['make', '-j', str(os.cpu_count()), '-f', makefile],
        cwd=exe_src_dir, stdout=subprocess.DEVNULL)


def main():
    if os.path.isdir(BASE):
        print(f"[gen] Removing old {BASE}...")
        shutil.rmtree(BASE)

    os.makedirs(LIBS_DIR, exist_ok=True)
    os.makedirs(EXES_DIR, exist_ok=True)
    os.makedirs(SRC_DIR, exist_ok=True)

    pad_obj = generate_padding_object()
    generate_libs(pad_obj)
    generate_exes(pad_obj)

    # Verify sizes
    lib_sizes = [os.path.getsize(os.path.join(LIBS_DIR, f))
                 for f in os.listdir(LIBS_DIR)]
    exe_sizes = [os.path.getsize(os.path.join(EXES_DIR, f))
                 for f in os.listdir(EXES_DIR)]

    total_mb = (sum(lib_sizes) + sum(exe_sizes)) / (1024 * 1024)
    avg_lib = sum(lib_sizes) / len(lib_sizes) / (1024 * 1024)
    avg_exe = sum(exe_sizes) / len(exe_sizes) / (1024 * 1024)

    print(f"\n[gen] Done.")
    print(f"  {len(lib_sizes)} libs, avg {avg_lib:.1f} MB each")
    print(f"  {len(exe_sizes)} exes, avg {avg_exe:.1f} MB each")
    print(f"  Total: {total_mb:.1f} MB ({total_mb/1024:.2f} GB)")
    print(f"  Output: {BASE}")


if __name__ == "__main__":
    main()
