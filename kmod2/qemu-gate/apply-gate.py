#!/usr/bin/env python3
# apply-gate.py — drop the qemu-user decrypt gate into a qemu source tree.
#
#   python3 apply-gate.py /path/to/qemu-src
#
# Copies the three new files (arev_uapi.h, arev_gate.h, arev_gate.c) into
# <qemu>/linux-user/ and applies three small anchor-based edits to elfload.c,
# syscall.c and meson.build.  Idempotent: re-running skips edits already present.
# Anchors match qemu 11.0.0 linux-user; if an anchor is missing the script errors
# rather than corrupting the file (adapt the anchor for a different qemu version).
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NEW_FILES = ["arev_uapi.h", "arev_gate.h", "arev_gate.c"]

# (file, must-already-contain marker, anchor, replacement)
EDITS = [
    ("linux-user/meson.build",
     "'arev_gate.c',",
     "linux_user_ss.add(files(\n  'elfload.c',",
     "linux_user_ss.add(files(\n  'arev_gate.c',\n  'elfload.c',"),

    ("linux-user/elfload.c",
     '#include "arev_gate.h"',
     '#include "qemu.h"\n#include "user/tswap-target.h"',
     '#include "qemu.h"\n#include "user/tswap-target.h"\n#include "arev_gate.h"'),

    ("linux-user/elfload.c",
     "arev_gate_set_guest(bprm->filename);",
     "    memset(&interp_info, 0, sizeof(interp_info));\n"
     "#ifdef TARGET_MIPS\n"
     "    interp_info.fp_abi = MIPS_ABI_FP_UNKNOWN;\n"
     "#endif\n\n"
     "    load_elf_image(bprm->filename, &bprm->src, info, &ehdr, &elf_interpreter);",
     "    memset(&interp_info, 0, sizeof(interp_info));\n"
     "#ifdef TARGET_MIPS\n"
     "    interp_info.fp_abi = MIPS_ABI_FP_UNKNOWN;\n"
     "#endif\n\n"
     "    /* qemu-user decrypt gate: authorize this guest from its binary's\n"
     "     * vendor signature (via /dev/vcachefs).  No-op if the gate is off. */\n"
     "    arev_gate_set_guest(bprm->filename);\n\n"
     "    load_elf_image(bprm->filename, &bprm->src, info, &ehdr, &elf_interpreter);"),

    ("linux-user/syscall.c",
     '#include "arev_gate.h"',
     '#include "qemu.h"\n#include "gdbstub/user.h"',
     '#include "qemu.h"\n#include "gdbstub/user.h"\n#include "arev_gate.h"'),

    ("linux-user/syscall.c",
     "fd = arev_gate_open(dirfd, host_pathname, flags);",
     "    int fd = maybe_do_fake_open(cpu_env, dirfd, pathname, flags, mode, 0, safe);\n"
     "    if (fd > -2) {\n"
     "        return fd;\n"
     "    }\n\n"
     "    if (safe) {\n"
     "        return safe_openat(dirfd, path(pathname), flags, mode);\n"
     "    } else {\n"
     "        return openat(dirfd, path(pathname), flags, mode);\n"
     "    }\n"
     "}",
     "    const char *host_pathname;\n"
     "    int fd = maybe_do_fake_open(cpu_env, dirfd, pathname, flags, mode, 0, safe);\n"
     "    if (fd > -2) {\n"
     "        return fd;\n"
     "    }\n\n"
     "    /* path() may use a static/thread buffer — resolve once and reuse. */\n"
     "    host_pathname = path(pathname);\n\n"
     "    /* Per-guest decrypt gate: unauthorized guest reading a protected file\n"
     "     * gets keyless ciphertext (fd>=0) or is denied (-1); else -2. */\n"
     "    fd = arev_gate_open(dirfd, host_pathname, flags);\n"
     "    if (fd > -2) {\n"
     "        return fd;\n"
     "    }\n\n"
     "    if (safe) {\n"
     "        return safe_openat(dirfd, host_pathname, flags, mode);\n"
     "    } else {\n"
     "        return openat(dirfd, host_pathname, flags, mode);\n"
     "    }\n"
     "}"),

    ("linux-user/syscall.c",
     "afd = arev_gate_open(dirfd, host_pathname, how.flags);",
     "        ret = get_errno(safe_openat2(dirfd, host_pathname, &how,\n"
     "                                     sizeof(struct open_how_ver0)));\n"
     "    }",
     "        int afd = arev_gate_open(dirfd, host_pathname, how.flags);\n"
     "        if (afd > -2) {\n"
     "            ret = get_errno(afd);\n"
     "        } else {\n"
     "            ret = get_errno(safe_openat2(dirfd, host_pathname, &how,\n"
     "                                         sizeof(struct open_how_ver0)));\n"
     "        }\n"
     "    }"),
]


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: apply-gate.py <qemu-src-dir>")
    qemu = sys.argv[1]
    lu = os.path.join(qemu, "linux-user")
    if not os.path.isdir(lu):
        sys.exit(f"[error] not a qemu source tree (no linux-user/): {qemu}")

    for f in NEW_FILES:
        shutil.copy(os.path.join(HERE, f), os.path.join(lu, f))
        print(f"[copy] linux-user/{f}")

    for rel, marker, anchor, repl in EDITS:
        path = os.path.join(qemu, rel)
        src = open(path, encoding="utf-8").read()
        if marker in src:
            print(f"[skip] {rel}: already applied")
            continue
        if anchor not in src:
            sys.exit(f"[error] {rel}: anchor not found (qemu version mismatch?)\n"
                     f"        anchor begins: {anchor.splitlines()[0]!r}")
        src = src.replace(anchor, repl, 1)
        open(path, "w", encoding="utf-8").write(src)
        print(f"[edit] {rel}")

    print("done. Now build qemu-user as usual (configure --target-list=aarch64-linux-user; make).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
