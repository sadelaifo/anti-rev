#!/usr/bin/env python3
"""Diff two dlsym-interceptor logs (plaintext run vs encrypted run) and report
symbols whose *owning DSO* changed — i.e. dlsym() ownership flips that
LD_DEBUG=bindings structurally cannot see.

Log line format (produced by dlsym_intercept.c), tab-separated:
    <caller_basename>\t<DEFAULT|NEXT|HANDLE>\t<symbol>\t<owner_basename>

Usage:
    symdiff.py PLAIN ENC [--include-shim]

PLAIN and ENC are each either a single log file or a directory of logs (one
file per process, e.g. ANTIREV_DLSYM_LOG=<dir>/<service>); a directory is
merged across all its files.  Owner basenames are compared directly: a
memfd/daemon-loaded lib is reported by dladdr via its symlink path whose
basename is the soname, so it lines up with the plaintext disk path.

Exit status: 1 if any ownership flip was found (so it works as a CI gate),
else 0.
"""
import argparse
import glob
import os
import sys


def load(path, include_shim):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*")))
    else:
        files = [path]

    # key = (caller, kind, symbol) -> set of owner basenames seen
    table = {}
    for f in files:
        if not os.path.isfile(f):
            continue
        with open(f, errors="replace") as fh:
            for ln in fh:
                parts = ln.rstrip("\n").split("\t")
                if len(parts) != 4:
                    continue
                caller, kind, sym, owner = parts
                if not include_shim and caller.startswith("antirev_shim"):
                    continue
                table.setdefault((caller, kind, sym), set()).add(owner)
    return table


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plain", help="plaintext-run log file or directory")
    ap.add_argument("enc", help="encrypted-run log file or directory")
    ap.add_argument("--include-shim", action="store_true",
                    help="also report lookups made by antirev_shim itself")
    args = ap.parse_args()

    p = load(args.plain, args.include_shim)
    e = load(args.enc, args.include_shim)

    changed = []
    for key in sorted(p.keys() & e.keys()):
        if p[key] != e[key]:
            changed.append((key, p[key], e[key]))

    only_p = len(p.keys() - e.keys())
    only_e = len(e.keys() - p.keys())

    for (caller, kind, sym), po, eo in changed:
        print(f"[CHANGED] caller={caller} {kind} symbol={sym}")
        print(f"          plain -> {','.join(sorted(po))}")
        print(f"          enc   -> {','.join(sorted(eo))}")

    print()
    print(f"== dlsym ownership changed (investigate): {len(changed)}")
    print(f"== only-in-plain / only-in-enc lookups:   {only_p} / {only_e}")

    sys.exit(1 if changed else 0)


if __name__ == "__main__":
    main()
