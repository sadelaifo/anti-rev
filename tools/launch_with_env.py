#!/usr/bin/env python3
"""
launch_with_env — launch a binary with a captured environment.

Useful for reproducing bugs that depend on inherited env. Capture the env
of a running process once:

    cat /proc/<PID>/environ > /tmp/foo.env        # NUL-separated (native)
    # or:
    tr '\\0' '\\n' < /proc/<PID>/environ > /tmp/foo.env   # LF-separated

Then launch a target with exactly that env (nothing inherited from your shell):

    launch_with_env.py /tmp/foo.env /path/to/Foo [args...]

Options:
    --keep VAR        Also keep VAR from current shell env (repeatable)
                      Useful for PATH, HOME, DISPLAY if missing from capture.
    --set VAR=VAL     Override or add VAR=VAL (repeatable)
    --cwd PATH        chdir before exec (default: inherit current cwd)
    --print           Print the final env and exit without exec
"""
from __future__ import annotations

import argparse
import os
import sys


def parse_env_file(path: str) -> dict[str, str]:
    """Read env file. Auto-detects NUL-separated (/proc/PID/environ raw) vs LF."""
    with open(path, 'rb') as f:
        raw = f.read()

    sep = b'\0' if b'\0' in raw else b'\n'
    env = {}
    for entry in raw.split(sep):
        if not entry:
            continue
        text = entry.decode('utf-8', errors='replace')
        if '=' not in text:
            continue
        k, _, v = text.partition('=')
        env[k] = v
    return env


def main():
    ap = argparse.ArgumentParser(
        description="Launch a binary with a captured /proc/PID/environ file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("env_file", help="Captured env file (NUL- or LF-separated)")
    ap.add_argument("argv", nargs='+', help="Target binary and its arguments")
    ap.add_argument("--keep", action='append', default=[], metavar="VAR",
                    help="Keep VAR from current shell env (repeatable)")
    ap.add_argument("--set", action='append', default=[], metavar="VAR=VAL",
                    dest='set_vars', help="Override or add VAR=VAL (repeatable)")
    ap.add_argument("--cwd", help="chdir to this path before exec")
    ap.add_argument("--print", action='store_true',
                    help="Print final env and exit without exec")
    args = ap.parse_args()

    env = parse_env_file(args.env_file)

    for var in args.keep:
        if var in os.environ:
            env[var] = os.environ[var]

    for spec in args.set_vars:
        if '=' not in spec:
            sys.exit(f"[error] --set needs VAR=VAL, got: {spec}")
        k, _, v = spec.partition('=')
        env[k] = v

    if args.print:
        for k in sorted(env):
            print(f"{k}={env[k]}")
        print(f"\n[info] {len(env)} vars, would exec: {args.argv}", file=sys.stderr)
        return 0

    if args.cwd:
        os.chdir(args.cwd)

    prog = args.argv[0]
    print(f"[launch_with_env] exec {prog}  ({len(env)} env vars)", file=sys.stderr)
    try:
        os.execvpe(prog, args.argv, env)
    except OSError as e:
        sys.exit(f"[error] exec failed: {e}")


if __name__ == '__main__':
    sys.exit(main() or 0)
