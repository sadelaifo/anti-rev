#!/usr/bin/env python3
"""
Test: Python dlopen → libfoo (ctor dlopens libbar) → libbar (DT_NEEDED libzzz).

Scene 1: all 3 libs encrypted.
Scene 2: foo + zzz encrypted, bar unencrypted.

Usage:
    ./test.py           # build, pack, run both scenes
    ./test.py --skip-build  # reuse existing .so files
"""

import ctypes
import os
import signal
import subprocess
import sys
import time

DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(DIR, '..', '..')
PACK = os.path.join(ROOT, 'encryptor', 'antirev-pack.py')
STUB = os.path.join(ROOT, 'build', 'stub')

sys.path.insert(0, os.path.join(ROOT, 'tools'))

EXPECTED = 426  # zzz_value(42) + 100 = 142, * 3 = 426

PASS = 0
FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS: {label}")
    else:
        FAIL += 1
        print(f"  FAIL: {label} — got {got!r}, expected {want!r}")


def build():
    print("[build] compiling libs...")
    subprocess.check_call(['bash', os.path.join(DIR, 'build.sh')],
                          cwd=DIR, stdout=subprocess.DEVNULL)


def pack(config, out_dir):
    print(f"[pack] {config} -> {out_dir}")
    subprocess.check_call(
        [sys.executable, PACK, os.path.join(DIR, config)],
        cwd=DIR)


def start_daemon(out_dir):
    """Start the daemon.  It daemonizes (parent exits, child serves)."""
    daemon = os.path.join(DIR, out_dir, '.antirev-libd')
    result = subprocess.run([daemon], capture_output=True, timeout=5)
    if result.returncode != 0:
        raise RuntimeError(
            f"daemon failed (rc={result.returncode}): "
            f"{result.stderr.decode().strip()}")
    # Daemon child is now running in the background.
    # Find its PID so we can kill it later.
    try:
        pgrep = subprocess.run(
            ['pgrep', '-f', daemon], capture_output=True, text=True)
        pids = [int(p) for p in pgrep.stdout.split() if p.strip()]
    except Exception:
        pids = []
    return pids


def stop_daemon(pids):
    for pid in (pids or []):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    time.sleep(0.1)


def run_scene(label, out_dir):
    """Start daemon, activate client, load libfoo, check result."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")

    pids = None
    try:
        pids = start_daemon(out_dir)
        key_path = os.path.join(DIR, out_dir, '.antirev-libd')

        # We need a fresh import each scene since activate() patches ctypes
        # globally. Fork a subprocess to isolate.
        # LD_LIBRARY_PATH must be in the process env at startup so the
        # dynamic linker caches it — setting os.environ inside Python
        # is too late for dlopen() calls from C constructors.
        lib_dir = os.path.join(DIR, out_dir)
        script = f"""\
import sys, os
sys.path.insert(0, {os.path.join(ROOT, 'tools')!r})
from antirev_client import activate
import ctypes

client = activate({key_path!r})
print("libs=" + repr(sorted(client.libs.keys())), file=sys.stderr)

lib = ctypes.CDLL("libfoo.so")
lib.foo_result.restype = ctypes.c_int
result = lib.foo_result()
print(result)
"""
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = lib_dir + ':' + env.get('LD_LIBRARY_PATH', '')
        result = subprocess.run(
            [sys.executable, '-c', script],
            capture_output=True, text=True, timeout=10, env=env)

        if result.returncode != 0:
            print(f"  stderr: {result.stderr.strip()}")
            check(f"{label}: subprocess exited 0", result.returncode, 0)
            return

        stderr = result.stderr.strip()
        if stderr:
            for line in stderr.splitlines():
                print(f"  | {line}")

        val = int(result.stdout.strip())
        check(f"{label}: foo_result() == {EXPECTED}", val, EXPECTED)

    except Exception as e:
        global FAIL
        FAIL += 1
        print(f"  FAIL: {label}: {e}")
    finally:
        stop_daemon(pids)


def main():
    skip_build = '--skip-build' in sys.argv

    if not skip_build:
        build()

    pack('config_all_enc.yaml', 'out_all_enc')
    pack('config_mixed.yaml', 'out_mixed')

    run_scene("Scene 1: all 3 libs encrypted", 'out_all_enc')
    run_scene("Scene 2: foo+zzz encrypted, bar unencrypted", 'out_mixed')

    print(f"\n{'='*60}")
    print(f"  {PASS} passed, {FAIL} failed")
    print(f"{'='*60}")
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
