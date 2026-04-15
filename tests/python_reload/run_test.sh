#!/bin/bash
# test_python_reload — guard antirev_client.py's "don't pin the root"
# rule for on-demand ctypes loading.
#
# Loads libreload.so twice via ctypes.CDLL (with a real dlclose in
# between) and counts the ctor lines libreload.so writes to its log
# file.  If antirev_client._ensure_deps ever regresses into _ensure_loaded
# for the root lib, the second dlopen will be a refcount bump rather
# than a real re-load and the ctor will only run once — which is the
# same class of bug that triggers "libprotobuf ERROR: File already
# exists in database" collisions when two plugins share static state.

set -e

STUB="$1"
LIBRELOAD="$2"
SRC_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROTECT="$SRC_DIR/encryptor/protect.py"
TD="$(dirname "$STUB")/python_reload_test"
LOG="$TD/reload.log"

rm -rf "$TD"
mkdir -p "$TD"

python3 "$PROTECT" protect-daemon \
    --stub "$STUB" --key "$TD/daemon.key" \
    --libs "$LIBRELOAD" \
    --output "$TD/antirev-libd" >/dev/null

"$TD/antirev-libd"
sleep 0.3

cleanup() {
    pkill -f "$TD/antirev-libd" 2>/dev/null || true
}
trap cleanup EXIT

export LIBRELOAD_LOG="$LOG"
rm -f "$LOG"

PYTHONPATH="$SRC_DIR/tools" python3 - "$TD/daemon.key" "$LOG" <<'PY'
import os
import sys
import ctypes
import _ctypes
from antirev_client import activate

key_path = sys.argv[1]
log_path = sys.argv[2]

# Explicit key source; don't touch the host environment's ANTIREV_KEY.
client = activate(key_path)

def one_round(label):
    lib = ctypes.CDLL("libreload.so")
    sym = ctypes.c_int.in_dll(lib, "libreload_symbol")
    if sym.value != 42:
        print(f"FAIL [{label}]: libreload_symbol={sym.value}, expected 42")
        sys.exit(1)
    # Explicit dlclose — ctypes.CDLL has no __del__ that unloads.
    _ctypes.dlclose(lib._handle)

one_round("first")
one_round("second")

# Count ctor lines in the log file libreload.so wrote to.
with open(log_path) as f:
    lines = f.read().splitlines()
ctors = sum(1 for l in lines if l.startswith("ctor"))
dtors = sum(1 for l in lines if l.startswith("dtor"))
print(f"[python_reload] log shows {ctors} ctor / {dtors} dtor lines")

if ctors < 2:
    print(
        "FAIL: expected >= 2 ctor lines (one per ctypes.CDLL round), "
        f"got {ctors}.\n"
        "  antirev_client appears to be pinning the root lib's refcount,\n"
        "  so dlclose never unloaded it and the second CDLL call was a\n"
        "  no-op refcount bump instead of a real reload.",
        file=sys.stderr,
    )
    sys.exit(1)

print("PASS: python_reload")
PY

echo "PASS: antirev_client ctypes reload"
