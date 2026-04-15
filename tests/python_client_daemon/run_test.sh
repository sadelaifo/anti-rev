#!/bin/bash
# test_python_client_daemon — antirev_client.py speaks daemon protocol v2.
#
# Builds a daemon with two libs, starts it, then runs the Python client
# and checks that it received both fds as memfds via SCM_RIGHTS.  Catches
# v2-protocol regressions in tools/antirev_client.py (OP_INIT handshake,
# OP_BATCH/OP_END framing).

set -e

STUB="$1"
MYLIB="$2"
LIBLINKEDMATH="$3"
SRC_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROTECT="$SRC_DIR/encryptor/protect.py"
TD="$(dirname "$STUB")/python_client_daemon_test"

rm -rf "$TD"
mkdir -p "$TD"

python3 "$PROTECT" protect-daemon \
    --stub "$STUB" --key "$TD/daemon.key" \
    --libs "$MYLIB" "$LIBLINKEDMATH" \
    --output "$TD/antirev-libd" >/dev/null

"$TD/antirev-libd"
sleep 0.3

cleanup() {
    pkill -f "$TD/antirev-libd" 2>/dev/null || true
}
trap cleanup EXIT

PYTHONPATH="$SRC_DIR/tools" python3 - "$TD/daemon.key" <<'PY'
import os, sys
from pathlib import Path
from antirev_client import AntirevClient, _load_key

# Skip __init__ to avoid touching LD_LIBRARY_PATH / soname map — we
# just want to verify the wire protocol.
c = object.__new__(AntirevClient)
c._key = _load_key(Path(sys.argv[1]))
c._libs = {}
c._connect()

want = {"mylib.so", "liblinkedmath.so"}
got  = set(c._libs)
if got != want:
    print(f"FAIL: expected libs={sorted(want)}, got={sorted(got)}")
    sys.exit(1)

for name, fd in c._libs.items():
    target = os.readlink(f"/proc/self/fd/{fd}")
    if "memfd:" not in target:
        print(f"FAIL: {name} fd {fd} -> {target} (not a memfd)")
        sys.exit(1)

print(f"PASS: antirev_client received {len(got)} libs via v2 protocol")
PY

echo "PASS: python client daemon v2 protocol"
