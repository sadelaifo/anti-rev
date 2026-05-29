#!/bin/bash
# arm64_qemu_demo runner — run INSIDE the arm64 chroot (or a real arm64
# container).  Builds the demo, packs it with antirev in daemon mode,
# MANUALLY starts the lrxd daemon (as in a real deployment), then runs
# the protected launcher against the already-running daemon.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT=/root/antirev
STUB="$ROOT/build/stub_aarch64"
RUN=/tmp/demo_run
KEY="$RUN/demo.key"
rm -rf "$RUN"; mkdir -p "$RUN"

echo "=== 1. build demo (aarch64 native) ==="
gcc -O2 -shared -fPIC -Wl,-soname,libcore.so   -o "$RUN/libcore.so"   "$HERE/libcore.c"
gcc -O2 -shared -fPIC -Wl,-soname,libplugin.so   -o "$RUN/libplugin.so"   "$HERE/libplugin.c" -L"$RUN" -lcore
gcc -O2 -shared -fPIC -Wl,-soname,libmockanti.so -o "$RUN/libmockanti.so" "$HERE/mock_anti.c"
gcc -O2 -o "$RUN/pg.elf"   "$HERE/pg.c"
gcc -O2 -o "$RUN/launcher" "$HERE/launcher.c" -L"$RUN" -lmockanti -ldl
gcc -O2 -o "$RUN/worker"   "$HERE/worker.c"
echo "BUILD_OK"

echo "=== 2. antirev pack (daemon mode) ==="
python3 "$ROOT/encryptor/protect.py" encrypt-lib    --key "$KEY" --libs "$RUN/libplugin.so" "$RUN/libcore.so" "$RUN/libmockanti.so" "$RUN/pg.elf" --output-dir "$RUN"
python3 "$ROOT/encryptor/protect.py" protect-daemon --stub "$STUB" --key "$KEY" --output "$RUN/lrxd"
python3 "$ROOT/encryptor/protect.py" protect-exe    --stub "$STUB" --main "$RUN/launcher" --key "$KEY" --daemon-libs --output "$RUN/launcher.protected"
echo "PACK_OK"

cd "$RUN"
chmod +x lrxd launcher.protected worker

echo "=== 3. start daemon manually ==="
ANTIREV_LOG=1 ANTIREV_LOG_FILE=/tmp/daemon.log ./lrxd
sleep 1
echo "daemon procs:"; pgrep -af lrxd || echo "(no lrxd proc visible by name)"

echo "=== 4. run protected launcher (connects to running daemon) ==="
set +e
ANTIREV_LOG=1 ANTIREV_LOG_FILE=/tmp/launcher.log ANTIREV_DLOPEN_LOG=/tmp/dlopen.log ANTIREV_AARCH64_EXTEND_LOG=/tmp/aae.log ./launcher.protected
echo "LAUNCHER_EC=$?"

echo "=== 4b. Python client (antirev_client.py loads encrypted lib via daemon) ==="
cp "$HERE/pyclient.py" "$RUN/"
ANTIREV_KEY="$KEY" python3 "$RUN/pyclient.py"
echo "PYCLIENT_EC=$?"
set -e

echo "=== 5. stop daemon ==="
pkill -f "$RUN/lrxd" 2>/dev/null || pkill -f lrxd 2>/dev/null || true
echo "DONE"
