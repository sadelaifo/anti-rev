#!/usr/bin/env bash
#
# popen_vfork_repro.sh — reproduce & diagnose the aarch64 vfork/popen
# failure under antirev.
#
# Builds a minimal C program that calls popen("date","r"), encrypts it,
# and runs both plain and encrypted versions N times. Captures strace
# of each and diffs the syscall sequence around clone/execve.
#
# Usage:
#   tools/popen_vfork_repro.sh                # defaults: date, 20 iter
#   CMD='ls /etc' ITER=50 tools/popen_vfork_repro.sh
#   STUB=./build/stub_aarch64 tools/popen_vfork_repro.sh
#
# Env:
#   CMD    command passed to popen (default: "date")
#   ITER   run count for flakiness detection (default: 20)
#   STUB   antirev stub path (default: auto-detect)
#   WORK   working dir (default: /tmp/popen_vfork_repro)

set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-/tmp/popen_vfork_repro}
CMD=${CMD:-date}
ITER=${ITER:-20}

# Auto-detect stub if not provided
if [[ -z "${STUB:-}" ]]; then
    if [[ -x "$REPO/build/stub" ]]; then
        STUB="$REPO/build/stub"
    elif [[ -x "$REPO/build/stub_aarch64" ]]; then
        STUB="$REPO/build/stub_aarch64"
    else
        echo "no stub found in $REPO/build/. Build the project first." >&2
        exit 1
    fi
fi

ARCH=$(uname -m)
GLIBC=$(ldd --version 2>&1 | head -1 | awk '{print $NF}')

echo "=================================================================="
echo "  arch:  $ARCH      glibc: $GLIBC"
echo "  stub:  $STUB"
echo "  work:  $WORK"
echo "  cmd:   popen(\"$CMD\", \"r\")"
echo "  iter:  $ITER"
echo "=================================================================="

mkdir -p "$WORK"
cd "$WORK"

# ── 1. Write minimal reproducer ─────────────────────────────────────
cat > popen_test.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
int main(int argc, char *argv[]) {
    const char *cmd = argc > 1 ? argv[1] : "date";
    FILE *f = popen(cmd, "r");
    if (!f) { fprintf(stderr, "popen: %s\n", strerror(errno)); return 10; }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    int rc = pclose(f);
    if (rc == -1) { fprintf(stderr, "pclose: %s\n", strerror(errno)); return 20; }
    if (n == 0) { fprintf(stderr, "empty output, exit=%d\n", rc); return 30; }
    printf("%s", buf);
    return rc == 0 ? 0 : 40;
}
EOF
gcc -O2 -o popen_test popen_test.c
echo "[+] built popen_test"

# ── 2. Encrypt with antirev ─────────────────────────────────────────
python3 "$REPO/encryptor/protect.py" protect-exe \
    --stub "$STUB" \
    --main ./popen_test \
    --key  ./test.key \
    --output ./popen_test.protected >/dev/null
echo "[+] encrypted popen_test.protected"
echo

# ── 3. Failure-rate comparison ──────────────────────────────────────
run_many() {
    local bin=$1 label=$2
    local fail=0 rc
    for i in $(seq 1 "$ITER"); do
        if ! "$bin" "$CMD" >/dev/null 2>&1; then
            ((fail++))
        fi
    done
    printf "  %-10s  fail=%d/%d\n" "$label" "$fail" "$ITER"
}

echo "=== failure rate ==="
run_many ./popen_test plain
run_many ./popen_test.protected encrypted
echo

# ── 4. Capture strace of each (single run) ──────────────────────────
strace_opts="-f -e trace=%process,clone,clone3,pipe,pipe2,dup2,close"
echo "=== strace: plain ==="
# shellcheck disable=SC2086
strace $strace_opts -o strace_plain.log ./popen_test "$CMD" >/dev/null 2>&1 \
    && echo "  plain: OK" || echo "  plain: FAIL rc=$?"
echo "=== strace: encrypted ==="
# shellcheck disable=SC2086
strace $strace_opts -o strace_enc.log ./popen_test.protected "$CMD" >/dev/null 2>&1 \
    && echo "  encrypted: OK" || echo "  encrypted: FAIL rc=$?"
echo

# ── 5. Extract clone flags from both ────────────────────────────────
extract_clone() {
    grep -oE 'clone3?\([^)]*\)' "$1" | head -5
}
echo "=== clone flags (plain) ==="
extract_clone strace_plain.log || echo "  (none captured)"
echo
echo "=== clone flags (encrypted) ==="
extract_clone strace_enc.log || echo "  (none captured)"
echo

# ── 6. Show child's syscall sequence (after clone, before execve) ──
#     Focus on what happens inside the vfork window.
child_window() {
    local log=$1
    # Strip timing/pid prefixes for diff, then pull lines between clone
    # and the child's execve. -f output has [pid N] per-line prefixes.
    awk '
        /clone.*CLONE_VM.*CLONE_VFORK/ { in_window=1; print; next }
        /clone3.*CLONE_VM.*CLONE_VFORK/ { in_window=1; print; next }
        /clone(\(|3\().*SIGCHLD/ && !/CLONE_VM/ { in_window=1; print; next }
        in_window && /execve.*\/bin\/sh|execve.*'"$CMD"'/ { print; in_window=0; next }
        in_window { print }
    ' "$log"
}
echo "=== child syscall window (plain) ==="
child_window strace_plain.log | head -40
echo
echo "=== child syscall window (encrypted) ==="
child_window strace_enc.log | head -40
echo

# ── 7. Diff (pid-normalized) ────────────────────────────────────────
normalize() {
    sed -E 's/\[pid [0-9]+\]/[pid X]/g; s/<[0-9.]+>//g; s/= [0-9]+$/= N/' "$1"
}
normalize strace_plain.log > strace_plain.norm
normalize strace_enc.log   > strace_enc.norm

echo "=== diff (plain vs encrypted, normalized) ==="
diff -u strace_plain.norm strace_enc.norm | head -80 || true
echo

# ── 8. Summary ──────────────────────────────────────────────────────
echo "=================================================================="
echo "  artifacts in: $WORK"
echo "    popen_test, popen_test.protected"
echo "    strace_plain.log, strace_enc.log"
echo "    strace_plain.norm, strace_enc.norm (pid-normalized for diff)"
echo "=================================================================="
echo
echo "next steps if failure rate > 0:"
echo "  1. Enable core dumps and run the encrypted version until it fails:"
echo "       ulimit -c unlimited"
echo "       echo '/tmp/core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern"
echo "       while $WORK/popen_test.protected \"$CMD\" >/dev/null 2>&1; do :; done"
echo "       ls -l /tmp/core.* | tail -1"
echo "  2. gdb on the core:"
echo "       gdb $WORK/popen_test.protected /tmp/core.popen_test.XXX"
echo "       (gdb) thread apply all bt"
echo "       (gdb) info registers"
echo "  3. bpftrace the vfork child syscalls (sudo):"
echo "       bpftrace -e 'tracepoint:raw_syscalls:sys_enter /comm == \"popen_test\"/ {"
echo "            printf(\"tid=%d sys=%d\\n\", tid, args->id);"
echo "        }'"
