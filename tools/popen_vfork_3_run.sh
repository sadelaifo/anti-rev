#!/usr/bin/env bash
#
# Step 3/3  — run on the aarch64 run (test) machine.
#
# Takes popen_test (plaintext) + popen_test.protected (antirev-encrypted),
# runs each ITER times to measure failure rate, strace'es one instance
# of each, and diffs the syscall sequence.
#
# Usage:
#   tools/popen_vfork_3_run.sh <popen_test> <popen_test.protected>
#
# Env:
#   CMD   command passed as argv[1] to both binaries (default: "date")
#   ITER  iterations per binary (default: 20)
#   WORK  working dir for strace logs (default: /tmp/popen_vfork_run)
#
# Output:
#   Summary to stdout, full strace logs under $WORK/.

set -u

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <popen_test> <popen_test.protected>" >&2
    exit 1
fi

PLAIN=$(readlink -f "$1")
ENC=$(readlink -f "$2")
CMD=${CMD:-date}
ITER=${ITER:-20}
WORK=${WORK:-/tmp/popen_vfork_run}

[[ -x "$PLAIN" ]] || { echo "not executable: $PLAIN" >&2; exit 1; }
[[ -x "$ENC"   ]] || { echo "not executable: $ENC"   >&2; exit 1; }

mkdir -p "$WORK"

ARCH=$(uname -m)
GLIBC=$(ldd --version 2>&1 | head -1 | awk '{print $NF}')

echo "=================================================================="
echo "  arch:   $ARCH      glibc: $GLIBC"
echo "  plain:  $PLAIN"
echo "  enc:    $ENC"
echo "  cmd:    popen(\"$CMD\", \"r\")"
echo "  iter:   $ITER"
echo "  work:   $WORK"
echo "=================================================================="

# ── 1. Failure rate ─────────────────────────────────────────────────
run_many() {
    local bin=$1 label=$2 fail=0
    for i in $(seq 1 "$ITER"); do
        if ! "$bin" "$CMD" >/dev/null 2>&1; then
            ((fail++))
        fi
    done
    printf "  %-10s  fail=%d/%d\n" "$label" "$fail" "$ITER"
}
echo "=== failure rate ==="
run_many "$PLAIN" plain
run_many "$ENC"   encrypted
echo

# ── 2. strace each once ─────────────────────────────────────────────
STRACE_OPTS="-f -e trace=%process,clone,clone3,pipe,pipe2,dup2,close"
echo "=== strace ==="
# shellcheck disable=SC2086
strace $STRACE_OPTS -o "$WORK/plain.log" "$PLAIN" "$CMD" >/dev/null 2>&1 \
    && echo "  plain      OK"     || echo "  plain      FAIL rc=$?"
# shellcheck disable=SC2086
strace $STRACE_OPTS -o "$WORK/enc.log"   "$ENC"   "$CMD" >/dev/null 2>&1 \
    && echo "  encrypted  OK"     || echo "  encrypted  FAIL rc=$?"
echo

# ── 3. clone flags ─────────────────────────────────────────────────
extract_clone() { grep -oE 'clone3?\([^)]*\)' "$1" | head -5; }
echo "=== clone flags (plain) ==="
extract_clone "$WORK/plain.log" || echo "  (none)"
echo
echo "=== clone flags (encrypted) ==="
extract_clone "$WORK/enc.log"   || echo "  (none)"
echo

# ── 4. Child syscall window (between clone-vfork and execve) ───────
child_window() {
    awk '
        /clone.*CLONE_VM.*CLONE_VFORK/   { in_window=1; print; next }
        /clone3.*CLONE_VM.*CLONE_VFORK/  { in_window=1; print; next }
        /clone(\(|3\().*SIGCHLD/ && !/CLONE_VM/ { in_window=1; print; next }
        in_window && /execve.*\/bin\/sh/ { print; in_window=0; next }
        in_window                        { print }
    ' "$1"
}
echo "=== child window (plain) ==="
child_window "$WORK/plain.log" | head -40
echo
echo "=== child window (encrypted) ==="
child_window "$WORK/enc.log"   | head -40
echo

# ── 5. Full pid-normalized diff ────────────────────────────────────
normalize() {
    sed -E 's/\[pid [0-9]+\]/[pid X]/g; s/<[0-9.]+>//g; s/= [0-9]+$/= N/' "$1"
}
normalize "$WORK/plain.log" > "$WORK/plain.norm"
normalize "$WORK/enc.log"   > "$WORK/enc.norm"
echo "=== diff (plain vs encrypted, pid-normalized) ==="
diff -u "$WORK/plain.norm" "$WORK/enc.norm" | head -80 || true
echo

echo "=================================================================="
echo "  artifacts under $WORK/"
echo "    plain.log enc.log   — raw strace"
echo "    plain.norm enc.norm — pid-normalized for diff"
echo "=================================================================="
echo
echo "if failure rate > 0 and syscall diff isn't enough, go deeper:"
echo "  ulimit -c unlimited"
echo "  echo '/tmp/core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern"
echo "  while $ENC \"$CMD\" >/dev/null 2>&1; do :; done"
echo "  gdb $ENC /tmp/core.popen_test.XXX"
echo "    (gdb) thread apply all bt"
echo "    (gdb) info registers"
