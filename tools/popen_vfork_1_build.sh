#!/usr/bin/env bash
#
# Step 1/3  — run on the aarch64 compile machine.
#
# Writes the popen test source and compiles it for aarch64.
# Two source variants, selected via PRESSURE env var:
#
#   PRESSURE=0 (default) — minimal single-shot popen("date","r").
#                          Good for clean syscall traces, but may not
#                          trigger the vfork+shim race in isolation.
#
#   PRESSURE=1           — multithreaded: N threads × M popens each,
#                          with a little dlopen / VMA churn first.
#                          Closer to how the business process exercises
#                          popen and much more likely to expose a race.
#
# Output: ./artifacts/popen_test  (aarch64 ELF, plaintext, dynamic).
# Next:   copy popen_test to the x86 encrypt machine and run
#         tools/popen_vfork_2_encrypt.sh there.
#
# Usage:
#   tools/popen_vfork_1_build.sh                 # minimal
#   PRESSURE=1 tools/popen_vfork_1_build.sh      # multithreaded
#
# In pressure mode the resulting binary itself takes optional args:
#   ./popen_test [nthreads] [iters_per_thread]
# (defaults: 4 threads, 100 iters each, set inside the source)

set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$REPO/artifacts}
CC=${CC:-gcc}
PRESSURE=${PRESSURE:-0}

mkdir -p "$OUT"
cd "$OUT"

if [[ "$PRESSURE" == "0" ]]; then
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
    EXTRA_LIBS=""
    MODE="minimal"
else
    # PRESSURE=1: multithreaded repro with extra VMA churn.
    # vfork + LD_PRELOAD shim issues are timing-sensitive; running N
    # concurrent popens in the same process widens the race window
    # dramatically. We also dlopen libc a few times up front to grow
    # the mmap/VMA list a bit closer to a real business process.
    cat > popen_test.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>

static int g_iter = 100;

static void *worker(void *arg) {
    long tid = (long)arg;
    int fail = 0;
    for (int i = 0; i < g_iter; i++) {
        FILE *f = popen("date", "r");
        if (!f) { fail++; continue; }
        char buf[256];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        int rc = pclose(f);
        if (rc == -1 || n == 0) fail++;
    }
    if (fail)
        fprintf(stderr, "  thread %ld: %d/%d failed\n", tid, fail, g_iter);
    return (void *)(long)fail;
}

int main(int argc, char *argv[]) {
    int nthr = argc > 1 ? atoi(argv[1]) : 4;
    if (argc > 2) g_iter = atoi(argv[2]);
    if (nthr <= 0) nthr = 4;
    if (g_iter <= 0) g_iter = 100;

    /* Warm up some VMAs / memfd refs before the popen storm. */
    for (int i = 0; i < 16; i++) {
        void *h = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
        if (h) dlclose(h);
    }

    pthread_t *t = calloc(nthr, sizeof(pthread_t));
    if (!t) { perror("calloc"); return 1; }
    for (int i = 0; i < nthr; i++)
        pthread_create(&t[i], NULL, worker, (void *)(long)i);

    int total_fail = 0;
    for (int i = 0; i < nthr; i++) {
        void *rc;
        pthread_join(t[i], &rc);
        total_fail += (int)(long)rc;
    }
    free(t);

    fprintf(stderr, "total: %d/%d failed across %d threads x %d iter\n",
            total_fail, nthr * g_iter, nthr, g_iter);
    return total_fail > 0 ? 1 : 0;
}
EOF
    EXTRA_LIBS="-lpthread -ldl"
    MODE="pressure (configurable via argv on the run machine)"
fi

# Dynamic linking is required — see note in comments. Build the binary
# so the encrypted wrapper can actually LD_PRELOAD the antirev shims.
# shellcheck disable=SC2086
"$CC" -O2 -o popen_test popen_test.c $EXTRA_LIBS

echo "[+] built:  $OUT/popen_test   ($MODE)"
file popen_test | sed 's/^/         /'
echo
if [[ "$PRESSURE" == "1" ]]; then
    echo "pressure-mode binary takes:  ./popen_test [nthreads] [iters_per_thread]"
    echo "  e.g. ./popen_test 8 200   (8 threads x 200 popens each)"
    echo "  note: step 3 passes CMD as argv[1]; non-numeric values (like"
    echo "        'date') fall through to the defaults (4 thr, 100 iter)"
fi
echo
echo "next: scp $OUT/popen_test + $REPO/build/stub_aarch64 to your x86 machine,"
echo "then run tools/popen_vfork_2_encrypt.sh there."
