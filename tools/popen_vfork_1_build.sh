#!/usr/bin/env bash
#
# Step 1/3  — run on the aarch64 compile machine.
#
# Writes the minimal popen test source and compiles it for aarch64.
# Output: ./artifacts/popen_test  (aarch64 ELF, plaintext)
# Next:   copy popen_test to the x86 encrypt machine and run
#         tools/popen_vfork_2_encrypt.sh there.
#
# Usage:
#   tools/popen_vfork_1_build.sh
#   CC=gcc OUT=/tmp/pt tools/popen_vfork_1_build.sh

set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$REPO/artifacts}
CC=${CC:-gcc}

mkdir -p "$OUT"
cd "$OUT"

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

# Must be DYNAMIC — the repro depends on exe_shim being LD_PRELOAD'd
# into the encrypted binary at runtime. Static binaries skip the dynamic
# linker entirely, so LD_PRELOAD has no effect and the shim never loads
# (which means the vfork+shim interaction we're trying to reproduce
# never happens, and the test silently passes on the wrong basis).
#
# If the resulting binary hits "No such file or directory" on the run
# machine, that's a PT_INTERP layout mismatch. Fix on the run host:
#   sudo ln -sf /lib64/ld-linux-aarch64.so.1 /lib/ld-linux-aarch64.so.1
# or rebuild here with an explicit interpreter path:
#   CC='gcc -Wl,--dynamic-linker=/lib64/ld-linux-aarch64.so.1' $0
"$CC" -O2 -o popen_test popen_test.c

echo "[+] built:  $OUT/popen_test"
file popen_test | sed 's/^/         /'
echo
echo "next: scp $OUT/popen_test + $REPO/build/stub_aarch64 to your x86 machine,"
echo "then run tools/popen_vfork_2_encrypt.sh there."
