/*
 * hotpatch demo — patch payload (the "v2" of say_hello)
 *
 * Compile this to a .o; that .o IS the hot-patch object your
 * PatchFetch/PatchActive applies, and which antirev encrypts into the
 * .pat the daemon serves decrypted.
 *
 * Build (aarch64):
 *   aarch64-linux-gnu-gcc -O0 -fno-inline -c -o say_hello.o patch_v2.c
 *   # rename/encrypt to the .pat your loader expects, e.g.:
 *   cp say_hello.o say_hello.pat
 *   python3 encryptor/protect.py encrypt-patch \
 *       --key <part1.key> --lrxd <lrxd-aarch64> --version <version-value> \
 *       --patches say_hello.pat --output-dir <daemon-scan-dir>
 *   # --version is the deployment version VALUE (e.g. V100R001C00), matching
 *   # what the target's $HOME/SW/version parses to.
 *
 * The signature MUST match the original say_hello() in demo.c exactly.
 */
#include <stdio.h>

void say_hello(int call_no)
{
    printf("[demo] call #%d -> PATCHED say_hello (v2!)  <-- hot patch live\n",
           call_no);
}
