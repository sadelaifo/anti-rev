/*
 * hotpatch demo — target program (aarch64 hot-patch test)
 *
 * A long-running process whose say_hello() is the live-patch target.
 * Run it, then apply the encrypted .pat built from patch_v2.c via your
 * PatchFetch/PatchActive flow; the per-second log line should switch
 * from "ORIGINAL (v1)" to "PATCHED (v2!)" without restarting the process.
 *
 * Build (aarch64):
 *   aarch64-linux-gnu-gcc -O0 -fno-inline -fpatchable-function-entry=2 \
 *       -no-pie -o demo demo.c
 *   (drop/adjust -fpatchable-function-entry / -no-pie to match whatever
 *    your PatchActive requires for a redirectable call target.)
 */
#include <stdio.h>
#include <unistd.h>
#include <time.h>

/* The function the hot patch replaces.
 *  - noinline + used: guarantee a real, standalone call target the
 *    patcher can redirect (not inlined away, not GC'd).
 *  - distinct body/string: so the log unambiguously shows which version
 *    is running. */
__attribute__((noinline, used))
void say_hello(int call_no)
{
    printf("[demo] call #%d -> ORIGINAL say_hello (v1)\n", call_no);
}

int main(void)
{
    printf("[demo] started pid=%d — calling say_hello() every 1s\n",
           (int)getpid());
    fflush(stdout);

    for (int i = 1; ; i++) {
        say_hello(i);
        fflush(stdout);          /* line-buffered so logs appear live */
        sleep(1);
    }
    return 0;                     /* unreachable */
}
