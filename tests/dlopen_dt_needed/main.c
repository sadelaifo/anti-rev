/*
 * Test: encrypted exe dlopen's encrypted libfoo, which DT_NEEDs
 * encrypted libbar.  ALL three binaries are encrypted.
 *
 * Topology:
 *   main (encrypted)
 *     |
 *   dlopen("libfoo.so")        <-- intercepted by dlopen_shim
 *     |
 *   libfoo.so (encrypted)
 *     |
 *   DT_NEEDED libbar.so        <-- resolved by ld.so, NOT by dlopen_shim
 *     |
 *   libbar.so (encrypted)
 *
 * This tests the critical path where the dynamic linker must find
 * libbar.so's decrypted memfd (via LD_LIBRARY_PATH symlinks) when
 * resolving libfoo.so's DT_NEEDED.  Without that, the linker hits
 * the encrypted file on disk and fails with "invalid ELF header".
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
    void *h = dlopen("libfoo.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "FAIL: dlopen(libfoo.so): %s\n", dlerror());
        return 1;
    }

    int (*fn)(void) = dlsym(h, "foo_combined");
    if (!fn) {
        fprintf(stderr, "FAIL: dlsym(foo_combined): %s\n", dlerror());
        dlclose(h);
        return 1;
    }

    int val = fn();
    if (val != 177) {
        fprintf(stderr, "FAIL: foo_combined() = %d, expected 177\n", val);
        dlclose(h);
        return 1;
    }

    printf("PASS: dlopen_dt_needed — foo_combined() = %d "
           "(exe->dlopen(libfoo)->DT_NEEDED(libbar), all encrypted)\n", val);
    dlclose(h);
    return 0;
}
