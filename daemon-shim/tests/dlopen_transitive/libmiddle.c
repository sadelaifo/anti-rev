/*
 * Encrypted business lib, DT_NEEDED by unencrypted libbridge.so.
 * At runtime, dlopen's libinner.so (also encrypted).
 *
 * Dependency chain tested:
 *   exe ──DT_NEEDED──→ libbridge.so (unencrypted)
 *                           │
 *                       DT_NEEDED
 *                           ↓
 *                      libmiddle.so (encrypted, this file)
 *                           │
 *                        dlopen()
 *                           ↓
 *                      libinner.so (encrypted)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int middle_value(void)
{
    return 42;
}

int middle_load_inner(void)
{
    void *h = dlopen("libinner.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "  middle: dlopen(libinner.so): %s\n", dlerror());
        return -1;
    }
    int (*fn)(void) = dlsym(h, "inner_secret");
    if (!fn) {
        fprintf(stderr, "  middle: dlsym(inner_secret): %s\n", dlerror());
        dlclose(h);
        return -1;
    }
    int result = fn();
    dlclose(h);
    return result;
}
