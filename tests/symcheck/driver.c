/*
 * driver.c — dlopens two libs that both export `who`, then resolves `who`
 * two ways:
 *   1. dlsym(RTLD_DEFAULT, "who")  — global-scope lookup, ORDER-DEPENDENT.
 *      Whichever lib was loaded first wins; changing load order flips the
 *      owner.  This is the dlsym ownership flip we want the tooling to catch.
 *   2. dlsym(<fixed handle>, "who") — lookup scoped to one specific lib,
 *      STABLE regardless of load order (the negative control).
 *
 * argv[1], argv[2] = the two libs, in load order.
 * argv[3]          = the lib to use for the fixed-handle control (already
 *                    loaded via [1] or [2]; opened here with RTLD_NOLOAD).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <first.so> <second.so> <fixed.so>\n", argv[0]);
        return 2;
    }

    void *h1 = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    void *h2 = dlopen(argv[2], RTLD_NOW | RTLD_GLOBAL);
    if (!h1 || !h2) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 3;
    }

    const char *(*w_default)(void) =
        (const char *(*)(void)) dlsym(RTLD_DEFAULT, "who");

    void *hf = dlopen(argv[3], RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL);
    const char *(*w_fixed)(void) =
        hf ? (const char *(*)(void)) dlsym(hf, "who") : NULL;

    printf("default=%s fixed=%s\n",
           w_default ? w_default() : "?",
           w_fixed ? w_fixed() : "?");
    return 0;
}
