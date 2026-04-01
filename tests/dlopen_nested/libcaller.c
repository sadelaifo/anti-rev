/*
 * Outer library for nested dlopen test.
 * Calls dlopen("libcallee.so") internally to load another protected library.
 *
 * When both libcaller.so and libcallee.so are in ANTIREV_FD_MAP, the shim
 * must intercept dlopen calls originating from within a shared library,
 * not just from the main binary.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

static void *open_callee(void)
{
    void *h = dlopen("libcallee.so", RTLD_NOW);
    if (!h)
        fprintf(stderr, "  libcaller: dlopen(libcallee.so): %s\n", dlerror());
    return h;
}

int caller_invoke(void)
{
    void *h = open_callee();
    if (!h) return -1;

    int (*fn)(void) = dlsym(h, "callee_value");
    if (!fn) {
        fprintf(stderr, "  libcaller: dlsym(callee_value): %s\n", dlerror());
        dlclose(h);
        return -1;
    }

    int result = fn();
    dlclose(h);
    return result;
}

int caller_sum(int a, int b)
{
    void *h = open_callee();
    if (!h) return -1;

    int (*fn)(int, int) = dlsym(h, "callee_add");
    if (!fn) { dlclose(h); return -1; }

    int result = fn(a, b);
    dlclose(h);
    return result;
}
