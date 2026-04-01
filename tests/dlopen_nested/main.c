/*
 * Nested dlopen test: main dlopen's libcaller.so, which internally
 * dlopen's libcallee.so.  Both libraries are protected and listed in
 * ANTIREV_FD_MAP.
 *
 * Verifies the shim intercepts dlopen calls from within shared
 * libraries, not just from the main binary.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
    int failures = 0;

    void *h = dlopen("libcaller.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "FAIL: dlopen(libcaller.so): %s\n", dlerror());
        return 1;
    }

    /* Test 1: caller_invoke() internally dlopen's libcallee.so
     *         and calls callee_value() which returns 42 */
    {
        int (*fn)(void) = dlsym(h, "caller_invoke");
        if (!fn) {
            fprintf(stderr, "FAIL: dlsym(caller_invoke): %s\n", dlerror());
            return 1;
        }
        int val = fn();
        if (val != 42) {
            fprintf(stderr, "FAIL: caller_invoke() = %d, expected 42\n", val);
            failures++;
        }
    }

    /* Test 2: caller_sum() internally dlopen's libcallee.so
     *         and calls callee_add(17, 25) which returns 42 */
    {
        int (*fn)(int, int) = dlsym(h, "caller_sum");
        if (!fn) {
            fprintf(stderr, "FAIL: dlsym(caller_sum): %s\n", dlerror());
            return 1;
        }
        int s = fn(17, 25);
        if (s != 42) {
            fprintf(stderr, "FAIL: caller_sum(17,25) = %d, expected 42\n", s);
            failures++;
        }
    }

    dlclose(h);

    if (failures == 0)
        printf("PASS: dlopen_nested (caller->callee chain, 2 checks)\n");
    else
        printf("FAIL: dlopen_nested (%d failure(s))\n", failures);

    return failures ? 1 : 0;
}
