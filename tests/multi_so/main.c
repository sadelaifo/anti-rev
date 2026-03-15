/*
 * multi_so test: loads TWO protected shared libraries via dlopen.
 * Both libraries are protected and their names are in ANTIREV_FD_MAP.
 * The shim must redirect both dlopen calls correctly.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(void)
{
    int ok = 1;

    /* --- Load libmath.so --- */
    void *hmath = dlopen("libmath.so", RTLD_NOW);
    if (!hmath) {
        fprintf(stderr, "FAIL: dlopen(libmath.so): %s\n", dlerror());
        return 1;
    }
    int (*multiply)(int, int) = dlsym(hmath, "multiply");
    int (*subtract)(int, int) = dlsym(hmath, "subtract");
    if (!multiply || !subtract) {
        fprintf(stderr, "FAIL: dlsym on libmath.so: %s\n", dlerror());
        return 1;
    }

    /* --- Load libstr.so --- */
    void *hstr = dlopen("libstr.so", RTLD_NOW);
    if (!hstr) {
        fprintf(stderr, "FAIL: dlopen(libstr.so): %s\n", dlerror());
        return 1;
    }
    int (*str_len)(const char *) = dlsym(hstr, "str_len");
    int (*str_eq)(const char *, const char *) = dlsym(hstr, "str_eq");
    if (!str_len || !str_eq) {
        fprintf(stderr, "FAIL: dlsym on libstr.so: %s\n", dlerror());
        return 1;
    }

    /* --- Exercise libmath --- */
    if (multiply(6, 7) != 42) {
        fprintf(stderr, "FAIL: multiply(6,7)=%d\n", multiply(6, 7));
        ok = 0;
    }
    if (subtract(10, 3) != 7) {
        fprintf(stderr, "FAIL: subtract(10,3)=%d\n", subtract(10, 3));
        ok = 0;
    }

    /* --- Exercise libstr --- */
    if (str_len("hello") != 5) {
        fprintf(stderr, "FAIL: str_len(hello)=%d\n", str_len("hello"));
        ok = 0;
    }
    if (!str_eq("abc", "abc")) {
        fprintf(stderr, "FAIL: str_eq(abc,abc) returned 0\n");
        ok = 0;
    }
    if (str_eq("abc", "xyz")) {
        fprintf(stderr, "FAIL: str_eq(abc,xyz) returned 1\n");
        ok = 0;
    }

    if (ok) {
        printf("PASS: multiply(6,7)=%d  subtract(10,3)=%d"
               "  str_len(hello)=%d  str_eq ok\n",
               multiply(6, 7), subtract(10, 3), str_len("hello"));
    }

    dlclose(hmath);
    dlclose(hstr);
    return ok ? 0 : 1;
}
