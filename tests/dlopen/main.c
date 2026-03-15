/*
 * dlopen test: loads mylib.so at runtime by bare name (no path).
 * The antirev dlopen shim must intercept the call and redirect it
 * to the in-memory decrypted library.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(void)
{
    /* Load by bare soname — shim intercepts and redirects to memfd */
    void *handle = dlopen("mylib.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL: dlopen(\"mylib.so\"): %s\n", dlerror());
        return 1;
    }

    /* Resolve add() */
    int (*add_fn)(int, int) = dlsym(handle, "add");
    if (!add_fn) {
        fprintf(stderr, "FAIL: dlsym(add): %s\n", dlerror());
        return 1;
    }
    int result = add_fn(3, 4);
    if (result != 7) {
        fprintf(stderr, "FAIL: add(3,4) returned %d, expected 7\n", result);
        return 1;
    }

    /* Resolve greeting() */
    const char *(*greet_fn)(void) = dlsym(handle, "greeting");
    if (!greet_fn) {
        fprintf(stderr, "FAIL: dlsym(greeting): %s\n", dlerror());
        return 1;
    }
    const char *msg = greet_fn();
    if (!msg || msg[0] == '\0') {
        fprintf(stderr, "FAIL: greeting() returned empty string\n");
        return 1;
    }

    printf("PASS: add(3,4)=%d  greeting=\"%s\"\n", result, msg);
    dlclose(handle);
    return 0;
}
