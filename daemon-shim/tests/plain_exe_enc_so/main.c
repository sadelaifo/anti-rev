/*
 * plain_exe_enc_so test — plain (unencrypted) exe loads an encrypted .so
 * via dlopen. The audit shim is injected via LD_AUDIT by protect.py run.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-to-encrypted.so>\n", argv[0]);
        return 1;
    }

    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL: dlopen(\"%s\"): %s\n", argv[1], dlerror());
        return 1;
    }

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
