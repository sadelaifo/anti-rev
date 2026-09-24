/*
 * fork_exec test — child (daemon) binary.
 *
 * This binary is NOT wrapped by the antirev stub.  It is exec'd by parent.c
 * and relies entirely on the LD_AUDIT shim and ANTIREV_KEY_FD inherited from
 * the parent process to decrypt and load the encrypted .so it is given.
 *
 * Usage: child <encrypted_lib_path>
 */
#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <encrypted_lib>\n", argv[0]);
        return 1;
    }

    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL: dlopen('%s'): %s\n", argv[1], dlerror());
        return 1;
    }

    typedef int (*add_fn)(int, int);
    add_fn add = (add_fn)dlsym(handle, "add");
    if (!add) {
        fprintf(stderr, "FAIL: dlsym(add): %s\n", dlerror());
        return 1;
    }

    int result = add(3, 4);
    if (result != 7) {
        fprintf(stderr, "FAIL: add(3,4)=%d (expected 7)\n", result);
        return 1;
    }

    printf("child: add(3,4)=%d via inherited audit shim\n", result);
    dlclose(handle);
    return 0;
}
