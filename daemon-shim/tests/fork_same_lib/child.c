/*
 * Test 3 child: dlopen's mylib.so by soname.
 * Relies on LD_PRELOAD inherited from parent providing the lib.
 */
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
    void *handle = dlopen("mylib.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL: child dlopen(\"mylib.so\"): %s\n", dlerror());
        return 1;
    }

    int (*add_fn)(int, int) = dlsym(handle, "add");
    if (!add_fn) {
        fprintf(stderr, "FAIL: child dlsym(add): %s\n", dlerror());
        return 1;
    }

    int result = add_fn(3, 4);
    if (result != 7) {
        fprintf(stderr, "FAIL: child add(3,4)=%d (expected 7)\n", result);
        return 1;
    }

    printf("child: add(3,4)=%d via inherited LD_PRELOAD\n", result);
    dlclose(handle);
    return 0;
}
