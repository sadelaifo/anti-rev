/*
 * Test 4 child: protected binary that dlopen's libchild.so (bundled in its stub).
 * This binary is protected separately from the parent.
 */
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
    void *handle = dlopen("libchild.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL: child dlopen(\"libchild.so\"): %s\n", dlerror());
        return 1;
    }

    int (*sub)(int, int) = dlsym(handle, "child_subtract");
    if (!sub) {
        fprintf(stderr, "FAIL: child dlsym(child_subtract): %s\n", dlerror());
        return 1;
    }

    int result = sub(10, 3);
    if (result != 7) {
        fprintf(stderr, "FAIL: child_subtract(10,3)=%d (expected 7)\n", result);
        return 1;
    }

    printf("child: child_subtract(10,3)=%d OK\n", result);
    dlclose(handle);
    return 0;
}
