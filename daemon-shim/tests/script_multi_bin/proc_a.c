/*
 * Test 5 process A: uses libcommon.so + libA_only.so (both bundled).
 */
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
    void *hc = dlopen("libcommon.so", RTLD_NOW);
    if (!hc) { fprintf(stderr, "FAIL: A dlopen(libcommon.so): %s\n", dlerror()); return 1; }
    void *ha = dlopen("libA_only.so", RTLD_NOW);
    if (!ha) { fprintf(stderr, "FAIL: A dlopen(libA_only.so): %s\n", dlerror()); return 1; }

    int (*cadd)(int, int) = dlsym(hc, "common_add");
    int (*amul)(int, int) = dlsym(ha, "a_multiply");

    if (!cadd || !amul) {
        fprintf(stderr, "FAIL: A dlsym failed: %s\n", dlerror());
        return 1;
    }

    int r1 = cadd(3, 4);
    int r2 = amul(6, 7);
    if (r1 != 7 || r2 != 42) {
        fprintf(stderr, "FAIL: A common_add(3,4)=%d a_multiply(6,7)=%d\n", r1, r2);
        return 1;
    }

    printf("A: common_add(3,4)=%d  a_multiply(6,7)=%d  PASS\n", r1, r2);
    dlclose(ha);
    dlclose(hc);
    return 0;
}
