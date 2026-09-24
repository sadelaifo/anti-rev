/*
 * Test 5 process B: uses libcommon.so + libB_only.so (both bundled).
 */
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
    void *hc = dlopen("libcommon.so", RTLD_NOW);
    if (!hc) { fprintf(stderr, "FAIL: B dlopen(libcommon.so): %s\n", dlerror()); return 1; }
    void *hb = dlopen("libB_only.so", RTLD_NOW);
    if (!hb) { fprintf(stderr, "FAIL: B dlopen(libB_only.so): %s\n", dlerror()); return 1; }

    int (*cadd)(int, int) = dlsym(hc, "common_add");
    int (*bsub)(int, int) = dlsym(hb, "b_subtract");

    if (!cadd || !bsub) {
        fprintf(stderr, "FAIL: B dlsym failed: %s\n", dlerror());
        return 1;
    }

    int r1 = cadd(10, 20);
    int r2 = bsub(100, 58);
    if (r1 != 30 || r2 != 42) {
        fprintf(stderr, "FAIL: B common_add(10,20)=%d b_subtract(100,58)=%d\n", r1, r2);
        return 1;
    }

    printf("B: common_add(10,20)=%d  b_subtract(100,58)=%d  PASS\n", r1, r2);
    dlclose(hb);
    dlclose(hc);
    return 0;
}
