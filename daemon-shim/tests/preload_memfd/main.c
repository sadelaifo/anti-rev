/*  Smoke test: DT_NEEDED satisfied by LD_PRELOAD from memfd.
 *
 *  main is linked against libpretest.so (-lpretest).
 *  At runtime the .so is NOT on disk in any search path.
 *  The launcher loads it into a memfd and sets
 *      LD_PRELOAD=/proc/self/fd/<memfd>
 *  If the dynamic linker reuses the preloaded library for DT_NEEDED,
 *  the program runs and prints PASS.  Otherwise it fails to start. */

#include <stdio.h>

extern int pretest_add(int, int);

int main(void)
{
    int r = pretest_add(3, 4);
    if (r == 7) {
        printf("PASS: pretest_add(3,4) = %d\n", r);
        return 0;
    }
    printf("FAIL: pretest_add(3,4) = %d (expected 7)\n", r);
    return 1;
}
