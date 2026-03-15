#include <stdio.h>
#include "linked/liblinkedmath.h"

int main(void) {
    int a = lm_add(3, 4);
    int m = lm_multiply(6, 7);
    printf("lm_add(3,4)=%d  lm_multiply(6,7)=%d\n", a, m);
    if (a != 7 || m != 42) { printf("FAIL\n"); return 1; }
    printf("PASS: DT_NEEDED library loaded via LD_AUDIT\n");
    return 0;
}
