/* Stress test: nested DT_NEEDED dependencies.
 *
 * main DT_NEEDs libouter.so
 * libouter.so DT_NEEDs libinner.so
 * Both are encrypted and loaded from memfds via LD_PRELOAD.
 *
 * The dynamic linker must resolve the transitive dependency chain
 * entirely from preloaded memfds. */

#include <stdio.h>

extern int outer_sum_of_squares(int, int);
extern int outer_quad(int);
extern int inner_square(int);

int main(void)
{
    int fail = 0;

    /* Test outer functions (which internally call inner functions) */
    int sos = outer_sum_of_squares(3, 4);
    if (sos != 25) { fprintf(stderr, "FAIL: outer_sum_of_squares(3,4)=%d (expected 25)\n", sos); fail++; }

    int q = outer_quad(5);
    if (q != 20) { fprintf(stderr, "FAIL: outer_quad(5)=%d (expected 20)\n", q); fail++; }

    /* Test direct call to inner (also DT_NEEDED transitively) */
    int sq = inner_square(7);
    if (sq != 49) { fprintf(stderr, "FAIL: inner_square(7)=%d (expected 49)\n", sq); fail++; }

    if (fail == 0)
        printf("PASS: nested_deps (outer->inner chain, 3 calls)\n");
    else
        printf("FAIL: %d check(s) failed\n", fail);

    return fail;
}
