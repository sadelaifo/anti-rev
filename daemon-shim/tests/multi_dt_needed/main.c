/* Stress test: 3 DT_NEEDED encrypted libs in a single binary.
 * All three must be resolved via LD_PRELOAD from bundled memfds. */

#include <stdio.h>

extern int calc_add(int, int);
extern int calc_sub(int, int);
extern int format_int(char *, int, int);
extern int format_len(const char *);
extern int validate_range(int, int, int);
extern int validate_positive(int);

int main(void)
{
    int fail = 0;

    int sum = calc_add(10, 20);
    if (sum != 30) { fprintf(stderr, "FAIL: calc_add\n"); fail++; }

    int diff = calc_sub(50, 17);
    if (diff != 33) { fprintf(stderr, "FAIL: calc_sub\n"); fail++; }

    char buf[64];
    format_int(buf, sizeof(buf), sum);
    int len = format_len(buf);
    if (len != 4) { fprintf(stderr, "FAIL: format [%s] len=%d\n", buf, len); fail++; }

    if (!validate_range(sum, 0, 100)) { fprintf(stderr, "FAIL: validate_range\n"); fail++; }
    if (!validate_positive(diff))     { fprintf(stderr, "FAIL: validate_positive\n"); fail++; }

    if (fail == 0)
        printf("PASS: multi_dt_needed (3 libs, 6 functions)\n");
    else
        printf("FAIL: %d check(s) failed\n", fail);

    return fail;
}
