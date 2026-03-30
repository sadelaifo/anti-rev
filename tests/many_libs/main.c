/* Auto-generated stress test: 20 DT_NEEDED encrypted libs */
#include <stdio.h>

extern int stress_01_func(int);
extern int stress_02_func(int);
extern int stress_03_func(int);
extern int stress_04_func(int);
extern int stress_05_func(int);
extern int stress_06_func(int);
extern int stress_07_func(int);
extern int stress_08_func(int);
extern int stress_09_func(int);
extern int stress_10_func(int);
extern int stress_11_func(int);
extern int stress_12_func(int);
extern int stress_13_func(int);
extern int stress_14_func(int);
extern int stress_15_func(int);
extern int stress_16_func(int);
extern int stress_17_func(int);
extern int stress_18_func(int);
extern int stress_19_func(int);
extern int stress_20_func(int);

int main(void)
{
    int fail = 0;
    int result;
    result = stress_01_func(100);
    if (result != 101) { fprintf(stderr, "FAIL: stress_01_func(100)=%d (expected 101)\n", result); fail++; }
    result = stress_02_func(100);
    if (result != 102) { fprintf(stderr, "FAIL: stress_02_func(100)=%d (expected 102)\n", result); fail++; }
    result = stress_03_func(100);
    if (result != 103) { fprintf(stderr, "FAIL: stress_03_func(100)=%d (expected 103)\n", result); fail++; }
    result = stress_04_func(100);
    if (result != 104) { fprintf(stderr, "FAIL: stress_04_func(100)=%d (expected 104)\n", result); fail++; }
    result = stress_05_func(100);
    if (result != 105) { fprintf(stderr, "FAIL: stress_05_func(100)=%d (expected 105)\n", result); fail++; }
    result = stress_06_func(100);
    if (result != 106) { fprintf(stderr, "FAIL: stress_06_func(100)=%d (expected 106)\n", result); fail++; }
    result = stress_07_func(100);
    if (result != 107) { fprintf(stderr, "FAIL: stress_07_func(100)=%d (expected 107)\n", result); fail++; }
    result = stress_08_func(100);
    if (result != 108) { fprintf(stderr, "FAIL: stress_08_func(100)=%d (expected 108)\n", result); fail++; }
    result = stress_09_func(100);
    if (result != 109) { fprintf(stderr, "FAIL: stress_09_func(100)=%d (expected 109)\n", result); fail++; }
    result = stress_10_func(100);
    if (result != 110) { fprintf(stderr, "FAIL: stress_10_func(100)=%d (expected 110)\n", result); fail++; }
    result = stress_11_func(100);
    if (result != 111) { fprintf(stderr, "FAIL: stress_11_func(100)=%d (expected 111)\n", result); fail++; }
    result = stress_12_func(100);
    if (result != 112) { fprintf(stderr, "FAIL: stress_12_func(100)=%d (expected 112)\n", result); fail++; }
    result = stress_13_func(100);
    if (result != 113) { fprintf(stderr, "FAIL: stress_13_func(100)=%d (expected 113)\n", result); fail++; }
    result = stress_14_func(100);
    if (result != 114) { fprintf(stderr, "FAIL: stress_14_func(100)=%d (expected 114)\n", result); fail++; }
    result = stress_15_func(100);
    if (result != 115) { fprintf(stderr, "FAIL: stress_15_func(100)=%d (expected 115)\n", result); fail++; }
    result = stress_16_func(100);
    if (result != 116) { fprintf(stderr, "FAIL: stress_16_func(100)=%d (expected 116)\n", result); fail++; }
    result = stress_17_func(100);
    if (result != 117) { fprintf(stderr, "FAIL: stress_17_func(100)=%d (expected 117)\n", result); fail++; }
    result = stress_18_func(100);
    if (result != 118) { fprintf(stderr, "FAIL: stress_18_func(100)=%d (expected 118)\n", result); fail++; }
    result = stress_19_func(100);
    if (result != 119) { fprintf(stderr, "FAIL: stress_19_func(100)=%d (expected 119)\n", result); fail++; }
    result = stress_20_func(100);
    if (result != 120) { fprintf(stderr, "FAIL: stress_20_func(100)=%d (expected 120)\n", result); fail++; }
    if (fail == 0) printf("PASS: many_libs (20 libs, 20 functions)\n");
    else printf("FAIL: %d/20 checks failed\n", fail);
    return fail;
}
