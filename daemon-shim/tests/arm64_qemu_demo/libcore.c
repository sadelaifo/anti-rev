/* Encrypted core lib, reached only as libplugin's DT_NEEDED. */
#include <stdio.h>
int core_compute(int x)
{
    printf("[core] core_compute running\n");
    return x * 2;
}
