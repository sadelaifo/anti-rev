/* Encrypted business plugin.  DT_NEEDED libcore.so (also encrypted),
 * so dlopen(libplugin) must pull libcore through the daemon closure. */
#include <stdio.h>
extern int core_compute(int);
int plugin_run(void)
{
    int v = core_compute(42);
    printf("[plugin] core_compute(42) = %d\n", v);
    return v;
}
