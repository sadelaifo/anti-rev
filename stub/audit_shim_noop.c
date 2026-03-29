/* No-op audit shim — does absolutely nothing, just passes through.
 * Used to test if LD_AUDIT itself breaks things on this glibc version. */
#define _GNU_SOURCE
#include <link.h>

__attribute__((visibility("default")))
unsigned int la_version(unsigned int version)
{
    (void)version;
    return LAV_CURRENT;
}

__attribute__((visibility("default")))
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
    (void)cookie;
    (void)flag;
    return (char *)name;
}
