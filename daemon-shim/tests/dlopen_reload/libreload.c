/*
 * Reload-test library.  Its constructor and destructor each append a
 * line to the file named by $LIBRELOAD_LOG.  The main binary counts
 * "ctor" lines after doing dlopen / dlclose / dlopen / dlclose — it
 * expects two ctor runs, one per load, which only happens if dlclose
 * actually brought the refcount to zero and unloaded the lib.
 *
 * If anything in the stub / dlopen_shim chain pins the root lib's
 * refcount above zero (e.g. a regression of the "don't pre-load the
 * root" lazy-fetch fix), dlclose will be a no-op, the second dlopen
 * will just bump refcount, the constructor will not run again, and
 * the test will fail.
 */

#include <stdio.h>
#include <stdlib.h>

static void bump(const char *kind)
{
    const char *path = getenv("LIBRELOAD_LOG");
    if (!path || !*path)
        return;
    FILE *f = fopen(path, "a");
    if (!f)
        return;
    fprintf(f, "%s\n", kind);
    fclose(f);
}

__attribute__((constructor))
static void reload_init(void) { bump("ctor"); }

__attribute__((destructor))
static void reload_fini(void) { bump("dtor"); }

/* A stable exported symbol so the test can exercise dlsym on the
 * reloaded handle and prove the mapping is live. */
int libreload_symbol = 42;
