/*
 * antirev rtld-audit shim — loaded via LD_AUDIT into the target binary.
 *
 * Implements the rtld-audit interface so ld.so calls la_objsearch() for
 * EVERY library name lookup — both DT_NEEDED entries at startup AND
 * dlopen() at runtime.
 *
 * Reads ANTIREV_FD_MAP="libfoo.so=5,libbar.so=6" and redirects matching
 * library searches to /proc/self/fd/N, where N is the memfd holding the
 * decrypted library.  All other searches pass through unchanged.
 */

#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Resolve basename of a library path (no allocation) */
static const char *basename_of(const char *path)
{
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Look up a library basename in ANTIREV_FD_MAP.
 * Returns fd number (>=0) if found, -1 otherwise. */
static int lookup_fd(const char *name)
{
    const char *map = getenv("ANTIREV_FD_MAP");
    if (!map)
        return -1;

    /* Parse "basename=fd,basename=fd,..." without modifying the env string */
    const char *p = map;
    while (*p) {
        /* find '=' */
        const char *eq = strchr(p, '=');
        if (!eq)
            break;
        size_t key_len = (size_t)(eq - p);
        if (strlen(name) == key_len && strncmp(p, name, key_len) == 0) {
            return atoi(eq + 1);
        }
        /* advance past this entry */
        const char *comma = strchr(eq + 1, ',');
        if (!comma)
            break;
        p = comma + 1;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  rtld-audit interface                                               */
/* ------------------------------------------------------------------ */

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

    /* Only intercept the original (unresolved) name lookup */
    if (flag != LA_SER_ORIG)
        return (char *)name;

    const char *base = basename_of(name);
    int fd = lookup_fd(base);
    if (fd < 0)
        return (char *)name;

    /* ld.so serializes la_objsearch calls — static buffer is safe */
    static char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    return path;
}
