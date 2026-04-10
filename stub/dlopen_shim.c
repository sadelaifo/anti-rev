/*
 * antirev dlopen interceptor — loaded via LD_PRELOAD into the target binary.
 *
 * Reads ANTIREV_FD_MAP="libfoo.so=5,libbar.so=6" and redirects matching
 * dlopen() calls to /proc/self/fd/N, where N is the memfd holding the
 * decrypted library.  All other dlopen() calls pass through unchanged.
 *
 * Also intercepts Python ctypes and any other code that calls C dlopen().
 *
 * Libs are loaded on-demand: only when something actually calls dlopen()
 * for a lib in ANTIREV_FD_MAP does the shim redirect to the memfd.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static void *(*real_dlopen_fn)(const char *, int) = NULL;

static void *get_real_dlopen(void)
{
    if (!real_dlopen_fn) {
        /* RTLD_NEXT may land on an intermediate wrapper (e.g. libdopra.so)
         * instead of glibc.  Get that wrapper first, then use it to obtain
         * a handle to libdl/libc so we can resolve glibc's real dlopen. */
        void *(*next_fn)(const char *, int) = dlsym(RTLD_NEXT, "dlopen");
        if (next_fn) {
            /* glibc < 2.34: dlopen lives in libdl.so.2
             * glibc >= 2.34: dlopen lives in libc.so.6 */
            void *h = next_fn("libdl.so.2", RTLD_LAZY | RTLD_NOLOAD);
            if (!h)
                h = next_fn("libc.so.6", RTLD_LAZY | RTLD_NOLOAD);
            if (h) {
                void *fn = dlsym(h, "dlopen");
                if (fn)
                    real_dlopen_fn = fn;
            }
        }
        if (!real_dlopen_fn)
            real_dlopen_fn = next_fn;
    }
    return real_dlopen_fn;
}

__attribute__((visibility("default")))
void *dlopen(const char *filename, int flags)
{
    get_real_dlopen();

    if (!filename)
        return real_dlopen_fn(filename, flags);

    const char *map = getenv("ANTIREV_FD_MAP");
    if (!map)
        return real_dlopen_fn(filename, flags);

    /* Match on the basename so both "libfoo.so" and "/path/to/libfoo.so" work */
    const char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;

    /* Parse "name=fd,name=fd,..." */
    char *buf = strdup(map);
    if (!buf)
        return real_dlopen_fn(filename, flags);

    void *handle = NULL;
    char *save   = NULL;
    char *tok    = strtok_r(buf, ",", &save);
    while (tok) {
        char *eq = strchr(tok, '=');
        if (eq) {
            *eq = '\0';
            if (strcmp(tok, base) == 0) {
                int fd = atoi(eq + 1);
                char path[64];
                snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
                handle = real_dlopen_fn(path, flags);
                goto done;
            }
        }
        tok = strtok_r(NULL, ",", &save);
    }
    /* No match — fall through to real dlopen */
    handle = real_dlopen_fn(filename, flags);

done:
    free(buf);
    return handle;
}
