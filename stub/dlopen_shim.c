/*
 * antirev dlopen interceptor — loaded via LD_PRELOAD into the target binary.
 *
 * Reads ANTIREV_FD_MAP="libfoo.so=5,libbar.so=6" and redirects matching
 * dlopen() calls to /proc/self/fd/N, where N is the memfd holding the
 * decrypted library.  All other dlopen() calls pass through unchanged.
 *
 * Also intercepts Python ctypes and any other code that calls C dlopen().
 *
 * Constructor: eagerly preloads all ANTIREV_FD_MAP libs with a retry loop
 * to handle dependency ordering automatically (leaf deps loaded first).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void *(*real_dlopen_fn)(const char *, int) = NULL;

static void *get_real_dlopen(void)
{
    if (!real_dlopen_fn)
        real_dlopen_fn = dlsym(RTLD_NEXT, "dlopen");
    return real_dlopen_fn;
}

/* Preload all ANTIREV_FD_MAP libs at startup.  Retry loop handles
 * dependency ordering: leaf libs load first, dependents in later passes. */
__attribute__((constructor))
static void antirev_preload(void)
{
    if (!get_real_dlopen()) return;
    const char *map = getenv("ANTIREV_FD_MAP");
    if (!map || !*map) return;

    char *buf = strdup(map);
    if (!buf) return;

    /* Parse entries */
    #define MAX_PRELOAD 1024
    int  fds[MAX_PRELOAD];
    char loaded[MAX_PRELOAD];
    int  count = 0;

    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save);
         tok && count < MAX_PRELOAD;
         tok = strtok_r(NULL, ",", &save)) {
        char *eq = strchr(tok, '=');
        if (eq) {
            fds[count] = atoi(eq + 1);
            loaded[count] = 0;
            count++;
        }
    }
    free(buf);

    int remaining = count;
    for (int pass = 0; pass < count && remaining > 0; pass++) {
        int progress = 0;
        for (int i = 0; i < count; i++) {
            if (loaded[i]) continue;
            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fds[i]);
            if (real_dlopen_fn(path, RTLD_NOW | RTLD_GLOBAL)) {
                loaded[i] = 1;
                remaining--;
                progress = 1;
            }
        }
        if (!progress) break;
    }
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
