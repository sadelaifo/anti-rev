/*
 * patch_redirect — fopen/fopen64 hot-patch (.pat) redirect, ALL arches.
 *
 * glibc's fopen/fopen64 open the underlying file via a PRIVATE internal
 * open that bypasses the PLT, so the open/openat interposers (aarch64
 * only) never see an std::ifstream's fopen64(".pat"). Hooking the stdio
 * entry points here covers .pat uniformly on both arches — and is the
 * ONLY .pat hook on x86 (x86 has no open/openat hook and doesn't need
 * one; the business reads .pat via ifstream → fopen64).
 *
 * On a read-only open of a .pat in the owner (protected) process, fetch
 * the decrypted memfd from the daemon (patch_fetch) and wrap it with the
 * real fdopen, so the caller gets a FILE* over plaintext. No key, no
 * crypto, no discovery file: reuses the inherited daemon connection.
 *
 * The .pat suffix check + OP_GET_PATCH fetch live in patch_fetch.c, shared
 * with aarch64_extend_shim's open/openat path.
 *
 * Env: ANTIREV_PATCH_LOG=<path> — line-buffered log of every decision.
 */
#define _GNU_SOURCE
#include "patch_fetch.h"
#include "daemon_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>

static FILE *(*g_real_fopen)(const char *, const char *)   = NULL;
static FILE *(*g_real_fopen64)(const char *, const char *) = NULL;
static FILE *(*g_real_fdopen)(int, const char *)           = NULL;
static FILE *g_log    = NULL;
static int   g_inited = 0;

static void ensure_inited(void)
{
    if (g_inited) return;
    g_inited = 1;
    /* idempotent — other shims' constructors also call it; ensures the
     * daemon socket / __r_EL are read even if we run first. */
    daemon_client_init();
    g_real_fopen   = dlsym(RTLD_NEXT, "fopen");
    g_real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    g_real_fdopen  = dlsym(RTLD_NEXT, "fdopen");
    const char *lp = getenv("ANTIREV_PATCH_LOG");
    if (lp && g_real_fopen) {
        /* the REAL fopen, not our interposer, to avoid re-entering us */
        g_log = g_real_fopen(lp, "w");
        if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);
    }
}
#define LOG(...) do { if (g_log) fprintf(g_log, __VA_ARGS__); } while (0)

static FILE *redirect_common(const char *path, const char *mode,
                             FILE *(*real)(const char *, const char *))
{
    /* Only the protected (owner) process redirects; read-only modes only
     * ("r"/"rb", no "+"/"w"/"a"). Owner is decided by exe_shim's ctor. */
    if (daemon_client_is_owner() && patch_is_pat_path(path)
        && mode && mode[0] == 'r' && !strchr(mode, '+')) {
        int fd = patch_fetch_fd(path);
        if (fd >= 0 && g_real_fdopen) {
            FILE *f = g_real_fdopen(fd, mode);
            if (f) { LOG("fopen .pat %s -> memfd fd=%d\n", path, fd); return f; }
            close(fd);
        }
        LOG("fopen .pat %s: daemon miss/err, passthrough\n", path);
    }
    if (!real) { errno = ENOSYS; return NULL; }
    return real(path, mode);
}

__attribute__((visibility("default")))
FILE *fopen(const char *path, const char *mode)
{
    ensure_inited();
    return redirect_common(path, mode, g_real_fopen);
}

__attribute__((visibility("default")))
FILE *fopen64(const char *path, const char *mode)
{
    ensure_inited();
    return redirect_common(path, mode, g_real_fopen64);
}
