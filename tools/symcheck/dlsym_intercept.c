/*
 * dlsym_intercept.c — LD_PRELOAD shim that logs every dlsym() lookup and the
 * DSO that ended up *owning* the returned symbol.
 *
 * Why this exists:
 *   LD_DEBUG=bindings only shows *relocation*-based symbol resolution.  A
 *   runtime dlsym(handle, name) is performed by the linker's _dl_sym path and
 *   is NOT a relocation, so LD_DEBUG never logs it — yet its result is
 *   load-order / scope dependent and can therefore change when the same
 *   binaries are loaded via memfd+daemon instead of from disk.  This shim
 *   fills that blind spot: run the workload once plaintext and once encrypted,
 *   then diff the two logs with symdiff.py.  Any symbol whose owning DSO
 *   changed is a dlsym ownership flip.
 *
 *   The "owner" is recovered with dladdr() on the address dlsym() returned.
 *   For a memfd/daemon-loaded lib dladdr reports the symlink path
 *   (/tmp/antirev_<pid>_xxx/<soname>), whose basename is the soname — so the
 *   diff normalizes to basenames and lines up with the plaintext run.
 *
 * Log line (tab-separated), one per dlsym() call:
 *   <caller_basename>\t<DEFAULT|NEXT|HANDLE>\t<symbol>\t<owner_basename>
 *
 * Env:
 *   ANTIREV_DLSYM_LOG=<path>   line-buffered log file (default: stderr).
 *
 * Build:
 *   gcc -shared -fPIC -O2 -D_GNU_SOURCE -o dlsym_intercept.so \
 *       tools/symcheck/dlsym_intercept.c -ldl
 *
 * Run (both plaintext and encrypted, then diff):
 *   LD_PRELOAD=/path/dlsym_intercept.so ANTIREV_DLSYM_LOG=plain.log  <workload>
 *   LD_PRELOAD=/path/dlsym_intercept.so ANTIREV_DLSYM_LOG=enc.log    <workload-encrypted>
 *   python3 tools/symcheck/symdiff.py plain.log enc.log
 *
 * Coexists with antirev_shim (which interposes dlopen, not dlsym); keep both
 * on LD_PRELOAD in the encrypted run.  Lookups the shim itself makes
 * (caller basename "antirev_shim*") are filtered by symdiff.py by default.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Real libc dlsym, resolved once via dlvsym (which we do NOT interpose). */
static void *(*real_dlsym)(void *, const char *) = NULL;

static FILE           *g_log  = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Reentrancy guard: dladdr / fprintf must never recurse back through us. */
static __thread int g_in = 0;

/*
 * Candidate glibc symbol-version nodes for dlsym.  dlvsym(RTLD_NEXT,"dlsym",v)
 * skips our own definition and returns the real one.  The per-arch base
 * version still resolves on glibc >= 2.34 (dl* moved into libc but the old
 * compat version nodes are retained); 2.34 is tried too for completeness.
 */
static const char *const DLSYM_VERS[] = {
#if defined(__aarch64__)
    "GLIBC_2.17",
#elif defined(__x86_64__)
    "GLIBC_2.2.5",
#endif
    "GLIBC_2.34",
    "GLIBC_2.4",
    "GLIBC_2.0",
    NULL,
};

static void bootstrap(void)
{
    if (real_dlsym)
        return;
    for (const char *const *v = DLSYM_VERS; *v; ++v) {
        void *p = dlvsym(RTLD_NEXT, "dlsym", *v);
        if (p) {
            real_dlsym = (void *(*)(void *, const char *)) p;
            return;
        }
    }
}

static void open_log_once(void)
{
    if (g_log)
        return;
    const char *p = getenv("ANTIREV_DLSYM_LOG");
    g_log = (p && *p) ? fopen(p, "w") : stderr;
    if (g_log)
        setvbuf(g_log, NULL, _IOLBF, 0);
}

__attribute__((constructor)) static void init(void)
{
    bootstrap();
    open_log_once();
}

static const char *base_name(const char *path)
{
    if (!path)
        return "?";
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

void *dlsym(void *handle, const char *symbol)
{
    if (!real_dlsym)
        bootstrap();
    if (!real_dlsym)     /* could not resolve real dlsym — nothing we can do */
        return NULL;

    void *ret = real_dlsym(handle, symbol);

    if (g_in)            /* re-entered from our own logging path — pass through */
        return ret;
    g_in = 1;

    open_log_once();
    if (g_log && symbol) {
        const char *kind = (handle == RTLD_DEFAULT) ? "DEFAULT"
                         : (handle == RTLD_NEXT)    ? "NEXT"
                                                    : "HANDLE";
        Dl_info ci, ti;
        void *pc = __builtin_return_address(0);
        const char *caller =
            (dladdr(pc, &ci) && ci.dli_fname) ? base_name(ci.dli_fname) : "?";
        const char *owner =
            !ret ? "<null>"
                 : ((dladdr(ret, &ti) && ti.dli_fname) ? base_name(ti.dli_fname)
                                                       : "?");
        pthread_mutex_lock(&g_lock);
        fprintf(g_log, "%s\t%s\t%s\t%s\n", caller, kind, symbol, owner);
        pthread_mutex_unlock(&g_lock);
    }

    g_in = 0;
    return ret;
}
