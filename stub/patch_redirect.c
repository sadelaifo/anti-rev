/*
 * patch_redirect — fopen/fopen64 hot-patch (.pat) redirect, ALL arches.
 *
 * Hooks fopen/fopen64 on ALL arches, plus open/open64/openat/openat64 on
 * x86 ONLY:
 *   - fopen* are mandatory everywhere: glibc opens the underlying file via
 *     a PRIVATE internal open that bypasses the PLT, so even an open/openat
 *     interposer can't see an std::ifstream's fopen64(".pat").
 *   - open/openat: the business ALSO opens .pat directly via open(); on
 *     aarch64 that is already hooked in aarch64_extend_shim (where open
 *     also does the .elf redirect), so here we add open/openat on x86 only
 *     (#ifndef __aarch64__) to avoid a duplicate-symbol clash. x86 has no
 *     .elf path, so .pat is the only reason to hook open there.
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
#include "obfstr.h"     /* MUST be included: obfstr_gen rewrites string
                         * literals to _OBF(...) at codegen time, so every
                         * TU it processes needs the _OBF macro. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>       /* O_RDONLY / O_WRONLY / O_CREAT / AT_FDCWD (x86) */
#include <stdarg.h>      /* va_list for the variadic open* (x86)          */

static FILE *(*g_real_fopen)(const char *, const char *)   = NULL;
static FILE *(*g_real_fopen64)(const char *, const char *) = NULL;
static FILE *(*g_real_fdopen)(int, const char *)           = NULL;
#ifndef __aarch64__
/* x86 hooks open/openat too (.pat only). aarch64's open/openat live in
 * aarch64_extend_shim (also doing the .elf redirect); defining them here
 * on aarch64 would be a duplicate symbol. */
static int (*g_real_open)(const char *, int, ...)          = NULL;
static int (*g_real_open64)(const char *, int, ...)        = NULL;
static int (*g_real_openat)(int, const char *, int, ...)   = NULL;
static int (*g_real_openat64)(int, const char *, int, ...) = NULL;
#endif
static FILE *g_log    = NULL;
static int   g_inited = 0;

static void ensure_inited(void)
{
    if (g_inited) return;
    /* idempotent — other shims' constructors also call it; ensures the
     * daemon socket / __r_EL are read even if we run first. */
    daemon_client_init();
    /* Resolve every real symbol BEFORE publishing g_inited.  The previous
     * code set g_inited=1 up-front, so a second thread racing into the
     * very first fopen could `if (g_inited) return` while g_real_fopen was
     * still NULL — then redirect_common hits `if (!real)` and returns
     * ENOSYS/NULL.  On a multi-threaded business startup that NULLs out an
     * early fopen (e.g. opening/rotating the log file → fprintf on NULL →
     * logging silently dies while the main loop keeps running).  x86 hit
     * this timing window; aarch64 didn't.  Now a racing thread either sees
     * g_inited==0 and re-does the harmless idempotent dlsyms, or sees a
     * fully-populated g_real_* — never a half-initialised NULL. */
    g_real_fopen   = dlsym(RTLD_NEXT, "fopen");
    g_real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    g_real_fdopen  = dlsym(RTLD_NEXT, "fdopen");
#ifndef __aarch64__
    g_real_open     = dlsym(RTLD_NEXT, "open");
    g_real_open64   = dlsym(RTLD_NEXT, "open64");
    g_real_openat   = dlsym(RTLD_NEXT, "openat");
    g_real_openat64 = dlsym(RTLD_NEXT, "openat64");
#endif
    const char *lp = getenv("ANTIREV_PATCH_LOG");
    if (lp && g_real_fopen) {
        /* the REAL fopen, not our interposer, to avoid re-entering us */
        g_log = g_real_fopen(lp, "w");
        if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);
    }
    g_inited = 1;   /* publish LAST, after every g_real_* is stored */
}

/* Initialise at load time — single-threaded, before main() and before any
 * business thread is spawned — so the first fopen/open from ANY thread
 * already sees non-NULL g_real_*.  Belt-and-suspenders with the g_inited
 * ordering above: together they make the lazy path race-free. */
__attribute__((constructor))
static void patch_redirect_ctor(void) { ensure_inited(); }

#define LOG(...) do { if (g_log) fprintf(g_log, __VA_ARGS__); } while (0)

static FILE *redirect_common(const char *path, const char *mode,
                             FILE *(*real)(const char *, const char *))
{
    /* Only the protected (owner) process redirects; read-only modes only
     * ("r"/"rb", no "+"/"w"/"a"). Owner is decided by exe_shim's ctor.
     * Order matters: test the cheap .pat-suffix + mode FIRST so the common
     * non-.pat fopen short-circuits before the daemon_client_is_owner()
     * getpid() syscall — this is a hot path on log-heavy business code. */
    if (patch_is_pat_path(path) && mode && mode[0] == 'r'
        && !strchr(mode, '+') && daemon_client_is_owner()) {
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

#ifndef __aarch64__   /* x86: open/openat .pat redirect (aarch64 has its own) */

/* open()/openat() consume the variadic mode arg for O_CREAT — and also for
 * O_TMPFILE (= O_DIRECTORY | __O_TMPFILE), so test the full mask.  Without
 * this an O_TMPFILE create would pass mode 0 → a 000-perm file. */
#ifdef O_TMPFILE
#  define OPEN_NEEDS_MODE(f) (((f) & O_CREAT) || (((f) & O_TMPFILE) == O_TMPFILE))
#else
#  define OPEN_NEEDS_MODE(f) ((f) & O_CREAT)
#endif

/* Fresh memfd fd for a read-only .pat open in the owner process, or -1 to
 * mean "not handled — fall through to the real call". */
static int open_pat_fd(const char *path, int flags)
{
    /* Cheap suffix + flag test first; getpid()-backed owner check last so
     * the common non-.pat open short-circuits without a syscall. */
    if (patch_is_pat_path(path)
        && !(flags & (O_WRONLY | O_RDWR | O_CREAT))
        && daemon_client_is_owner()) {
        int fd = patch_fetch_fd(path);
        if (fd >= 0) { LOG("open .pat %s -> memfd fd=%d\n", path, fd); return fd; }
        LOG("open .pat %s: daemon miss/err, passthrough\n", path);
    }
    return -1;
}

__attribute__((visibility("default")))
int open(const char *path, int flags, ...)
{
    ensure_inited();
    mode_t mode = 0;
    if (OPEN_NEEDS_MODE(flags)) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    int fd = open_pat_fd(path, flags);
    if (fd >= 0) return fd;
    if (!g_real_open) { errno = ENOSYS; return -1; }
    return g_real_open(path, flags, mode);
}

__attribute__((visibility("default")))
int open64(const char *path, int flags, ...)
{
    ensure_inited();
    mode_t mode = 0;
    if (OPEN_NEEDS_MODE(flags)) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    int fd = open_pat_fd(path, flags);
    if (fd >= 0) return fd;
    if (!g_real_open64) { errno = ENOSYS; return -1; }
    return g_real_open64(path, flags, mode);
}

__attribute__((visibility("default")))
int openat(int dirfd, const char *path, int flags, ...)
{
    ensure_inited();
    mode_t mode = 0;
    if (OPEN_NEEDS_MODE(flags)) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (dirfd == AT_FDCWD || (path && path[0] == '/')) {
        int fd = open_pat_fd(path, flags);
        if (fd >= 0) return fd;
    }
    if (!g_real_openat) { errno = ENOSYS; return -1; }
    return g_real_openat(dirfd, path, flags, mode);
}

__attribute__((visibility("default")))
int openat64(int dirfd, const char *path, int flags, ...)
{
    ensure_inited();
    mode_t mode = 0;
    if (OPEN_NEEDS_MODE(flags)) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (dirfd == AT_FDCWD || (path && path[0] == '/')) {
        int fd = open_pat_fd(path, flags);
        if (fd >= 0) return fd;
    }
    if (!g_real_openat64) { errno = ENOSYS; return -1; }
    return g_real_openat64(dirfd, path, flags, mode);
}

#endif /* !__aarch64__ */
