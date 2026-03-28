/*
 * antirev exe shim — loaded via LD_PRELOAD into the target binary.
 *
 * Intercepts:
 *   - readlink/readlinkat for "/proc/self/exe" → returns ANTIREV_REAL_EXE
 *   - realpath/canonicalize_file_name for /proc/self/exe → returns real path
 *   - getauxval(AT_EXECFN)                     → returns ANTIREV_REAL_EXE
 *   - prctl(PR_SET_NAME) in constructor         → restores original process name
 *   - program_invocation_name/short_name        → patched in constructor
 *
 * Without this, code that reads /proc/self/exe would see "/memfd:name (deleted)"
 * and fail to locate config files, sockets, or other resources relative to the
 * binary's real path. Programs that self-read (checksumming, license verification)
 * would read the encrypted stub+bundle instead of the original binary.
 *
 * Uses raw syscalls for fallthrough — no recursion risk, no dlsym dependency.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/auxv.h>
#include <fcntl.h>

/* glibc globals — declared in <errno.h> with _GNU_SOURCE */
extern char *program_invocation_name;
extern char *program_invocation_short_name;

/* ------------------------------------------------------------------ */
/*  Constructor: restore process comm name                             */
/* ------------------------------------------------------------------ */

/* Static buffers for program_invocation_name/short_name override.
 * Must outlive the process — cannot be stack or freed. */
static char g_inv_name[4096];
static char g_inv_short[256];

__attribute__((constructor))
static void restore_identity(void)
{
    const char *real = getenv("ANTIREV_REAL_EXE");
    if (!real)
        return;
    const char *base = strrchr(real, '/');
    base = base ? base + 1 : real;

    /* Restore process comm (ps -o comm, /proc/pid/comm) */
    prctl(PR_SET_NAME, (unsigned long)base, 0, 0, 0);

    /* Restore program_invocation_name and program_invocation_short_name.
     * These glibc globals are used by logging frameworks, error messages,
     * and some path-discovery code. After fexecve from memfd, they point
     * to the memfd path or argv[0] which may not be the real path. */
    strncpy(g_inv_name, real, sizeof(g_inv_name) - 1);
    g_inv_name[sizeof(g_inv_name) - 1] = '\0';
    strncpy(g_inv_short, base, sizeof(g_inv_short) - 1);
    g_inv_short[sizeof(g_inv_short) - 1] = '\0';

    program_invocation_name       = g_inv_name;
    program_invocation_short_name = g_inv_short;
}

/* ------------------------------------------------------------------ */
/*  Helper: check if path is /proc/self/exe or /proc/<pid>/exe         */
/* ------------------------------------------------------------------ */

static int is_self_exe(const char *path)
{
    if (strcmp(path, "/proc/self/exe") == 0)
        return 1;
    char pidpath[64];
    snprintf(pidpath, sizeof(pidpath), "/proc/%d/exe", (int)getpid());
    return strcmp(path, pidpath) == 0;
}


/* ------------------------------------------------------------------ */
/*  readlink / readlinkat interception                                  */
/* ------------------------------------------------------------------ */

__attribute__((visibility("default")))
ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
    if (is_self_exe(path)) {
        const char *real = getenv("ANTIREV_REAL_EXE");
        if (real) {
            size_t len = strlen(real);
            if (len > bufsiz) len = bufsiz;
            memcpy(buf, real, len);
            return (ssize_t)len;
        }
    }
    return (ssize_t)syscall(SYS_readlinkat, AT_FDCWD, path, buf, bufsiz);
}

__attribute__((visibility("default")))
ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    if (is_self_exe(path)) {
        const char *real = getenv("ANTIREV_REAL_EXE");
        if (real) {
            size_t len = strlen(real);
            if (len > bufsiz) len = bufsiz;
            memcpy(buf, real, len);
            return (ssize_t)len;
        }
    }
    return (ssize_t)syscall(SYS_readlinkat, dirfd, path, buf, bufsiz);
}

/* Fortified variants — called when compiled with _FORTIFY_SOURCE >= 1 */
__attribute__((visibility("default")))
ssize_t __readlink_chk(const char *path, char *buf, size_t bufsiz,
                       size_t buflen)
{
    (void)buflen;
    return readlink(path, buf, bufsiz);
}

__attribute__((visibility("default")))
ssize_t __readlinkat_chk(int dirfd, const char *path, char *buf,
                         size_t bufsiz, size_t buflen)
{
    (void)buflen;
    return readlinkat(dirfd, path, buf, bufsiz);
}

/* ------------------------------------------------------------------ */
/*  realpath / canonicalize_file_name interception                     */
/*  glibc's realpath() uses internal __readlink which bypasses         */
/*  LD_PRELOAD, so we must intercept realpath itself.                  */
/*  Qt's QCoreApplication::applicationFilePath() uses this path.       */
/* ------------------------------------------------------------------ */

__attribute__((visibility("default")))
char *realpath(const char *path, char *resolved)
{
    if (path && is_self_exe(path)) {
        const char *real = getenv("ANTIREV_REAL_EXE");
        if (real) {
            /* Resolve ANTIREV_REAL_EXE through the real realpath
             * by calling the raw syscall path resolution.
             * We can't call libc realpath (that's us), so we just
             * return the path directly — it's already absolute. */
            size_t len = strlen(real);
            if (!resolved) {
                resolved = malloc(len + 1);
                if (!resolved)
                    return NULL;
            }
            memcpy(resolved, real, len + 1);
            return resolved;
        }
    }

    /* Fallthrough: use dlsym to find the real realpath in libc */
    static char *(*real_realpath)(const char *, char *) = NULL;
    if (!real_realpath) {
        real_realpath = dlsym(RTLD_NEXT, "realpath");
        if (!real_realpath)
            return NULL;
    }
    return real_realpath(path, resolved);
}

/* GNU extension — same as realpath(path, NULL) */
__attribute__((visibility("default")))
char *canonicalize_file_name(const char *path)
{
    return realpath(path, NULL);
}

/* __realpath_chk — fortified version called when _FORTIFY_SOURCE is enabled */
__attribute__((visibility("default")))
char *__realpath_chk(const char *path, char *resolved, size_t resolved_len)
{
    if (path && is_self_exe(path)) {
        const char *real = getenv("ANTIREV_REAL_EXE");
        if (real) {
            size_t len = strlen(real);
            if (resolved && len >= resolved_len) {
                return NULL;  /* buffer too small */
            }
            if (!resolved) {
                resolved = malloc(len + 1);
                if (!resolved)
                    return NULL;
            }
            memcpy(resolved, real, len + 1);
            return resolved;
        }
    }

    static char *(*real_realpath_chk)(const char *, char *, size_t) = NULL;
    if (!real_realpath_chk) {
        real_realpath_chk = dlsym(RTLD_NEXT, "__realpath_chk");
        if (!real_realpath_chk)
            return realpath(path, resolved);
    }
    return real_realpath_chk(path, resolved, resolved_len);
}

/* ------------------------------------------------------------------ */
/*  getauxval interception (Fix #6)                                    */
/* ------------------------------------------------------------------ */

__attribute__((visibility("default")))
unsigned long getauxval(unsigned long type)
{
    if (type == AT_EXECFN) {
        const char *real = getenv("ANTIREV_REAL_EXE");
        if (real)
            return (unsigned long)real;
    }

    /* Fallthrough: walk the auxiliary vector directly.
     * The auxv sits in memory right after the environment strings:
     *   [argv...] NULL [envp...] NULL [auxv_t entries...] AT_NULL
     * We access it via /proc/self/auxv to avoid fragile stack walking. */
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/auxv", O_RDONLY);
    if (fd < 0)
        return 0;

    unsigned long result = 0;
    unsigned long pair[2];  /* auxv_t: {a_type, a_val} */
    while (syscall(SYS_read, fd, pair, sizeof(pair)) == (long)sizeof(pair)) {
        if (pair[0] == 0)  /* AT_NULL */
            break;
        if (pair[0] == type) {
            result = pair[1];
            break;
        }
    }
    syscall(SYS_close, fd);
    return result;
}

/* open/openat interception removed — intercepting these broadly caused
 * breakage in normal file operations (config file loading, Qt plugins, etc.).
 * The self-read redirect (Fix #3) is deferred until a targeted solution
 * can be implemented without side effects. */
