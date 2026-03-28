/*
 * antirev exe shim — loaded via LD_PRELOAD into the target binary.
 *
 * Intercepts:
 *   - readlink/readlinkat for "/proc/self/exe" → returns ANTIREV_REAL_EXE
 *   - realpath/canonicalize_file_name for /proc/self/exe → returns real path
 *   - getauxval(AT_EXECFN)                     → returns ANTIREV_REAL_EXE
 *   - open/openat for the protected binary      → redirects to decrypted memfd
 *   - prctl(PR_SET_NAME) in constructor         → restores original process name
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
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/auxv.h>
#include <fcntl.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/*  Constructor: restore process comm name                             */
/* ------------------------------------------------------------------ */

__attribute__((constructor))
static void restore_comm(void)
{
    const char *real = getenv("ANTIREV_REAL_EXE");
    if (!real)
        return;
    const char *base = strrchr(real, '/');
    base = base ? base + 1 : real;
    /* PR_SET_NAME truncates to 15 chars (TASK_COMM_LEN - 1) */
    prctl(PR_SET_NAME, (unsigned long)base, 0, 0, 0);
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
/*  Helper: check if path matches the protected binary on disk         */
/*  (Fix #3: self-read redirect)                                       */
/* ------------------------------------------------------------------ */

static int is_self_binary(const char *path)
{
    const char *real = getenv("ANTIREV_REAL_EXE");
    if (!real)
        return 0;
    return strcmp(path, real) == 0;
}

static int get_main_fd(void)
{
    const char *s = getenv("ANTIREV_MAIN_FD");
    if (!s)
        return -1;
    return atoi(s);
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

/* ------------------------------------------------------------------ */
/*  open / openat interception (Fix #3: self-read redirect)            */
/* ------------------------------------------------------------------ */

__attribute__((visibility("default")))
int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    /* If opening the protected binary for reading, redirect to decrypted memfd */
    if (is_self_binary(path) && (flags & O_ACCMODE) == O_RDONLY) {
        int main_fd = get_main_fd();
        if (main_fd >= 0) {
            char fd_path[64];
            snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", main_fd);
            return (int)syscall(SYS_openat, AT_FDCWD, fd_path, O_RDONLY);
        }
    }

    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

__attribute__((visibility("default")))
int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (is_self_binary(path) && (flags & O_ACCMODE) == O_RDONLY) {
        int main_fd = get_main_fd();
        if (main_fd >= 0) {
            char fd_path[64];
            snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", main_fd);
            return (int)syscall(SYS_openat, AT_FDCWD, fd_path, O_RDONLY);
        }
    }

    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}
