/*
 * antirev exe shim — loaded via LD_PRELOAD into the target binary.
 *
 * Intercepts:
 *   - readlink/readlinkat for "/proc/self/exe" → returns ANTIREV_REAL_EXE
 *   - __readlink_chk/__readlinkat_chk (fortified variants)
 *   - realpath/canonicalize_file_name for /proc/self/exe → returns real path
 *   - getauxval(AT_EXECFN)                     → returns ANTIREV_REAL_EXE
 *   - prctl(PR_SET_NAME) in constructor         → restores original process name
 *   - program_invocation_name/short_name        → patched in constructor
 *
 * All interceptions only activate for the protected process itself (detected
 * by checking if /proc/self/exe points to a memfd). Child processes that
 * inherit LD_PRELOAD pass through to real libc functions untouched.
 *
 * Without this, code that reads /proc/self/exe would see "/memfd:name (deleted)"
 * and fail to locate config files, sockets, or other resources relative to the
 * binary's real path.
 *
 * Uses raw syscalls for fallthrough — no recursion risk.
 * Linked with -ldl for realpath resolution (dlopen/dlsym to find libc's
 * realpath, since raw syscall fallthrough is not possible for realpath).
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/auxv.h>
#include <fcntl.h>

#include <dlfcn.h>

/* glibc globals — declared in <errno.h> with _GNU_SOURCE */
extern char *program_invocation_name;
extern char *program_invocation_short_name;

/* ------------------------------------------------------------------ */
/*  Owner process tracking                                             */
/* ------------------------------------------------------------------ */

/* PID of the process that was actually protected by antirev.
 * Child processes inherit LD_PRELOAD but should NOT have their
 * /proc/self/exe, realpath, etc. intercepted — they are different
 * binaries and ANTIREV_REAL_EXE refers to the parent. */
static pid_t g_owner_pid = 0;

static int is_owner_process(void)
{
    return g_owner_pid != 0 && getpid() == g_owner_pid;
}

/* ------------------------------------------------------------------ */
/*  Cached libc realpath pointers                                      */
/* ------------------------------------------------------------------ */

static char *(*g_libc_realpath)(const char *, char *) = NULL;
static char *(*g_libc_realpath_chk)(const char *, char *, size_t) = NULL;

/* ------------------------------------------------------------------ */
/*  Constructor: restore process identity                              */
/* ------------------------------------------------------------------ */

static char g_inv_name[4096];
static char g_inv_short[256];

/* Resolve libc realpath using the best available method.
 * Tries dlopen(libc) first (handles multi-shim), falls back to RTLD_NEXT. */
static void resolve_libc_realpath(void)
{
    if (g_libc_realpath)
        return;

    /* Method 1: dlopen libc directly (safe with multiple exe_shims) */
    void *libc = dlopen("libc.so.6", RTLD_LAZY | RTLD_NOLOAD);
    if (libc) {
        g_libc_realpath = dlsym(libc, "realpath");
        g_libc_realpath_chk = dlsym(libc, "__realpath_chk");
        dlclose(libc);
        if (g_libc_realpath)
            return;
    }
    /* Method 2: RTLD_NEXT (works when only one exe_shim loaded) */
    g_libc_realpath = dlsym(RTLD_NEXT, "realpath");
    g_libc_realpath_chk = dlsym(RTLD_NEXT, "__realpath_chk");
}

__attribute__((constructor))
static void restore_identity(void)
{
    /* Resolve libc realpath for ALL processes — needed for the realpath
     * wrapper fallthrough even in non-protected child processes. */
    resolve_libc_realpath();

    const char *real = getenv("ANTIREV_REAL_EXE");
    if (!real)
        return;

    /* Check if this is the protected (owner) process or a child that
     * merely inherited LD_PRELOAD.
     *
     * Primary check: /proc/self/exe → "memfd:..." (normal kernel).
     * Fallback: ANTIREV_MAIN_FD is set and the fd path contains "memfd:"
     *   — covers QEMU user-mode where /proc/self/exe points to the QEMU
     *   binary instead of the guest memfd. */
    int is_owner = 0;
    char exe_buf[256];
    ssize_t n = (ssize_t)syscall(SYS_readlinkat, AT_FDCWD,
                                 "/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
    if (n > 0) {
        exe_buf[n] = '\0';
        if (strstr(exe_buf, "memfd:") != NULL)
            is_owner = 1;
    }

    if (!is_owner) {
        /* QEMU fallback: check if ANTIREV_MAIN_FD points to a memfd */
        const char *main_fd_str = getenv("ANTIREV_MAIN_FD");
        if (main_fd_str) {
            char fd_link[64], fd_target[256];
            snprintf(fd_link, sizeof(fd_link),
                     "/proc/self/fd/%s", main_fd_str);
            ssize_t fn = (ssize_t)syscall(SYS_readlinkat, AT_FDCWD,
                                          fd_link, fd_target,
                                          sizeof(fd_target) - 1);
            if (fn > 0) {
                fd_target[fn] = '\0';
                if (strstr(fd_target, "memfd:") != NULL)
                    is_owner = 1;
            }
        }
    }

    if (!is_owner)
        return;

    /* Consume the marker so forked children don't false-positive. */
    unsetenv("ANTIREV_MAIN_FD");

    g_owner_pid = getpid();

    const char *base = strrchr(real, '/');
    base = base ? base + 1 : real;

    /* Restore process comm (ps -o comm, /proc/pid/comm) */
    prctl(PR_SET_NAME, (unsigned long)base, 0, 0, 0);

    /* Restore program_invocation_name and program_invocation_short_name */
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
    if (!is_owner_process())
        return 0;
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

static char *fill_real_exe(char *resolved)
{
    const char *real = getenv("ANTIREV_REAL_EXE");
    if (!real)
        return NULL;
    size_t len = strlen(real);
    if (!resolved) {
        resolved = malloc(len + 1);
        if (!resolved)
            return NULL;
    }
    memcpy(resolved, real, len + 1);
    return resolved;
}

__attribute__((visibility("default")))
char *realpath(const char *path, char *resolved)
{
    if (path && is_self_exe(path))
        return fill_real_exe(resolved);

    /* Lazy retry: constructor may fail when LD_AUDIT is active (linker
       holds internal locks during early init, breaking dlopen/dlsym). */
    if (!g_libc_realpath)
        resolve_libc_realpath();
    if (g_libc_realpath)
        return g_libc_realpath(path, resolved);
    return NULL;
}

__attribute__((visibility("default")))
char *canonicalize_file_name(const char *path)
{
    if (path && is_self_exe(path))
        return fill_real_exe(NULL);

    if (!g_libc_realpath)
        resolve_libc_realpath();
    if (g_libc_realpath)
        return g_libc_realpath(path, NULL);
    return NULL;
}

__attribute__((visibility("default")))
char *__realpath_chk(const char *path, char *resolved, size_t resolved_len)
{
    if (path && is_self_exe(path)) {
        const char *real = getenv("ANTIREV_REAL_EXE");
        if (real && resolved && strlen(real) >= resolved_len)
            return NULL;
        return fill_real_exe(resolved);
    }

    if (!g_libc_realpath_chk && !g_libc_realpath)
        resolve_libc_realpath();
    if (g_libc_realpath_chk)
        return g_libc_realpath_chk(path, resolved, resolved_len);
    if (g_libc_realpath)
        return g_libc_realpath(path, resolved);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  getauxval interception (Fix #6)                                    */
/* ------------------------------------------------------------------ */

__attribute__((visibility("default")))
unsigned long getauxval(unsigned long type)
{
    if (type == AT_EXECFN && is_owner_process()) {
        const char *real = getenv("ANTIREV_REAL_EXE");
        if (real)
            return (unsigned long)real;
    }

    /* Fallthrough: read /proc/self/auxv via raw syscall */
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/auxv", O_RDONLY);
    if (fd < 0)
        return 0;

    unsigned long result = 0;
    unsigned long pair[2];
    while (syscall(SYS_read, fd, pair, sizeof(pair)) == (long)sizeof(pair)) {
        if (pair[0] == 0)
            break;
        if (pair[0] == type) {
            result = pair[1];
            break;
        }
    }
    syscall(SYS_close, fd);
    return result;
}
