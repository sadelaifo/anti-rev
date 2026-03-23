/*
 * antirev exe shim — loaded via LD_PRELOAD into the target binary.
 *
 * Intercepts readlink() and readlinkat() for "/proc/self/exe" (and the
 * equivalent "/proc/<pid>/exe") and returns the real on-disk path stored
 * in ANTIREV_REAL_EXE, which the stub captured before fexecve().
 *
 * Also restores the process comm (visible in ps -o comm, /proc/pid/comm)
 * to the original binary name via prctl(PR_SET_NAME) in a constructor,
 * so that tools like `ps`, `top`, and `pgrep` show the expected name.
 *
 * Without this, any code that calls readlink("/proc/self/exe") would see
 * "/memfd:binary_name (deleted)" and fail to locate config files, sockets,
 * or other resources that are resolved relative to the binary's real path.
 *
 * Uses raw syscalls for the fallthrough so there is no risk of recursion
 * and no dependency on dlsym/RTLD_NEXT.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <fcntl.h>

/* Runs before main() — restore the process name from ANTIREV_REAL_EXE */
__attribute__((constructor))
static void restore_comm(void)
{
    const char *real = getenv("ANTIREV_REAL_EXE");
    if (!real)
        return;
    /* Extract basename */
    const char *base = strrchr(real, '/');
    base = base ? base + 1 : real;
    /* PR_SET_NAME truncates to 15 chars (TASK_COMM_LEN - 1), which matches
     * what ps/top/pgrep display — no need to handle this ourselves. */
    prctl(PR_SET_NAME, (unsigned long)base, 0, 0, 0);
}

static int is_self_exe(const char *path)
{
    if (strcmp(path, "/proc/self/exe") == 0)
        return 1;
    /* also match /proc/<pid>/exe for the current process */
    char pidpath[64];
    snprintf(pidpath, sizeof(pidpath), "/proc/%d/exe", (int)getpid());
    return strcmp(path, pidpath) == 0;
}

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
    /* SYS_readlink doesn't exist on ARM64; use SYS_readlinkat with AT_FDCWD */
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
