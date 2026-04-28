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
#include <dirent.h>

#include <dlfcn.h>

#include "obf.h"

/* glibc globals — declared in <errno.h> with _GNU_SOURCE */
extern char *program_invocation_name;
extern char *program_invocation_short_name;

/* ------------------------------------------------------------------ */
/*  Owner process tracking                                             */
/* ------------------------------------------------------------------ */

/* PID of the process that was actually protected by antirev.
 * Child processes inherit LD_PRELOAD but should NOT have their
 * /proc/self/exe, realpath, etc. intercepted — they are different
 * binaries and ANTIREV_REAL_EXE refers to the parent.
 *
 * On x86_64, ownership is detected lazily: interceptor calls that
 * arrive before the shim's constructor (e.g. from a C++ global
 * static initializer in a DT_NEEDED lib) fall into the lazy path
 * and probe /proc/self/exe themselves.  On aarch64 we keep master's
 * constructor-only detection (the ARM build has never needed the
 * lazy path in practice and this keeps the runtime code identical
 * to what's been field-tested on ARM). */
static pid_t g_owner_pid = 0;
#if !defined(__aarch64__)
static int g_owner_checked = 0; /* 1 once constructor or lazy probe decided */
#endif

static int is_owner_process(void)
{
#if defined(__aarch64__)
    return g_owner_pid != 0 && getpid() == g_owner_pid;
#else
    if (g_owner_checked)
        return g_owner_pid != 0 && getpid() == g_owner_pid;

    /* Constructor hasn't decided yet — probe /proc/self/exe on the fly.
     * Required when DT_NEEDED libs have C++ static initializers that
     * call readlink/realpath/getauxval before restore_identity() runs. */
    if (!getenv(OBF(ENV_REAL_EXE)))
        return 0;
    char exe_buf[256];
    ssize_t n = (ssize_t) syscall(SYS_readlinkat, AT_FDCWD, OBF(PATH_PROC_SELF_EXE), exe_buf, sizeof(exe_buf) - 1);
    if (n > 0) {
        exe_buf[n] = '\0';
        if (strstr(exe_buf, OBF(MEMFD_NEEDLE)) != NULL) {
            g_owner_pid = getpid();
            g_owner_checked = 1;
            return 1;
        }
    }
    return 0;
#endif
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

/* Rebuild the colon-separated env var `varname`, dropping any entry
 * that starts with `prefix`.  Unsets the var if nothing remains.
 * Used during constructor-time env hygiene so children inherit a
 * clean LD_PRELOAD / LD_LIBRARY_PATH when we decide they shouldn't
 * see our shim fds / temp dirs. */
static void strip_env_path_entries(const char *varname, const char *prefix) {
    const char *val = getenv(varname);
    if (!val || !strstr(val, prefix))
        return;

    size_t plen = strlen(prefix);
    char buf[8192];
    size_t off = 0;
    const char *p = val;
    while (*p) {
        const char *end = p;
        while (*end && *end != ':')
            end++;
        size_t seg = (size_t) (end - p);
        if (seg > 0 && strncmp(p, prefix, plen) != 0) {
            if (off + seg + 2 >= sizeof(buf))
                break;
            if (off > 0)
                buf[off++] = ':';
            memcpy(buf + off, p, seg);
            off += seg;
        }
        p = (*end == ':') ? end + 1 : end;
    }
    buf[off] = '\0';
    if (off > 0)
        setenv(varname, buf, 1);
    else
        unsetenv(varname);
}

/* ------------------------------------------------------------------ */
/*  Constructor helpers (arch-neutral)                                  */
/* ------------------------------------------------------------------ */

/* Returns 1 iff this process is the antirev owner.
 *
 * Primary check: readlinkat("/proc/self/exe") contains "memfd:"
 *   — the normal kernel path.
 * Fallback: ANTIREV_MAIN_FD set with an fd that reads back as a memfd
 *   — covers QEMU user-mode where /proc/self/exe points to the QEMU
 *   binary instead of the guest memfd.  In QEMU even the fd link
 *   readlink may fail; presence of ANTIREV_MAIN_FD alone is trusted
 *   because the stub only ever injects it into the direct fexecve
 *   target, never into children.
 *
 * Consumes ANTIREV_MAIN_FD on return so forked+exec'd children never
 * inherit the marker and false-positive as owner. */
static int detect_owner(void) {
    int is_owner = 0;
    char exe_buf[256];
    ssize_t n = (ssize_t) syscall(SYS_readlinkat, AT_FDCWD, OBF(PATH_PROC_SELF_EXE), exe_buf, sizeof(exe_buf) - 1);
    if (n > 0) {
        exe_buf[n] = '\0';
        if (strstr(exe_buf, OBF(MEMFD_NEEDLE)) != NULL)
            is_owner = 1;
    }

    if (!is_owner) {
        const char *main_fd_str = getenv(OBF(ENV_MAIN_FD));
        if (main_fd_str) {
            char fd_link[64], fd_target[256];
            snprintf(fd_link, sizeof(fd_link), OBF(FMT_PROC_SELF_FD_S), main_fd_str);
            ssize_t fn = (ssize_t) syscall(SYS_readlinkat, AT_FDCWD, fd_link, fd_target, sizeof(fd_target) - 1);
            if (fn > 0) {
                fd_target[fn] = '\0';
                if (strstr(fd_target, OBF(MEMFD_NEEDLE)) != NULL)
                    is_owner = 1;
            }
            /* QEMU: readlinkat didn't confirm "memfd:" — trust presence alone. */
            if (!is_owner)
                is_owner = 1;
        }
    }

    unsetenv(OBF(ENV_MAIN_FD));
    return is_owner;
}

/* Scrub antirev env from a non-owner child (e.g. WAE.elf loaded by
 * helf loadpg).  ANTIREV_FD_MAP would otherwise make dlopen_shim
 * redirect dlopen calls; antirev entries on LD_PRELOAD /
 * LD_LIBRARY_PATH would keep our shim fds + symlink dir visible. */
static void scrub_nonowner_env(void) {
    unsetenv(OBF(ENV_FD_MAP));
    unsetenv(OBF(ENV_REAL_EXE));
    strip_env_path_entries(OBF(ENV_LD_PRELOAD), OBF(PATH_PROC_SELF_FD_DIR));
    strip_env_path_entries(OBF(ENV_LD_LIBRARY_PATH), OBF(PREFIX_SYMLINK_DIR));
}

/* Close DT_NEEDED memfds now that glibc's dynamic linker has finished
 * mapping them.  The fds are pure bookkeeping at this point — the
 * libraries stay live via their mmap references — but closing them
 * frees fd-table slots so later socket()/open()/memfd_create() calls
 * land at low fd numbers.  Matters for code that still uses select()
 * (FD_SETSIZE=1024).
 *
 * Set by stub.c only on the symlink-dir code path (has_needed_section).
 * Unset immediately so fork()ed children don't misinterpret stale fds. */
static void close_dt_needed_fds(void) {
    const char *close_list = getenv(OBF(ENV_CLOSE_FDS));
    if (close_list && *close_list) {
        const char *p = close_list;
        while (*p) {
            char *end = NULL;
            long fd = strtol(p, &end, 10);
            if (end == p)
                break;
            if (fd > 2)
                (void)syscall(SYS_close, (int)fd);
            if (*end != ',')
                break;
            p = end + 1;
        }
    }
    unsetenv(OBF(ENV_CLOSE_FDS));
}

/* Restore /proc/self/comm (ps -o comm) and the glibc
 * program_invocation_name{,_short_name} globals so the protected
 * process presents under its real name instead of "memfd:...". */
static void restore_process_name(const char *real) {
    const char *base = strrchr(real, '/');
    base = base ? base + 1 : real;

    prctl(PR_SET_NAME, (unsigned long)base, 0, 0, 0);

    strncpy(g_inv_name, real, sizeof(g_inv_name) - 1);
    g_inv_name[sizeof(g_inv_name) - 1] = '\0';
    strncpy(g_inv_short, base, sizeof(g_inv_short) - 1);
    g_inv_short[sizeof(g_inv_short) - 1] = '\0';

    program_invocation_name = g_inv_name;
    program_invocation_short_name = g_inv_short;
}

/* ------------------------------------------------------------------ */
/*  Constructor (per-arch variants, single #ifdef)                      */
/*                                                                      */
/*  Keep the two arches as dedicated functions instead of scattering    */
/*  #ifdefs through a shared body.  The arch-specific differences are:  */
/*    - x86 maintains g_owner_checked so the lazy probe in              */
/*      is_owner_process() short-circuits once the constructor runs.    */
/*    - aarch64 additionally scrubs ANTIREV_FD_MAP / LD_PRELOAD /       */
/*      LD_LIBRARY_PATH in the owner (the ARM business stack closes     */
/*      random fds; children inheriting /proc/self/fd/N preloads fail). */
/*    - x86 deliberately skips that scrub — test_fork_same_lib needs a  */
/*      fork+exec child to inherit the daemon-backed shim env.          */
/* ------------------------------------------------------------------ */
/* Captured at constructor time so the atexit handler still has the
 * path even if something in the protected exe later unsets the env
 * var.  Also lets us own the lifetime exactly: registered iff we're
 * the owner. */
static char g_symlink_dir[256] = {0};

/* atexit handler: rm -rf the symlink dir we (the owner stub) created.
 * Runs LIFO with respect to other atexit handlers; since exe_shim's
 * ctor runs very early, this fires very late — after most shutdown
 * work that might still walk the dir.
 *
 * Doesn't fire on _exit / SIGKILL / segfault — that's the daemon's
 * sweep_dead_symlink_dirs job. */
static void cleanup_symlink_dir(void)
{
    if (!is_owner_process()) return;
    if (!g_symlink_dir[0]) return;

    DIR *dp = opendir(g_symlink_dir);
    if (dp) {
        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            char path[512];
            snprintf(path, sizeof(path), "%.255s/%.255s", g_symlink_dir, de->d_name);
            unlink(path);
        }
        closedir(dp);
    }
    rmdir(g_symlink_dir);
}

/* Capture the symlink dir path and register the atexit handler.
 * Idempotent — safe to call from both arch-specific ctor branches. */
static void register_symlink_dir_cleanup(void)
{
    const char *dir = getenv(OBF(ENV_SYMLINK_DIR));
    if (!dir || !*dir) return;
    if (g_symlink_dir[0]) return; /* already registered */
    snprintf(g_symlink_dir, sizeof(g_symlink_dir), "%s", dir);
    atexit(cleanup_symlink_dir);
}

#if defined(__aarch64__)
__attribute__((constructor)) static void restore_identity(void) {
    resolve_libc_realpath();

    const char *real = getenv(OBF(ENV_REAL_EXE));
    if (!real)
        return;

    if (!detect_owner()) {
        scrub_nonowner_env();
        return;
    }

    g_owner_pid = getpid();
    close_dt_needed_fds();

    /* Capture the symlink dir BEFORE the owner-scrub strips
     * /tmp/antirev_* entries from LD_LIBRARY_PATH (and before
     * anything else might unset the env var). */
    register_symlink_dir_cleanup();

    /* aarch64-only owner scrub — see comment above. */
    strip_env_path_entries(OBF(ENV_LD_PRELOAD), OBF(PATH_PROC_SELF_FD_DIR));
    strip_env_path_entries(OBF(ENV_LD_LIBRARY_PATH), OBF(PREFIX_SYMLINK_DIR));
    unsetenv(OBF(ENV_FD_MAP));

    restore_process_name(real);
}
#else /* !__aarch64__ : x86_64 */
__attribute__((constructor)) static void restore_identity(void) {
    resolve_libc_realpath();

    const char *real = getenv(OBF(ENV_REAL_EXE));
    if (!real)
        return;

    if (!detect_owner()) {
        scrub_nonowner_env();
        g_owner_checked = 1;
        return;
    }

    g_owner_pid = getpid();
    g_owner_checked = 1;

    close_dt_needed_fds();
    register_symlink_dir_cleanup();
    restore_process_name(real);
}
#endif

/* ------------------------------------------------------------------ */
/*  Helper: check if path is /proc/self/exe or /proc/<pid>/exe         */
/* ------------------------------------------------------------------ */

static int is_self_exe(const char *path)
{
    if (!is_owner_process())
        return 0;
    if (strcmp(path, OBF(PATH_PROC_SELF_EXE)) == 0)
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
        const char *real = getenv(OBF(ENV_REAL_EXE));
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
        const char *real = getenv(OBF(ENV_REAL_EXE));
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
    const char *real = getenv(OBF(ENV_REAL_EXE));
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
        const char *real = getenv(OBF(ENV_REAL_EXE));
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
        const char *real = getenv(OBF(ENV_REAL_EXE));
        if (real)
            return (unsigned long)real;
    }

    /* Fallthrough: read /proc/self/auxv via raw syscall */
    int fd = (int)syscall(SYS_openat, AT_FDCWD, OBF(PATH_PROC_SELF_AUXV), O_RDONLY);
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

/* popen / pclose interception previously lived here.  Moved to
 * stub/aarch64_extend_shim.c (aarch64-only) — it is aarch64-specific work and
 * now lives alongside the ANTI_LoadProcess hijack. */
