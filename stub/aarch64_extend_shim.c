/*
 * antirev aarch64-extend shim — loaded via LD_PRELOAD into the target
 * binary.  aarch64-only.  Houses two unrelated interceptors that share
 * an aarch64-specific rationale:
 *
 *   1. ANTI_LoadProcess(struct ANTI_ProcessInfo *) — business API that
 *      loads a program (PG) ELF from the path held in info->ltrBin.
 *      We swap the path with "/proc/self/fd/N" where N is a memfd
 *      populated with the decrypted .elf served by the antirev daemon,
 *      so the on-disk ciphertext is never exposed to ANTI_LoadProcess's
 *      open()/read()/mmap() sequence.  ANTI_UnLoadProcess is NOT
 *      intercepted — it takes a pgId handle (not a path) and the memfd
 *      stays pinned by the kernel mapping anyway.
 *
 *   2. popen / pclose — glibc's popen uses vfork (CLONE_VM|CLONE_VFORK)
 *      which corrupts parent state in antirev-protected aarch64
 *      processes (memfd-heavy, LD_PRELOAD shims active, ARM Crypto
 *      Extensions in use).  We override with a plain fork+exec pair,
 *      plus our own FILE*→pid table so pclose reaps the right child.
 *      Previously lived in exe_shim.c; moved here so exe_shim stays
 *      arch-neutral.
 *
 * Daemon I/O (socket fd, encrypted-name set, __r_FM) is
 * handled by the shared daemon_client module — see daemon_client.h.
 */

#if !defined(__aarch64__)
/* Non-aarch64 builds: empty translation unit.  CMake only compiles this
 * file on aarch64, but guard defensively in case someone invokes gcc
 * directly. */
typedef int _aarch64_extend_shim_empty;
#else

#define _GNU_SOURCE
#include "daemon_client.h"
#include "obfstr.h"     /* compile-time string-literal obfuscation */

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------ */
/*  Owner-process detection (independent copy — exe_shim is a sibling  */
/*  shim, not a dependency)                                            */
/* ------------------------------------------------------------------ */

static pid_t g_owner_pid = 0;

static int is_owner_process(void)
{
    return g_owner_pid != 0 && getpid() == g_owner_pid;
}

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

/* Cache of pgName → (memfd fd, stable "/proc/self/fd/N" string).
 *
 * Pinned for process lifetime on both axes:
 *   - the fd stays open so /proc/self/fd/N remains a valid path for
 *     any code that retains the rewritten ltrBin or reopens it later
 *     (business loader frequently does: header-peek openat, close,
 *     big anon mmap, then re-openat the same path for content reads);
 *   - the path string lives in this static array so we can hand its
 *     pointer to the caller's ltrBin and never restore/free it.  The
 *     memfd mapping itself is pinned by the loader's mmap on top of
 *     it independently of our fd. */
#define FD_PATH_MAX 32   /* "/proc/self/fd/2147483647" + NUL fits in ~25 */
static char g_cache_names[DC_MAX_FILES][DC_MAX_NAME + 1];
static int  g_cache_fds[DC_MAX_FILES];
static char g_cache_paths[DC_MAX_FILES][FD_PATH_MAX];
static int  g_cache_count = 0;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Optional log sink (ANTIREV_AARCH64_EXTEND_LOG=<path>). */
static FILE *g_log = NULL;
#define LOG(...) do { if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)

/* ------------------------------------------------------------------ */
/*  Little-endian helpers                                              */
/* ------------------------------------------------------------------ */

static inline void put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static inline uint32_t u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/*  Lookups                                                             */
/* ------------------------------------------------------------------ */

static int cache_find(const char *base)
{
    for (int i = 0; i < g_cache_count; i++)
        if (strcmp(g_cache_names[i], base) == 0) return i;
    return -1;
}

/* Ask the daemon for `base` and return the received fd, or -1 on failure.
 * Caller must hold g_lock. */
static int fetch_one(const char *base)
{
    if (daemon_client_sock() < 0) return -1;
    uint16_t nlen = (uint16_t)strlen(base);
    if (nlen == 0 || nlen > DC_MAX_NAME) return -1;

    uint8_t req[2 + DC_MAX_NAME];
    put_u16le(req, nlen);
    memcpy(req + 2, base, nlen);

    uint32_t op = 0, plen = 0;
    uint8_t  payload[16];
    int      fds[1];
    int      nfds = 0;
    int      send_ok, recv_ok;

    /* Hold the daemon-client IO lock across send + recv so a concurrent
     * dlopen_shim::fetch_closure on the same socket can't steal our
     * reply. */
    daemon_client_io_lock();
    send_ok = (daemon_client_send(DC_OP_GET_LIB, req, (uint32_t)(2 + nlen)) == 0);
    recv_ok = send_ok && (daemon_client_recv(&op, payload, &plen, sizeof(payload),
                                              fds, &nfds, 1) == 0);
    daemon_client_io_unlock();

    if (!send_ok) {
        LOG("  send OP_GET_LIB(%s) failed\n", base);
        return -1;
    }
    if (!recv_ok) {
        LOG("  recv OP_LIB(%s) failed\n", base);
        return -1;
    }
    if (op != DC_OP_LIB || plen < 4) {
        LOG("  bad reply for %s: op=0x%x plen=%u\n", base, op, plen);
        for (int i = 0; i < nfds; i++) close(fds[i]);
        return -1;
    }
    uint32_t status = u32le(payload);
    if (status != DC_ST_OK || nfds != 1) {
        LOG("  daemon status=%u nfds=%d for %s\n", status, nfds, base);
        for (int i = 0; i < nfds; i++) close(fds[i]);
        return -1;
    }
    return fds[0];
}

/* Resolve pgName basename to a stable "/proc/self/fd/N" path string
 * whose lifetime is the process's.  Returns a pointer into the
 * per-entry cache (do NOT free) on success, NULL if not available
 * (caller should pass through unmodified).
 *
 * Returning a stable persistent path — not a stack buffer, and never
 * restored — is what keeps the rewrite durable across loader patterns
 * that re-read info->ltrBin after ANTI_LoadProcess returns (deferred
 * worker threads, multi-stage loaders that openat → close → mmap →
 * re-openat, etc.). */
static const char *resolve_path(const char *base)
{
    pthread_mutex_lock(&g_lock);

    int idx = cache_find(base);
    if (idx >= 0) {
        const char *p = g_cache_paths[idx];
        pthread_mutex_unlock(&g_lock);
        LOG("  cache-hit %s -> %s\n", base, p);
        return p;
    }

    int fd = -1;
    /* Track whether this fd is one we own (received fresh via SCM_RIGHTS
     * from the daemon and must close ourselves on overflow) or one we
     * merely looked up in __r_FM (still referenced by the env
     * var and the stub's symlink dir — closing it would invalidate the
     * /proc/self/fd/N path for every other consumer). */
    int fd_is_owned = 0;

    /* Eager path first (stub pre-populated fd map). */
    if (daemon_client_have_fd_map()) {
        fd = daemon_client_eager_lookup_fd(base);
        if (fd >= 0) LOG("  eager-hit %s -> fd=%d\n", base, fd);
    }

    /* Daemon path. */
    if (fd < 0 && daemon_client_sock() >= 0 && daemon_client_is_encrypted(base)) {
        fd = fetch_one(base);
        if (fd >= 0) {
            LOG("  daemon-hit %s -> fd=%d\n", base, fd);
            fd_is_owned = 1;
        }
    }

    if (fd < 0) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    const char *out = NULL;
    int stored = 0;
    if (g_cache_count < DC_MAX_FILES) {
        size_t bl = strlen(base);
        if (bl <= DC_MAX_NAME) {
            memcpy(g_cache_names[g_cache_count], base, bl + 1);
            g_cache_fds[g_cache_count] = fd;
            snprintf(g_cache_paths[g_cache_count], FD_PATH_MAX,
                     "/proc/self/fd/%d", fd);
            out = g_cache_paths[g_cache_count];
            g_cache_count++;
            stored = 1;
        }
    }
    if (!stored && fd_is_owned) {
        LOG("  cache full / name too long, closing fresh daemon fd=%d\n", fd);
        close(fd);
    }

    pthread_mutex_unlock(&g_lock);
    return out;
}

/* ------------------------------------------------------------------ */
/*  Constructor                                                         */
/* ------------------------------------------------------------------ */

__attribute__((constructor))
static void init_aarch64_extend_shim(void)
{
    const char *logpath = getenv("ANTIREV_AARCH64_EXTEND_LOG");
    if (logpath && *logpath) {
        g_log = fopen(logpath, "w");
        if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);
    }

    /* Owner detection: same criterion as exe_shim — /proc/self/exe is
     * a memfd path for the protected process, and child processes
     * that merely inherited LD_PRELOAD see a normal path. */
    char exe_buf[256];
    ssize_t n = (ssize_t)syscall(SYS_readlinkat, AT_FDCWD,
                                 "/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
    int is_owner = 0;
    if (n > 0) {
        exe_buf[n] = '\0';
        if (strstr(exe_buf, "memfd:") != NULL) is_owner = 1;
    }
    if (!is_owner) {
        /* QEMU fallback: trust __r_MF's presence. */
        if (getenv("__r_MF")) is_owner = 1;
    }
    /* exe_shim's ctor runs before ours and consumes __r_MF (unsetenv).
     * Under QEMU /proc/self/exe is the qemu binary, not a memfd, so both
     * checks above miss — fall back to the ownership decision exe_shim
     * stashed in the shared daemon_client state. */
    if (!is_owner && daemon_client_is_owner()) is_owner = 1;
    if (is_owner) g_owner_pid = getpid();

    LOG("[aarch64_extend_shim] ctor pid=%d owner=%d\n", getpid(), is_owner);

    daemon_client_init();

    LOG("[aarch64_extend_shim] sock=%d fd_map=%s\n",
        daemon_client_sock(),
        daemon_client_have_fd_map() ? "yes" : "no");
}

/* ------------------------------------------------------------------ */
/*  ANTI_LoadProcess interception                                       */
/*                                                                      */
/*  struct ANTI_ProcessInfo {                                           */
/*      const char *pgName;     // offset 0                            */
/*      const char *ltrBin;     // offset 8  ← the path we rewrite     */
/*      uint64_t    memSize;                                           */
/*      uint32_t    cpuNum;                                            */
/*      uint32_t    nodeId;                                            */
/*      uint64_t    cpuMask;                                           */
/*      void      (*func)(...); // ANTI_ProcessAbnormalCb              */
/*  };                                                                 */
/*                                                                      */
/*  We only touch the first two fields.  The rest of the struct is     */
/*  forwarded verbatim to the real ANTI_LoadProcess — its exact size   */
/*  and layout past ltrBin does not affect our rewrite.                */
/* ------------------------------------------------------------------ */

struct anti_processinfo_head {
    const char *pgName;
    const char *ltrBin;
    /* remainder opaque */
};

static int (*g_real_anti_loadprocess)(void *) = NULL;

static void resolve_real_anti_loadprocess(void)
{
    if (g_real_anti_loadprocess) return;
    g_real_anti_loadprocess = dlsym(RTLD_NEXT, "ANTI_LoadProcess");
}

__attribute__((visibility("default")))
int ANTI_LoadProcess(void *info_raw)
{
    resolve_real_anti_loadprocess();

    if (!info_raw || !g_real_anti_loadprocess) {
        /* Nothing to dispatch to — let whatever caller we have crash on
         * its own terms rather than returning a bogus success code. */
        return g_real_anti_loadprocess ? g_real_anti_loadprocess(info_raw) : -1;
    }

    /* Only rewrite for the protected process itself.  Child processes
     * that dlopen a lib exporting ANTI_LoadProcess must see plaintext
     * paths. */
    if (!is_owner_process()) {
        LOG("ANTI_LoadProcess: non-owner, passthrough\n");
        return g_real_anti_loadprocess(info_raw);
    }

    struct anti_processinfo_head *info =
        (struct anti_processinfo_head *)info_raw;
    const char *ltrBin = info->ltrBin;
    if (!ltrBin || !*ltrBin) {
        LOG("ANTI_LoadProcess: null/empty ltrBin, passthrough\n");
        return g_real_anti_loadprocess(info_raw);
    }

    const char *base = strrchr(ltrBin, '/');
    base = base ? base + 1 : ltrBin;

    const char *stable_path = resolve_path(base);
    if (!stable_path) {
        LOG("ANTI_LoadProcess(pg=%s path=%s): no memfd, passthrough\n",
            info->pgName ? info->pgName : "?", ltrBin);
        return g_real_anti_loadprocess(info_raw);
    }

    /* Rewrite ltrBin to the cached "/proc/self/fd/N" string and do
     * NOT restore after the real call returns.  Business loaders
     * commonly defer actual content reads (openat / mmap) to a
     * worker thread or to a later API call, retaining the ltrBin
     * pointer; if we restored here, those late reads would land on
     * the original on-disk path and read ciphertext.
     *
     * Safety: the stable_path string lives in a static per-entry
     * cache (never freed) and the memfd fd is pinned open for the
     * process lifetime, so any subsequent openat on this path will
     * continue to resolve to the same memfd. */
    const char *saved = info->ltrBin;
    info->ltrBin = stable_path;
    LOG("ANTI_LoadProcess(pg=%s): rewrote ltrBin %s -> %s (persistent)\n",
        info->pgName ? info->pgName : "?", saved, stable_path);

    int rc = g_real_anti_loadprocess(info_raw);

    LOG("ANTI_LoadProcess(pg=%s): rc=%d\n",
        info->pgName ? info->pgName : "?", rc);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  openat / newfstatat / stat interception for encrypted .elf paths   */
/*                                                                      */
/*  The ANTI_LoadProcess symbol hijack above can only fire if the       */
/*  business code calls ANTI_LoadProcess via the PLT / GOT (cross-DSO   */
/*  lookup), so LD_PRELOAD interposition beats the real symbol.         */
/*  Real-world business .so's frequently build with -Bsymbolic or       */
/*  dlsym(handle, ...) to their own local copy, which bypasses          */
/*  LD_PRELOAD entirely — our struct-level hook never sees the call.    */
/*                                                                      */
/*  Fallback: intercept at the libc file-IO layer.  Whoever ends up     */
/*  opening/stat'ing the .elf path goes through libc's openat /         */
/*  newfstatat / stat / lstat — which ARE resolved cross-DSO and can    */
/*  be interposed.  We rewrite any path whose basename is an encrypted  */
/*  .elf asset to "/proc/self/fd/N" (backed by the cached memfd) and    */
/*  hand the call to the real libc function.  Kernel resolves the       */
/*  magic /proc symlink and the loader reads plaintext ELF bytes.       */
/*                                                                      */
/*  Scope:                                                              */
/*   - owner process only (child processes see plaintext).              */
/*   - basename must end in ".elf" AND be listed in __r_EL —  */
/*     scoping to .elf keeps us out of dlopen's and glibc's internal    */
/*     openat traffic on .so paths (handled by dlopen_shim).            */
/*   - paths already under /proc/self/fd/ pass through untouched to    */
/*     avoid any chance of recursion via real_openat.                   */
/* ------------------------------------------------------------------ */

/* Perform the real file-IO via RAW SYSCALLS instead of dlsym'ing libc
 * symbols.
 *
 * Why: glibc >= 2.33 makes stat/lstat/fstatat header *inlines* (not
 * exported symbols), and NO glibc ever exports a symbol literally
 * named "newfstatat" (that is the syscall name; libc's API symbols are
 * fstatat / __fxstatat).  The previous
 * dlsym(RTLD_NEXT,"newfstatat"/"stat"/"lstat") therefore returned NULL
 * on modern glibc, so every interceptor fell through to ENOSYS — and
 * because these functions are LD_PRELOAD-interposed *process-wide*,
 * EVERY stat()/lstat()/open()/access() in the protected process began
 * returning ENOSYS, so nothing could start.  Raw syscalls have no
 * libc-symbol dependency and are glibc-version-independent (same
 * pattern the shim already uses for memfd_create).  This TU only
 * compiles on aarch64, so the aarch64 syscall numbers are fixed.
 *
 * glibc's syscall() still returns -1 and sets errno on failure, so the
 * errno semantics business code observes are unchanged.  On aarch64
 * there is one canonical struct stat layout (no _FILE_OFFSET_BITS
 * split, no _STAT_VER, native 64-bit time), so the kernel's
 * newfstatat fills the same struct the caller expects — identical to
 * what glibc's own thin aarch64 wrapper would have copied. */
#ifndef __NR_openat
#  define __NR_openat     56
#endif
#ifndef __NR_newfstatat
#  define __NR_newfstatat 79
#endif
#ifndef __NR_faccessat
#  define __NR_faccessat  48
#endif

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    return (int) syscall(__NR_openat, dirfd, path, flags, (long) mode);
}
static int raw_newfstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    return (int) syscall(__NR_newfstatat, dirfd, path, buf, flags);
}
static int raw_faccessat(int dirfd, const char *path, int mode, int flags)
{
    return (int) syscall(__NR_faccessat, dirfd, path, mode, flags);
}

/* Return stable /proc/self/fd/N path if this pathname refers to an
 * encrypted .elf asset, else NULL (caller should pass through).
 *
 * The basename must be listed either in __r_EL (daemon /
 * lazy mode, dlopen_shim-style name list) OR in __r_FM
 * (eager / bundled mode: name=fd pairs baked in by stub).  Mode B /
 * Mode A protect-exe paths never populate __r_EL, so
 * checking only the name list missed them and left openat
 * unredirected. */
static int name_is_known_elf_asset(const char *base)
{
    if (daemon_client_is_encrypted(base)) return 1;
    if (daemon_client_have_fd_map() && daemon_client_eager_lookup_fd(base) >= 0) return 1;
    return 0;
}

static const char *maybe_rewrite_elf_path(const char *pathname)
{
    if (!pathname || !*pathname) return NULL;
    if (!is_owner_process())     return NULL;

    /* Don't recurse on our own rewritten paths. */
    if (strncmp(pathname, "/proc/self/fd/", 14) == 0) return NULL;

    const char *base = strrchr(pathname, '/');
    base = base ? base + 1 : pathname;

    size_t blen = strlen(base);
    if (blen < 5) return NULL;                      /* "x.elf" is 5 */
    if (strcmp(base + blen - 4, ".elf") != 0) return NULL;
    if (!name_is_known_elf_asset(base)) return NULL;

    return resolve_path(base);
}

__attribute__((visibility("default")))
int openat(int dirfd, const char *pathname, int flags, ...)
{
    /* Diagnostic: every openat invocation through this shim gets
     * logged (path only).  If strace shows an openat for a given
     * path but this log does not, the caller is bypassing libc
     * (e.g. syscall(SYS_openat, ...) or inline svc) and LD_PRELOAD
     * cannot interpose it at this layer — a syscall-level hook
     * (seccomp-bpf user-notify / ptrace) would be required. */
    if (g_log && pathname) LOG("openat trace: %s\n", pathname);

    /* O_CREAT / O_TMPFILE pass a mode_t via varargs; the kernel
     * ignores mode otherwise, so forwarding 0 verbatim is safe. */
    mode_t mode = 0;
    if ((flags & (O_CREAT | O_TMPFILE)) != 0) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("openat redirect %s -> %s\n", pathname, redirect);
        return raw_openat(AT_FDCWD, redirect, flags, mode);
    }

    int fd = raw_openat(dirfd, pathname, flags, mode);
    if (fd >= 0) return fd;

    /* ENOENT fallback: ask dlopen_shim if this path is an encrypted
     * lib in the daemon's __r_EL set that pack-time closure missed.
     * The helper self-gates on qemu_mode + owner + path-prefix and
     * returns -1 when it declines (so non-encrypted ENOENTs fall
     * through verbatim).  Declared extern; lives in dlopen_shim.c. */
    int saved_errno = errno;
    if (saved_errno == ENOENT) {
        extern int dlopen_shim_lazy_openat(int dirfd, const char *path,
                                           int flags, int mode);
        int lazy = dlopen_shim_lazy_openat(dirfd, pathname, flags, (int)mode);
        if (lazy >= 0) return lazy;
    }
    errno = saved_errno;
    return fd;
}

/* Some glibc builds call open() -> openat(AT_FDCWD, ...) internally,
 * but hijacking open() as well covers binaries that bind to open
 * directly (older builds, static, or explicitly resolved symbol). */
__attribute__((visibility("default")))
int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    int has_mode = (flags & (O_CREAT | O_TMPFILE)) != 0;
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return has_mode
        ? openat(AT_FDCWD, pathname, flags, mode)
        : openat(AT_FDCWD, pathname, flags);
}

__attribute__((visibility("default")))
int newfstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("newfstatat redirect %s -> %s\n", pathname, redirect);
        return raw_newfstatat(AT_FDCWD, redirect, buf, flags);
    }
    return raw_newfstatat(dirfd, pathname, buf, flags);
}

__attribute__((visibility("default")))
int stat(const char *pathname, struct stat *buf)
{
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("stat redirect %s -> %s\n", pathname, redirect);
        return raw_newfstatat(AT_FDCWD, redirect, buf, 0);
    }
    return raw_newfstatat(AT_FDCWD, pathname, buf, 0);
}

__attribute__((visibility("default")))
int lstat(const char *pathname, struct stat *buf)
{
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        /* For our rewrite the symlink-vs-target distinction is
         * irrelevant — /proc/self/fd/N IS a symlink but we want the
         * target (the memfd), matching plaintext semantics, so follow
         * it (flags = 0, not AT_SYMLINK_NOFOLLOW). */
        LOG("lstat redirect %s -> %s\n", pathname, redirect);
        return raw_newfstatat(AT_FDCWD, redirect, buf, 0);
    }
    return raw_newfstatat(AT_FDCWD, pathname, buf, AT_SYMLINK_NOFOLLOW);
}

__attribute__((visibility("default")))
int access(const char *pathname, int mode)
{
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("access redirect %s -> %s\n", pathname, redirect);
        return raw_faccessat(AT_FDCWD, redirect, mode, 0);
    }
    return raw_faccessat(AT_FDCWD, pathname, mode, 0);
}

/* ------------------------------------------------------------------ */
/*  popen / pclose interception                                         */
/*  (moved verbatim from exe_shim.c — see that commit history for      */
/*  the vfork-corruption rationale)                                    */
/* ------------------------------------------------------------------ */

#define POPEN_TABLE_SIZE 64

static FILE *(*g_real_popen )(const char *, const char *) = NULL;
static int   (*g_real_pclose)(FILE *)                     = NULL;

static struct popen_entry {
    FILE *fp;
    pid_t pid;
} g_popen_table[POPEN_TABLE_SIZE];
static pthread_mutex_t g_popen_lock = PTHREAD_MUTEX_INITIALIZER;

static void resolve_real_popen_funcs(void)
{
    if (g_real_popen && g_real_pclose) return;
    void *libc = dlopen("libc.so.6", RTLD_LAZY | RTLD_NOLOAD);
    if (libc) {
        if (!g_real_popen ) g_real_popen  = dlsym(libc, "popen");
        if (!g_real_pclose) g_real_pclose = dlsym(libc, "pclose");
        dlclose(libc);
    }
    if (!g_real_popen ) g_real_popen  = dlsym(RTLD_NEXT, "popen");
    if (!g_real_pclose) g_real_pclose = dlsym(RTLD_NEXT, "pclose");
}

static int popen_table_insert(FILE *fp, pid_t pid)
{
    pthread_mutex_lock(&g_popen_lock);
    for (int i = 0; i < POPEN_TABLE_SIZE; i++) {
        if (!g_popen_table[i].fp) {
            g_popen_table[i].fp  = fp;
            g_popen_table[i].pid = pid;
            pthread_mutex_unlock(&g_popen_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_popen_lock);
    return -1;
}

static pid_t popen_table_remove(FILE *fp)
{
    pthread_mutex_lock(&g_popen_lock);
    for (int i = 0; i < POPEN_TABLE_SIZE; i++) {
        if (g_popen_table[i].fp == fp) {
            pid_t pid = g_popen_table[i].pid;
            g_popen_table[i].fp  = NULL;
            g_popen_table[i].pid = 0;
            pthread_mutex_unlock(&g_popen_lock);
            return pid;
        }
    }
    pthread_mutex_unlock(&g_popen_lock);
    return (pid_t)-1;
}

__attribute__((visibility("default")))
FILE *popen(const char *command, const char *type)
{
    resolve_real_popen_funcs();

    if (!is_owner_process())
        return g_real_popen ? g_real_popen(command, type) : NULL;

    if (!type || type[0] != 'r')
        return g_real_popen ? g_real_popen(command, type) : NULL;

    int pipefd[2];
    if (pipe(pipefd) < 0)
        return NULL;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        /* Scrub every ANTIREV_* env var so the popen child doesn't
         * disclose internals via /proc/PID/environ and so descendant
         * Python tools (e.g. antirev_client.py) don't pick up stale
         * daemon fds / lib lists.  Iterate environ once and collect
         * names — unsetenv(3) shifts the array in-place so we can't
         * unset while iterating.  Cap is generous vs. today's ~10
         * ANTIREV_* vars; anything beyond the cap stays (best-effort
         * scrub, never a security boundary). */
        extern char **environ;
        char names[32][64];
        int  n_names = 0;
        for (char **e = environ; *e && n_names < 32; e++) {
            if (strncmp(*e, "ANTIREV_", 8) != 0) continue;
            const char *eq = strchr(*e, '=');
            size_t nlen = eq ? (size_t)(eq - *e) : strlen(*e);
            if (nlen >= sizeof(names[0])) continue;
            memcpy(names[n_names], *e, nlen);
            names[n_names][nlen] = '\0';
            n_names++;
        }
        for (int i = 0; i < n_names; i++) unsetenv(names[i]);
        unsetenv("LD_PRELOAD");

        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    FILE *fp = fdopen(pipefd[0], "r");
    if (!fp) {
        int st;
        close(pipefd[0]);
        waitpid(pid, &st, 0);
        return NULL;
    }

    if (popen_table_insert(fp, pid) < 0) {
        int st;
        fclose(fp);
        waitpid(pid, &st, 0);
        errno = ENOMEM;
        return NULL;
    }

    return fp;
}

__attribute__((visibility("default")))
int pclose(FILE *stream)
{
    pid_t pid = popen_table_remove(stream);
    if (pid == (pid_t)-1) {
        resolve_real_popen_funcs();
        if (g_real_pclose) return g_real_pclose(stream);
        errno = EINVAL;
        return -1;
    }

    fclose(stream);
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return status;
}

#endif  /* __aarch64__ */
