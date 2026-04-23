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
 * The shim resolves encrypted .elf names against the same
 * ANTIREV_ENC_LIBS environment variable dlopen_shim uses (.elf and .so
 * basenames coexist without collision).  It talks to the same daemon
 * over ANTIREV_LIBD_SOCK using OP_GET_LIB (single name → single fd).
 *
 * Eager mode (no daemon) is also supported via ANTIREV_FD_MAP, so
 * legacy bundled stubs work without a daemon.
 */

#if !defined(__aarch64__)
/* Non-aarch64 builds: empty translation unit.  CMake only compiles this
 * file on aarch64, but guard defensively in case someone invokes gcc
 * directly. */
typedef int _aarch64_extend_shim_empty;
#else

#define _GNU_SOURCE
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
#include <sys/uio.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------ */
/*  Protocol constants (must match stub.c)                              */
/* ------------------------------------------------------------------ */

#define MAX_NAME       255
#define MAX_FILES      1024
#define SCM_BATCH      250

#define OP_GET_LIB     0x02u
#define OP_LIB         0x83u

#define ST_OK          0u

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

/* Daemon (lazy) mode */
static int g_sock = -1;

/* Eager mode */
static const char *g_fd_map = NULL;

/* Encrypted-name set (shared with dlopen_shim via ANTIREV_ENC_LIBS).
 * Used to decide whether an ANTI_LoadProcess basename needs daemon lookup. */
static char g_enc_names[MAX_FILES][MAX_NAME + 1];
static int  g_enc_count = 0;

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
static char g_cache_names[MAX_FILES][MAX_NAME + 1];
static int  g_cache_fds[MAX_FILES];
static char g_cache_paths[MAX_FILES][FD_PATH_MAX];
static int  g_cache_count = 0;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Optional log sink (ANTIREV_AARCH64_EXTEND_LOG=<path>). */
static FILE *g_log = NULL;
#define LOG(...) do { if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)

/* ------------------------------------------------------------------ */
/*  Little-endian helpers                                              */
/* ------------------------------------------------------------------ */

static inline void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
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
/*  Minimal v2 protocol client                                          */
/* ------------------------------------------------------------------ */

static int recv_full(int sock, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(sock, (uint8_t *)buf + got, len - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int send_msg(int sock, uint32_t op, const void *payload, uint32_t plen)
{
    uint8_t hdr[8];
    put_u32le(hdr, op);
    put_u32le(hdr + 4, plen);
    struct iovec iov[2] = {
        { hdr, sizeof(hdr) },
        { (void *)payload, plen },
    };
    struct msghdr msg = {0};
    msg.msg_iov    = iov;
    msg.msg_iovlen = (plen > 0) ? 2 : 1;
    size_t total = 8 + (size_t)plen;
    ssize_t n = sendmsg(sock, &msg, 0);
    if (n < 0) return -1;
    if ((size_t)n == total) return 0;
    size_t sent = (size_t)n;
    if (sent < 8) {
        if (send(sock, hdr + sent, 8 - sent, 0) != (ssize_t)(8 - sent)) return -1;
        sent = 8;
    }
    size_t prem = total - sent;
    if (prem > 0) {
        if (send(sock, (const uint8_t *)payload + (sent - 8), prem, 0)
            != (ssize_t)prem) return -1;
    }
    return 0;
}

static int recv_msg(int sock, uint32_t *op,
                    uint8_t *payload, uint32_t *plen, uint32_t max_payload,
                    int *fds, int *nfds, int max_fds)
{
    *nfds = 0;
    uint8_t hdr[8];
    struct iovec iov = { hdr, sizeof(hdr) };
    char cmsg_buf[CMSG_SPACE(SCM_BATCH * sizeof(int))];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    struct msghdr msg = {0};
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    ssize_t got = recvmsg(sock, &msg, 0);
    if (got <= 0) return -1;

    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            int n = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            if (n > max_fds) {
                int *src = (int *)CMSG_DATA(cm);
                for (int k = 0; k < n; k++) close(src[k]);
                return -1;
            }
            memcpy(fds, CMSG_DATA(cm), (size_t)n * sizeof(int));
            *nfds = n;
        }
    }
    if (got < (ssize_t)sizeof(hdr)) {
        if (recv_full(sock, hdr + got, sizeof(hdr) - (size_t)got) < 0)
            return -1;
    }
    *op = u32le(hdr);
    uint32_t p = u32le(hdr + 4);
    if (p > max_payload) return -1;
    *plen = p;
    if (p > 0) {
        if (recv_full(sock, payload, p) < 0) return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Lookups                                                             */
/* ------------------------------------------------------------------ */

static int is_encrypted(const char *base)
{
    for (int i = 0; i < g_enc_count; i++)
        if (strcmp(g_enc_names[i], base) == 0) return 1;
    return 0;
}

static int cache_find(const char *base)
{
    for (int i = 0; i < g_cache_count; i++)
        if (strcmp(g_cache_names[i], base) == 0) return i;
    return -1;
}

/* Eager-mode FD_MAP lookup: parse "name=fd,name=fd,..." for `base`. */
static int eager_lookup_fd(const char *base)
{
    if (!g_fd_map) return -1;
    const char *p = g_fd_map;
    size_t blen = strlen(base);
    while (*p) {
        const char *eq = strchr(p, '=');
        if (!eq) break;
        size_t name_len = (size_t)(eq - p);
        if (name_len == blen && memcmp(p, base, blen) == 0)
            return atoi(eq + 1);
        const char *comma = strchr(eq, ',');
        if (!comma) break;
        p = comma + 1;
    }
    return -1;
}

/* Ask the daemon for `base` and return the received fd, or -1 on failure.
 * Caller must hold g_lock. */
static int fetch_one(const char *base)
{
    if (g_sock < 0) return -1;
    uint16_t nlen = (uint16_t)strlen(base);
    if (nlen == 0 || nlen > MAX_NAME) return -1;

    uint8_t req[2 + MAX_NAME];
    put_u16le(req, nlen);
    memcpy(req + 2, base, nlen);
    if (send_msg(g_sock, OP_GET_LIB, req, (uint32_t)(2 + nlen)) < 0) {
        LOG("  send OP_GET_LIB(%s) failed\n", base);
        return -1;
    }

    uint32_t op, plen;
    uint8_t  payload[16];
    int      fds[1];
    int      nfds = 0;
    if (recv_msg(g_sock, &op, payload, &plen, sizeof(payload),
                 fds, &nfds, 1) < 0) {
        LOG("  recv OP_LIB(%s) failed\n", base);
        return -1;
    }
    if (op != OP_LIB || plen < 4) {
        LOG("  bad reply for %s: op=0x%x plen=%u\n", base, op, plen);
        for (int i = 0; i < nfds; i++) close(fds[i]);
        return -1;
    }
    uint32_t status = u32le(payload);
    if (status != ST_OK || nfds != 1) {
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

    /* Eager path first (stub pre-populated fd map). */
    if (g_fd_map) {
        fd = eager_lookup_fd(base);
        if (fd >= 0) LOG("  eager-hit %s -> fd=%d\n", base, fd);
    }

    /* Daemon path. */
    if (fd < 0 && g_sock >= 0 && is_encrypted(base)) {
        fd = fetch_one(base);
        if (fd >= 0) LOG("  daemon-hit %s -> fd=%d\n", base, fd);
    }

    if (fd < 0) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    const char *out = NULL;
    if (g_cache_count < MAX_FILES) {
        size_t bl = strlen(base);
        if (bl <= MAX_NAME) {
            memcpy(g_cache_names[g_cache_count], base, bl + 1);
            g_cache_fds[g_cache_count] = fd;
            snprintf(g_cache_paths[g_cache_count], FD_PATH_MAX,
                     "/proc/self/fd/%d", fd);
            out = g_cache_paths[g_cache_count];
            g_cache_count++;
        }
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
        /* QEMU fallback: trust ANTIREV_MAIN_FD's presence. */
        if (getenv("ANTIREV_MAIN_FD")) is_owner = 1;
    }
    if (is_owner) g_owner_pid = getpid();

    LOG("[aarch64_extend_shim] ctor pid=%d owner=%d\n", getpid(), is_owner);

    g_fd_map = getenv("ANTIREV_FD_MAP");

    const char *sock_str = getenv("ANTIREV_LIBD_SOCK");
    if (sock_str) {
        int fd = atoi(sock_str);
        if (fd > 2) g_sock = fd;
    }

    const char *enc = getenv("ANTIREV_ENC_LIBS");
    if (enc && *enc) {
        char *buf = strdup(enc);
        if (buf) {
            char *save = NULL;
            for (char *tok = strtok_r(buf, ",", &save);
                 tok && g_enc_count < MAX_FILES;
                 tok = strtok_r(NULL, ",", &save)) {
                size_t len = strlen(tok);
                if (len == 0 || len > MAX_NAME) continue;
                memcpy(g_enc_names[g_enc_count], tok, len + 1);
                g_enc_count++;
            }
            free(buf);
        }
    }

    LOG("[aarch64_extend_shim] sock=%d fd_map=%s enc_count=%d\n",
        g_sock, g_fd_map ? "yes" : "no", g_enc_count);
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
/*   - basename must end in ".elf" AND be listed in ANTIREV_ENC_LIBS —  */
/*     scoping to .elf keeps us out of dlopen's and glibc's internal    */
/*     openat traffic on .so paths (handled by dlopen_shim).            */
/*   - paths already under /proc/self/fd/ pass through untouched to    */
/*     avoid any chance of recursion via real_openat.                   */
/* ------------------------------------------------------------------ */

static int     (*g_real_openat)(int, const char *, int, ...) = NULL;
static int     (*g_real_newfstatat)(int, const char *, struct stat *, int) = NULL;
static int     (*g_real_stat)(const char *, struct stat *) = NULL;
static int     (*g_real_lstat)(const char *, struct stat *) = NULL;
static int     (*g_real_access)(const char *, int) = NULL;

static void resolve_real_io_funcs(void)
{
    if (g_real_openat && g_real_newfstatat) return;
    if (!g_real_openat)     g_real_openat     = dlsym(RTLD_NEXT, "openat");
    if (!g_real_newfstatat) g_real_newfstatat = dlsym(RTLD_NEXT, "newfstatat");
    if (!g_real_stat)       g_real_stat       = dlsym(RTLD_NEXT, "stat");
    if (!g_real_lstat)      g_real_lstat      = dlsym(RTLD_NEXT, "lstat");
    if (!g_real_access)     g_real_access     = dlsym(RTLD_NEXT, "access");
}

/* Return stable /proc/self/fd/N path if this pathname refers to an
 * encrypted .elf asset, else NULL (caller should pass through).
 *
 * The basename must be listed either in ANTIREV_ENC_LIBS (daemon /
 * lazy mode, dlopen_shim-style name list) OR in ANTIREV_FD_MAP
 * (eager / bundled mode: name=fd pairs baked in by stub).  Mode B /
 * Mode A protect-exe paths never populate ANTIREV_ENC_LIBS, so
 * checking only the name list missed them and left openat
 * unredirected. */
static int name_is_known_elf_asset(const char *base)
{
    if (is_encrypted(base)) return 1;
    if (g_fd_map && eager_lookup_fd(base) >= 0) return 1;
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
    resolve_real_io_funcs();

    /* Diagnostic: every openat invocation through this shim gets
     * logged (path only).  If strace shows an openat for a given
     * path but this log does not, the caller is bypassing libc
     * (e.g. syscall(SYS_openat, ...) or inline svc) and LD_PRELOAD
     * cannot interpose it at this layer — a syscall-level hook
     * (seccomp-bpf user-notify / ptrace) would be required. */
    if (g_log && pathname) LOG("openat trace: %s\n", pathname);

    /* O_CREAT / O_TMPFILE pass a mode_t via varargs; forward verbatim. */
    mode_t mode = 0;
    int has_mode = (flags & (O_CREAT | O_TMPFILE)) != 0;
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("openat redirect %s -> %s\n", pathname, redirect);
        if (!g_real_openat) { errno = ENOSYS; return -1; }
        return g_real_openat(AT_FDCWD, redirect, flags, mode);
    }

    if (!g_real_openat) { errno = ENOSYS; return -1; }
    return has_mode
        ? g_real_openat(dirfd, pathname, flags, mode)
        : g_real_openat(dirfd, pathname, flags);
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
    resolve_real_io_funcs();
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("newfstatat redirect %s -> %s\n", pathname, redirect);
        if (!g_real_newfstatat) { errno = ENOSYS; return -1; }
        return g_real_newfstatat(AT_FDCWD, redirect, buf, flags);
    }
    if (!g_real_newfstatat) { errno = ENOSYS; return -1; }
    return g_real_newfstatat(dirfd, pathname, buf, flags);
}

__attribute__((visibility("default")))
int stat(const char *pathname, struct stat *buf)
{
    resolve_real_io_funcs();
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("stat redirect %s -> %s\n", pathname, redirect);
        if (g_real_stat) return g_real_stat(redirect, buf);
        /* Fall back to newfstatat if libc's stat isn't exported (glibc
         * >= 2.33 provides stat as an inline wrapper in headers). */
        if (g_real_newfstatat) return g_real_newfstatat(AT_FDCWD, redirect, buf, 0);
        errno = ENOSYS; return -1;
    }
    if (g_real_stat) return g_real_stat(pathname, buf);
    if (g_real_newfstatat) return g_real_newfstatat(AT_FDCWD, pathname, buf, 0);
    errno = ENOSYS; return -1;
}

__attribute__((visibility("default")))
int lstat(const char *pathname, struct stat *buf)
{
    resolve_real_io_funcs();
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        /* For our rewrite the symlink-vs-target distinction is
         * irrelevant — /proc/self/fd/N IS a symlink but we want the
         * target (the memfd), matching plaintext semantics. */
        LOG("lstat redirect %s -> %s\n", pathname, redirect);
        if (g_real_newfstatat) return g_real_newfstatat(AT_FDCWD, redirect, buf, 0);
        errno = ENOSYS; return -1;
    }
    if (g_real_lstat) return g_real_lstat(pathname, buf);
    if (g_real_newfstatat)
        return g_real_newfstatat(AT_FDCWD, pathname, buf, AT_SYMLINK_NOFOLLOW);
    errno = ENOSYS; return -1;
}

__attribute__((visibility("default")))
int access(const char *pathname, int mode)
{
    resolve_real_io_funcs();
    const char *redirect = maybe_rewrite_elf_path(pathname);
    if (redirect) {
        LOG("access redirect %s -> %s\n", pathname, redirect);
        if (g_real_access) return g_real_access(redirect, mode);
        errno = ENOSYS; return -1;
    }
    if (g_real_access) return g_real_access(pathname, mode);
    errno = ENOSYS; return -1;
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

        unsetenv("ANTIREV_FD_MAP");
        unsetenv("ANTIREV_REAL_EXE");
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
