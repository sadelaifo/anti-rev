/*
 * antirev dlopen interceptor — loaded via LD_PRELOAD into the target binary.
 *
 * Two modes, selected by the environment the stub hands us:
 *
 *   1. Eager (legacy).  ANTIREV_FD_MAP="libfoo.so=5,libbar.so=6" — every
 *      encrypted lib was fetched by the stub ahead of time; dlopen() just
 *      redirects matching calls to /proc/self/fd/N.
 *
 *   2. Lazy.  ANTIREV_LIBD_SOCK / ANTIREV_ENC_LIBS / ANTIREV_SYMLINK_DIR —
 *      the stub fetched only the exe's DT_NEEDED libs eagerly and left
 *      the daemon socket open for us.  On each dlopen() for an encrypted
 *      basename we send OP_GET_CLOSURE, receive the lib plus its
 *      transitive encrypted DT_NEEDED deps in one batch, materialize
 *      symlinks in ANTIREV_SYMLINK_DIR, then call real_dlopen so glibc's
 *      linker resolves the chain through the already-set LD_LIBRARY_PATH.
 *
 *      Per-lib fds returned by the daemon are cached for the process
 *      lifetime: glibc dedups loaded libraries by the path used to open
 *      them ("/proc/self/fd/N"), so reusing an fd number across libs
 *      would make glibc collapse them into one entry.  Keeping the fds
 *      open pins the paths and avoids that collision.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Must match stub.c */
#define MAX_NAME       255
#define MAX_FILES      1024
#define SCM_BATCH      250
#define MAX_PAYLOAD    (4u + SCM_BATCH * (2u + MAX_NAME))

#define OP_GET_CLOSURE 0x05u
#define OP_BATCH       0x81u
#define OP_END         0x82u

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

static void *(*real_dlopen_fn)(const char *, int) = NULL;

/* Eager-mode ANTIREV_FD_MAP string (legacy path). */
static const char *g_fd_map = NULL;

/* Lazy mode. */
static int  g_sock = -1;
static char g_symlink_dir[256] = {0};

static char g_enc_names[MAX_FILES][MAX_NAME + 1];
static int  g_enc_count = 0;

/* Cache of libs we have already fetched lazily (names + fds held open). */
static char g_cache_names[MAX_FILES][MAX_NAME + 1];
static int  g_cache_fds[MAX_FILES];
static int  g_cache_count = 0;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Diagnostic log file opened at ctor time if ANTIREV_DLOPEN_LOG is set
 * in the environment.  Records every dlopen decision and fetch outcome
 * so we can diagnose "dlopen(enc A) -> DT_NEEDED(enc B)" failures in
 * production binaries without needing stderr. */
static FILE *g_log = NULL;
#define LOG(...) do { if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)

/* ------------------------------------------------------------------ */
/*  Little-endian helpers                                              */
/* ------------------------------------------------------------------ */
static inline void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);      p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
}
static inline uint32_t u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/*  Minimal v2 protocol client                                         */
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
    /* partial */
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
/*  Cache + set lookups                                                */
/* ------------------------------------------------------------------ */

static int is_encrypted(const char *base)
{
    for (int i = 0; i < g_enc_count; i++) {
        if (strcmp(g_enc_names[i], base) == 0) return 1;
    }
    return 0;
}

static int cache_find(const char *base)
{
    for (int i = 0; i < g_cache_count; i++) {
        if (strcmp(g_cache_names[i], base) == 0) return i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Lazy fetch                                                         */
/* ------------------------------------------------------------------ */

/* Request `base` and its transitive encrypted closure from the daemon,
 * materialize symlinks for any names we don't already have cached,
 * keep the fds open for the process lifetime, and then real_dlopen()
 * each fetched lib by its symlink path in the daemon's (topological)
 * return order — so leaves land in glibc's link map before their
 * dependents start loading.  That way a plugin whose DT_RPATH points
 * at the on-disk encrypted directory still satisfies its DT_NEEDED
 * chain via the link map instead of trying to mmap ciphertext.
 *
 * Caller must hold g_lock. */
static void fetch_closure(const char *base)
{
    if (cache_find(base) >= 0) { LOG("  cache-hit %s\n", base); return; }
    if (g_sock < 0 || !g_symlink_dir[0]) {
        LOG("  no-sock (sock=%d dir='%s')\n", g_sock, g_symlink_dir);
        return;
    }

    /* Collect newly-created lib names so we can pre-load them after
     * all symlinks are in place. */
    char new_names[MAX_FILES][MAX_NAME + 1];
    int  new_count = 0;

    uint16_t nlen = (uint16_t)strlen(base);
    if (nlen == 0 || nlen > MAX_NAME) return;

    uint8_t req[2 + MAX_NAME];
    put_u16le(req, nlen);
    memcpy(req + 2, base, nlen);
    if (send_msg(g_sock, OP_GET_CLOSURE, req, (uint32_t)(2 + nlen)) < 0) {
        LOG("  send OP_GET_CLOSURE failed\n");
        return;
    }

    int n_received = 0;

    for (;;) {
        uint32_t op, plen;
        uint8_t  payload[MAX_PAYLOAD];
        int      fds[SCM_BATCH];
        int      nf = 0;
        if (recv_msg(g_sock, &op, payload, &plen, MAX_PAYLOAD,
                     fds, &nf, SCM_BATCH) < 0)
            return;
        if (op == OP_END) break;
        if (op != OP_BATCH || plen < 4) {
            for (int i = 0; i < nf; i++) close(fds[i]);
            return;
        }
        uint32_t nl = u32le(payload);
        if ((int)nl != nf) {
            for (int i = 0; i < nf; i++) close(fds[i]);
            return;
        }
        size_t poff = 4;
        for (uint32_t i = 0; i < nl; i++) {
            if (poff + 2 > plen) {
                for (uint32_t k = i; k < nl; k++) close(fds[k]);
                return;
            }
            uint16_t l = (uint16_t)payload[poff]
                        | ((uint16_t)payload[poff + 1] << 8);
            poff += 2;
            if (l == 0 || l > MAX_NAME || poff + l > plen) {
                for (uint32_t k = i; k < nl; k++) close(fds[k]);
                return;
            }
            char name[MAX_NAME + 1];
            memcpy(name, payload + poff, l);
            name[l] = '\0';
            poff += l;

            n_received++;
            if (cache_find(name) >= 0) {
                /* Already have it — close the fresh duplicate fd.
                 * This does not break path dedup because we keep our
                 * own cached fd (with a different number) pinned. */
                LOG("    dup %s (closed fresh fd)\n", name);
                close(fds[i]);
                continue;
            }
            if (g_cache_count >= MAX_FILES) {
                close(fds[i]);
                continue;
            }

            char lpath[512], target[64];
            snprintf(lpath, sizeof(lpath), "%s/%s", g_symlink_dir, name);
            snprintf(target, sizeof(target), "/proc/self/fd/%d", fds[i]);
            /* Overwrite any stale symlink that points at a closed fd
             * (e.g., a DT_NEEDED lib whose stub-era fd was reaped by
             * exe_shim).  The in-memory mapping stays live regardless. */
            unlink(lpath);
            if (symlink(target, lpath) < 0) {
                LOG("    symlink %s -> %s FAILED errno=%d\n",
                    lpath, target, errno);
                close(fds[i]);
                continue;
            }
            LOG("    new  %s (fd=%d)\n", name, fds[i]);
            memcpy(g_cache_names[g_cache_count], name, (size_t)l + 1);
            g_cache_fds[g_cache_count] = fds[i];
            g_cache_count++;
            if (new_count < MAX_FILES) {
                memcpy(new_names[new_count], name, (size_t)l + 1);
                new_count++;
            }
        }
    }
    LOG("  closure for %s: %d libs total\n", base, n_received);

    /* Pre-load each DEPENDENCY via its symlink path, in the order the
     * daemon returned them (topological: leaves first).  Each load
     * registers the dep's SONAME in glibc's link map so the final
     * real_dlopen() of `base` finds its DT_NEEDED chain in the link
     * map instead of falling back to DT_RPATH / DT_RUNPATH on disk.
     *
     * Explicitly skip `base` itself: pinning the root's refcount here
     * prevents the caller from ever fully dlclose()ing it, which
     * breaks plugin systems that unload one plugin before loading the
     * next — notably the libprotobuf "File already exists in database"
     * conflict seen when two plugins carry overlapping descriptors.
     * The caller's own real_dlopen() in the outer dlopen() handler
     * takes the single reference that the user is entitled to
     * manage. */
    for (int i = 0; i < new_count; i++) {
        if (strcmp(new_names[i], base) == 0) {
            LOG("    skip-root %s\n", new_names[i]);
            continue;
        }
        char spath[512];
        snprintf(spath, sizeof(spath), "%s/%s", g_symlink_dir, new_names[i]);
        void *h = real_dlopen_fn(spath, RTLD_LAZY);
        if (!h) {
            const char *err = dlerror();
            LOG("    preload(%s) FAILED: %s\n", new_names[i],
                err ? err : "(null)");
        } else {
            LOG("    preload(%s) OK handle=%p\n", new_names[i], h);
        }
        /* Deps are pinned intentionally — they're typically shared
         * across plugins (libc++, libprotobuf, libQtCore, etc.) and
         * must stay resident so repeated plugin loads don't drop and
         * re-register them. */
    }
}

/* ------------------------------------------------------------------ */
/*  Constructor: parse env and populate state                          */
/* ------------------------------------------------------------------ */

__attribute__((constructor))
static void init_shim(void)
{
    const char *logpath = getenv("ANTIREV_DLOPEN_LOG");
    if (logpath && *logpath) {
        g_log = fopen(logpath, "w");
        if (g_log) {
            setvbuf(g_log, NULL, _IOLBF, 0);
            LOG("[dlopen_shim] ctor pid=%d\n", getpid());
        }
    }

    g_fd_map = getenv("ANTIREV_FD_MAP");

    const char *sock_str = getenv("ANTIREV_LIBD_SOCK");
    if (sock_str) {
        int fd = atoi(sock_str);
        if (fd > 2) g_sock = fd;
    }

    const char *dir = getenv("ANTIREV_SYMLINK_DIR");
    if (dir && *dir) {
        snprintf(g_symlink_dir, sizeof(g_symlink_dir), "%s", dir);
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

    LOG("[dlopen_shim] sock=%d dir=%s enc_count=%d fd_map=%s\n",
        g_sock, g_symlink_dir, g_enc_count,
        g_fd_map ? "yes" : "no");
}

/* ------------------------------------------------------------------ */
/*  Eager-mode FD_MAP lookup (legacy path)                             */
/* ------------------------------------------------------------------ */

static int eager_lookup(const char *base, char *out_path, size_t out_sz)
{
    if (!g_fd_map) return 0;
    const char *p = g_fd_map;
    while (*p) {
        const char *eq = strchr(p, '=');
        if (!eq) break;
        size_t name_len = (size_t)(eq - p);
        if (name_len == strlen(base) && memcmp(p, base, name_len) == 0) {
            int fd = atoi(eq + 1);
            snprintf(out_path, out_sz, "/proc/self/fd/%d", fd);
            return 1;
        }
        const char *comma = strchr(eq, ',');
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public dlopen interceptor                                           */
/* ------------------------------------------------------------------ */

__attribute__((visibility("default")))
void *dlopen(const char *filename, int flags)
{
    if (!real_dlopen_fn)
        real_dlopen_fn = dlsym(RTLD_NEXT, "dlopen");

    if (!filename)
        return real_dlopen_fn(filename, flags);

    const char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;

    /* Legacy eager path: everything pre-fetched, just redirect. */
    if (g_fd_map) {
        char redir[64];
        if (eager_lookup(base, redir, sizeof(redir)))
            return real_dlopen_fn(redir, flags);
        return real_dlopen_fn(filename, flags);
    }

    /* Lazy path. */
    if (g_sock < 0 || g_enc_count == 0 || !is_encrypted(base)) {
        LOG("dlopen(%s) flags=0x%x -> passthrough (enc=%d)\n",
            filename, flags, is_encrypted(base));
        return real_dlopen_fn(filename, flags);
    }

    LOG("dlopen(%s) flags=0x%x -> fetch_closure(%s)\n",
        filename, flags, base);

    pthread_mutex_lock(&g_lock);
    fetch_closure(base);
    pthread_mutex_unlock(&g_lock);

    /* Resolve via the symlink dir so glibc sees a stable on-disk path
     * and its DT_NEEDED search finds sibling encrypted deps too. */
    char spath[512];
    snprintf(spath, sizeof(spath), "%s/%s", g_symlink_dir, base);
    void *h = real_dlopen_fn(spath, flags);
    if (!h) {
        const char *err = dlerror();
        LOG("  real_dlopen(%s) FAILED: %s\n", spath, err ? err : "(null)");
        /* If the symlink path didn't work (e.g., lib wasn't in our set),
         * fall through to the original request. */
        h = real_dlopen_fn(filename, flags);
        if (!h) {
            const char *e2 = dlerror();
            LOG("  real_dlopen(%s) also failed: %s\n", filename, e2 ? e2 : "(null)");
        }
    } else {
        LOG("  real_dlopen(%s) OK\n", spath);
    }
    return h;
}
