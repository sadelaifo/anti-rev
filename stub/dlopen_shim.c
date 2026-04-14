/*
 * antirev dlopen interceptor — loaded via LD_PRELOAD into the target binary.
 *
 * Two operational modes, detected at first dlopen call:
 *
 *   1. Lazy fetch (Mode C with needed section, Mode D wrapper):
 *      ANTIREV_FD_MAP_LIBS=libfoo.so,libbar.so,...
 *      ANTIREV_LIBD_SOCK=<fd>
 *      On matching dlopen: send OP_GET_LIB to the daemon socket, receive
 *      one memfd via SCM_RIGHTS, real_dlopen("/proc/self/fd/N"), then
 *      close(N) immediately — the mapping keeps the lib alive, and the
 *      fd slot is freed so the process never holds 500+ idle memfds.
 *
 *   2. Eager map (Mode A, libs bundled in exe):
 *      ANTIREV_FD_MAP=libfoo.so=5,libbar.so=6,...
 *      On matching dlopen: real_dlopen("/proc/self/fd/N") directly; fds
 *      are preallocated by the stub and held open for the whole process.
 *
 * Non-matching dlopen calls pass through to the real libc dlopen.
 *
 * Protocol opcodes and wire format mirror stub.c's daemon v2 protocol.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* Protocol opcodes (must match stub/stub.c daemon v2). */
#define OP_GET_LIB 0x02u
#define OP_BYE     0x03u
#define OP_LIB     0x83u
#define ST_OK      0u

#define MAX_NAME 255

static void *(*real_dlopen_fn)(const char *, int) = NULL;

/* Lazy-fetch state, initialized once on first dlopen. */
static char           *g_lazy_names = NULL;   /* strdup'd comma list */
static int             g_lazy_sock  = -1;
static pthread_mutex_t g_sock_mu    = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t  g_init_once  = PTHREAD_ONCE_INIT;

/* Per-lib fd cache.  Once a lazy-fetched lib is open, its fd is held for
 * the life of the process so the path /proc/self/fd/N stays stable —
 * glibc's path-based link-map dedup then correctly reuses the existing
 * handle on subsequent dlopen() calls.  Closing the fd and letting the
 * kernel reuse the number causes glibc to mis-identify different libs
 * as the same load. */
#define MAX_CACHE 1024
static struct {
    char name[MAX_NAME + 1];
    int  fd;
} g_cache[MAX_CACHE];
static int g_cache_n = 0;

/* Caller must hold g_sock_mu. */
static int cache_lookup_locked(const char *name)
{
    for (int i = 0; i < g_cache_n; i++)
        if (strcmp(g_cache[i].name, name) == 0)
            return g_cache[i].fd;
    return -1;
}

static void cache_insert_locked(const char *name, int fd)
{
    if (g_cache_n >= MAX_CACHE) return;
    size_t n = strlen(name);
    if (n > MAX_NAME) n = MAX_NAME;
    memcpy(g_cache[g_cache_n].name, name, n);
    g_cache[g_cache_n].name[n] = '\0';
    g_cache[g_cache_n].fd = fd;
    g_cache_n++;
}

static void init_state(void)
{
    const char *sock = getenv("ANTIREV_LIBD_SOCK");
    if (sock && *sock) {
        char *end = NULL;
        long v = strtol(sock, &end, 10);
        if (end != sock && v >= 0) g_lazy_sock = (int)v;
    }
    const char *libs = getenv("ANTIREV_FD_MAP_LIBS");
    if (libs && *libs) {
        g_lazy_names = strdup(libs);
    }
}

static void *get_real_dlopen(void)
{
    if (!real_dlopen_fn)
        real_dlopen_fn = dlsym(RTLD_NEXT, "dlopen");
    return real_dlopen_fn;
}

/* Exact-token match against the comma-separated lazy name list. */
static int name_in_lazy_list(const char *base)
{
    if (!g_lazy_names || !*g_lazy_names) return 0;
    size_t bl = strlen(base);
    const char *p = g_lazy_names;
    while (*p) {
        const char *c = strchr(p, ',');
        size_t tl = c ? (size_t)(c - p) : strlen(p);
        if (tl == bl && memcmp(p, base, bl) == 0) return 1;
        if (!c) break;
        p = c + 1;
    }
    return 0;
}

/* ---- Minimal blocking I/O helpers ---- */
static int send_all(int fd, const void *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)buf + sent, len - sent, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (char *)buf + got, len - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

/* Send OP_GET_LIB for `name`, receive OP_LIB response with SCM_RIGHTS fd.
 * Returns the fd on success, -1 on failure.
 * Caller must hold g_sock_mu. */
static int fetch_lib_locked(const char *name)
{
    size_t nlen = strlen(name);
    if (nlen == 0 || nlen > MAX_NAME) return -1;

    /* Build OP_GET_LIB message: [u32 op][u32 plen][u16 nlen][name] */
    uint8_t msg[8 + 2 + MAX_NAME];
    msg[0] = (uint8_t)(OP_GET_LIB & 0xff);
    msg[1] = (uint8_t)((OP_GET_LIB >> 8) & 0xff);
    msg[2] = 0;
    msg[3] = 0;
    uint32_t plen = (uint32_t)(2 + nlen);
    msg[4] = (uint8_t)(plen & 0xff);
    msg[5] = (uint8_t)((plen >> 8) & 0xff);
    msg[6] = (uint8_t)((plen >> 16) & 0xff);
    msg[7] = (uint8_t)((plen >> 24) & 0xff);
    msg[8] = (uint8_t)(nlen & 0xff);
    msg[9] = (uint8_t)((nlen >> 8) & 0xff);
    memcpy(msg + 10, name, nlen);

    if (send_all(g_lazy_sock, msg, 10 + nlen) < 0) return -1;

    /* Receive OP_LIB response: header (8) + ancillary SCM_RIGHTS on first byte. */
    uint8_t hdr[8];
    struct iovec iov = { .iov_base = hdr, .iov_len = sizeof(hdr) };

    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));

    struct msghdr rmsg = {0};
    rmsg.msg_iov        = &iov;
    rmsg.msg_iovlen     = 1;
    rmsg.msg_control    = cmsg_buf;
    rmsg.msg_controllen = sizeof(cmsg_buf);

    ssize_t got = recvmsg(g_lazy_sock, &rmsg, 0);
    if (got <= 0) return -1;

    int fd = -1;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&rmsg); cm; cm = CMSG_NXTHDR(&rmsg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            int n = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            if (n >= 1) memcpy(&fd, CMSG_DATA(cm), sizeof(int));
        }
    }

    /* Complete partial header read. */
    size_t hgot = (size_t)got;
    while (hgot < sizeof(hdr)) {
        ssize_t m = recv(g_lazy_sock, hdr + hgot, sizeof(hdr) - hgot, 0);
        if (m <= 0) { if (fd >= 0) close(fd); return -1; }
        hgot += (size_t)m;
    }

    uint32_t op =  (uint32_t)hdr[0]
                | ((uint32_t)hdr[1] << 8)
                | ((uint32_t)hdr[2] << 16)
                | ((uint32_t)hdr[3] << 24);
    uint32_t rp =  (uint32_t)hdr[4]
                | ((uint32_t)hdr[5] << 8)
                | ((uint32_t)hdr[6] << 16)
                | ((uint32_t)hdr[7] << 24);
    if (op != OP_LIB || rp < 4 || rp > 64) {
        if (fd >= 0) close(fd);
        return -1;
    }

    uint8_t payload[64];
    if (recv_all(g_lazy_sock, payload, rp) < 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    uint32_t status =  (uint32_t)payload[0]
                    | ((uint32_t)payload[1] << 8)
                    | ((uint32_t)payload[2] << 16)
                    | ((uint32_t)payload[3] << 24);
    if (status != ST_OK || fd < 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

__attribute__((visibility("default")))
void *dlopen(const char *filename, int flags)
{
    get_real_dlopen();
    pthread_once(&g_init_once, init_state);

    if (!filename)
        return real_dlopen_fn(filename, flags);

    /* Match on basename so "libfoo.so" and "/path/to/libfoo.so" both work. */
    const char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;

    /* --- Lazy fetch path: ANTIREV_FD_MAP_LIBS + ANTIREV_LIBD_SOCK --- */
    if (g_lazy_sock >= 0 && name_in_lazy_list(base)) {
        pthread_mutex_lock(&g_sock_mu);
        int fd = cache_lookup_locked(base);
        if (fd < 0) {
            fd = fetch_lib_locked(base);
            if (fd >= 0) cache_insert_locked(base, fd);
        }
        pthread_mutex_unlock(&g_sock_mu);
        if (fd >= 0) {
            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
            /* Leave fd open: the stable /proc/self/fd/N path is what
             * lets glibc's link-map dedup reuse the existing mapping
             * on subsequent dlopen() calls for the same lib. */
            return real_dlopen_fn(path, flags);
        }
        /* Daemon fetch failed — fall through to the eager path or real dlopen. */
    }

    /* --- Eager ANTIREV_FD_MAP path (Mode A) --- */
    const char *map = getenv("ANTIREV_FD_MAP");
    if (!map)
        return real_dlopen_fn(filename, flags);

    char *buf = strdup(map);
    if (!buf)
        return real_dlopen_fn(filename, flags);

    void *handle = NULL;
    char *save = NULL;
    char *tok  = strtok_r(buf, ",", &save);
    while (tok) {
        char *eq = strchr(tok, '=');
        if (eq) {
            *eq = '\0';
            if (strcmp(tok, base) == 0) {
                int fd = atoi(eq + 1);
                char path[64];
                snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
                handle = real_dlopen_fn(path, flags);
                goto done;
            }
        }
        tok = strtok_r(NULL, ",", &save);
    }
    /* No match — fall through to real dlopen */
    handle = real_dlopen_fn(filename, flags);

done:
    free(buf);
    return handle;
}
