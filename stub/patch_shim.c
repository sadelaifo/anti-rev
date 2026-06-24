/*
 * lrxd_<arch>.so — keyless open()/openat() redirect for hot-patch tools.
 * (Deployed artifact name; the CMake target is `antirev_patch`. Named to
 *  blend in next to the lrxd daemon binary.)
 *
 * Loaded via LD_PRELOAD into an *unprotected* host tool (a live-patch
 * injector).  When that tool open()s an encrypted ".pat" file from
 * disk, this shim transparently hands it the *decrypted* bytes instead,
 * fetched as a memfd from the antirev lib daemon.  The injector calls
 * plain open() and stays completely antirev-blind; all antirev knowledge
 * lives here, in an antirev-owned component (the anti-corruption layer).
 *
 * Deliberately standalone:
 *   - separate DSO from antirev_shim — these open/openat interceptors are
 *     NOT shared with exe_shim / dlopen_shim / aarch64_extend_shim, and
 *     are only ever loaded into the injector, never a protected process;
 *   - no AES key and no crypto — decryption happens in the daemon, which
 *     re-reads the key from its own trailer per request.  This shim is a
 *     pure socket client, so it is not a decryption oracle;
 *   - no daemon_client.c — that client connects via an inherited socket
 *     fd (ANTIREV_LIBD_SOCK).  A fresh injector process inherits nothing,
 *     so we connect from scratch: the daemon publishes its (non-secret)
 *     abstract socket name to a discovery file in its scan dir, and we
 *     find it by walking up from the .pat path's directory.
 *
 * Env:
 *   ANTIREV_PATCH_LOG=<path>  line-buffered log of every decision.
 *
 * Limitations (v1): stat()-by-path on a .pat path still returns the
 * on-disk ciphertext size; loaders that fstat() the opened fd see the
 * correct plaintext size (memfd) and work.  Relative openat() paths
 * without a directory component are not redirected.
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

/* Protocol constants — must match stub.c / the daemon. */
#define OP_GET_PATCH 0x06u
#define OP_LIB       0x83u
#define ST_OK        0u

/* Key-free discovery file the daemon drops in its scan dir. */
#define DISCOVERY_FILE ".antirev-libd.sock"

static FILE *g_log = NULL;
#define LOG(...) do { if (g_log) fprintf(g_log, __VA_ARGS__); } while (0)

static int (*g_real_open)(const char *, int, ...)      = NULL;
static int (*g_real_open64)(const char *, int, ...)    = NULL;
static int (*g_real_openat)(int, const char *, int, ...)   = NULL;
static int (*g_real_openat64)(int, const char *, int, ...) = NULL;
static FILE *(*g_real_fopen)(const char *, const char *)   = NULL;
static FILE *(*g_real_fopen64)(const char *, const char *) = NULL;
static FILE *(*g_real_fdopen)(int, const char *)           = NULL;
static int g_inited = 0;

static void init_reals(void) {
    if (g_inited) return;
    g_inited = 1;
    g_real_open     = dlsym(RTLD_NEXT, "open");
    g_real_open64   = dlsym(RTLD_NEXT, "open64");
    g_real_openat   = dlsym(RTLD_NEXT, "openat");
    g_real_openat64 = dlsym(RTLD_NEXT, "openat64");
    g_real_fopen    = dlsym(RTLD_NEXT, "fopen");
    g_real_fopen64  = dlsym(RTLD_NEXT, "fopen64");
    g_real_fdopen   = dlsym(RTLD_NEXT, "fdopen");
    const char *lp = getenv("ANTIREV_PATCH_LOG");
    if (lp && g_real_fopen) {
        /* Use the REAL fopen, not our interposer, to avoid re-entering
         * this DSO's own fopen() while init is still running. */
        g_log = g_real_fopen(lp, "w");
        if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);
    }
}

/* ---- little-endian wire helpers ---- */
static void put_u32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int write_all(int fd, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, (const char *)buf + off, len - off);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        off += (size_t)n;
    }
    return 0;
}
static int read_all(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, (char *)buf + off, len - off);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        off += (size_t)n;
    }
    return 0;
}

/* True iff `path`'s basename ends in ".pat" — the business patch
 * artifact (an .o-style file). */
static int has_suffix(const char *base, const char *suf) {
    size_t bl = strlen(base), sl = strlen(suf);
    return bl > sl && strcmp(base + bl - sl, suf) == 0;
}
static int is_patch_path(const char *path) {
    if (!path) return 0;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return has_suffix(base, ".pat");
}

/* Read-only open via the real libc open (never re-enters our interposer). */
static int real_open_ro(const char *path) {
    if (!g_real_open) return -1;
    return g_real_open(path, O_RDONLY);
}

/* Walk up from the .pat path's directory looking for the discovery
 * file; on success copy the abstract socket name into `out`. */
static int find_discovery(const char *patch_path, char *out, size_t out_sz) {
    char d[4096];
    snprintf(d, sizeof(d), "%s", patch_path);
    char *slash = strrchr(d, '/');
    if (!slash) return 0;            /* no directory component → give up */
    *slash = '\0';
    if (d[0] == '\0') { d[0] = '/'; d[1] = '\0'; }  /* file in root dir */

    for (int i = 0; i < 16; i++) {
        char p[4096];
        snprintf(p, sizeof(p), "%s/%s", d, DISCOVERY_FILE);
        int fd = real_open_ro(p);
        if (fd >= 0) {
            char buf[200];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
                buf[n] = '\0';
                char *nl = strchr(buf, '\n');
                if (nl) *nl = '\0';
                if (buf[0]) {
                    snprintf(out, out_sz, "%s", buf);
                    return 1;
                }
            }
        }
        if (d[0] == '/' && d[1] == '\0') break;   /* reached root */
        char *s = strrchr(d, '/');
        if (!s) break;
        if (s == d) d[1] = '\0';                  /* parent is "/" */
        else *s = '\0';
    }
    return 0;
}

/* Connect to the daemon's abstract socket by name. */
static int connect_daemon(const char *sock_name) {
    int sd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t nlen = strlen(sock_name);
    if (nlen + 1 > sizeof(addr.sun_path)) { close(sd); return -1; }
    memcpy(addr.sun_path + 1, sock_name, nlen);   /* abstract: leading NUL */
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + nlen);
    if (connect(sd, (struct sockaddr *)&addr, alen) < 0) { close(sd); return -1; }
    return sd;
}

/* Send OP_GET_PATCH(basename). */
static int send_get_patch(int sd, const char *base) {
    size_t blen = strlen(base);
    if (blen == 0 || blen > 0xffff) return -1;
    uint8_t hdr[8];
    put_u32le(hdr, OP_GET_PATCH);
    put_u32le(hdr + 4, (uint32_t)(2 + blen));
    uint8_t nlen[2] = { (uint8_t)(blen & 0xff), (uint8_t)((blen >> 8) & 0xff) };
    if (write_all(sd, hdr, sizeof(hdr)) < 0) return -1;
    if (write_all(sd, nlen, 2) < 0) return -1;
    if (write_all(sd, base, blen) < 0) return -1;
    return 0;
}

/* Receive one OP_LIB reply: [u32 status] + (status==OK ? one fd). Returns
 * the received fd, or -1 on any error / not-OK / no fd. */
static int recv_lib_fd(int sd) {
    uint8_t hdr[8];
    struct iovec iov = { .iov_base = hdr, .iov_len = sizeof(hdr) };
    char cbuf[CMSG_SPACE(sizeof(int) * 4)];
    memset(cbuf, 0, sizeof(cbuf));
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    ssize_t got = recvmsg(sd, &msg, 0);
    if (got <= 0) return -1;

    int recvfd = -1;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            int n = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            for (int k = 0; k < n; k++) {
                int x;
                memcpy(&x, CMSG_DATA(cm) + (size_t)k * sizeof(int), sizeof(int));
                if (k == 0) recvfd = x; else close(x);  /* keep only the first */
            }
        }
    }

    if (got < (ssize_t)sizeof(hdr)) {
        if (read_all(sd, hdr + got, sizeof(hdr) - (size_t)got) < 0) {
            if (recvfd >= 0) close(recvfd);
            return -1;
        }
    }
    uint32_t op   = u32le(hdr);
    uint32_t plen = u32le(hdr + 4);

    uint8_t pbuf[64];
    uint32_t status = (uint32_t)-1;
    uint32_t rem = plen;
    if (plen >= 4) {
        if (read_all(sd, pbuf, 4) < 0) { if (recvfd >= 0) close(recvfd); return -1; }
        status = u32le(pbuf);
        rem -= 4;
    }
    while (rem > 0) {  /* drain any unexpected extra payload */
        uint32_t step = rem > sizeof(pbuf) ? (uint32_t)sizeof(pbuf) : rem;
        if (read_all(sd, pbuf, step) < 0) break;
        rem -= step;
    }

    if (op != OP_LIB || status != ST_OK) {
        if (recvfd >= 0) close(recvfd);
        return -1;
    }
    return recvfd;
}

/* Full fetch: discover daemon → connect → request → receive memfd. */
static int fetch_patch(const char *path, int flags) {
    char sock_name[200];
    if (!find_discovery(path, sock_name, sizeof(sock_name))) {
        LOG("fetch %s: no discovery file\n", path);
        return -1;
    }
    int sd = connect_daemon(sock_name);
    if (sd < 0) {
        LOG("fetch %s: connect(%s) failed: %s\n", path, sock_name, strerror(errno));
        return -1;
    }
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    int fd = -1;
    if (send_get_patch(sd, base) == 0)
        fd = recv_lib_fd(sd);
    close(sd);
    if (fd >= 0 && (flags & O_CLOEXEC))
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    LOG("fetch %s (base=%s): %s\n", path, base, fd >= 0 ? "OK (memfd)" : "miss");
    return fd;
}

/* Only redirect read-only opens of a .pat path; everything else, and
 * any fetch miss, falls through to the real call. */
static int should_redirect(const char *path, int flags) {
    return is_patch_path(path) && !(flags & (O_WRONLY | O_RDWR | O_CREAT));
}

__attribute__((visibility("default")))
int open(const char *path, int flags, ...) {
    init_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (g_real_open && should_redirect(path, flags)) {
        int fd = fetch_patch(path, flags);
        if (fd >= 0) return fd;
    }
    if (!g_real_open) { errno = ENOSYS; return -1; }
    return g_real_open(path, flags, mode);
}

__attribute__((visibility("default")))
int open64(const char *path, int flags, ...) {
    init_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (g_real_open64 && should_redirect(path, flags)) {
        int fd = fetch_patch(path, flags);
        if (fd >= 0) return fd;
    }
    if (!g_real_open64) { errno = ENOSYS; return -1; }
    return g_real_open64(path, flags, mode);
}

__attribute__((visibility("default")))
int openat(int dirfd, const char *path, int flags, ...) {
    init_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (g_real_openat && should_redirect(path, flags)
        && (dirfd == AT_FDCWD || path[0] == '/')) {
        int fd = fetch_patch(path, flags);
        if (fd >= 0) return fd;
    }
    if (!g_real_openat) { errno = ENOSYS; return -1; }
    return g_real_openat(dirfd, path, flags, mode);
}

__attribute__((visibility("default")))
int openat64(int dirfd, const char *path, int flags, ...) {
    init_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (g_real_openat64 && should_redirect(path, flags)
        && (dirfd == AT_FDCWD || path[0] == '/')) {
        int fd = fetch_patch(path, flags);
        if (fd >= 0) return fd;
    }
    if (!g_real_openat64) { errno = ENOSYS; return -1; }
    return g_real_openat64(dirfd, path, flags, mode);
}

/* stdio entry points.  glibc's fopen/fopen64 open the underlying file via
 * a PRIVATE internal open that does NOT go through the PLT, so our
 * open()/open64() interposers never see it — a business loader that opens
 * the .pat with fopen64() would bypass the redirect entirely unless we
 * hook the stdio functions directly.  Only read-only modes are redirected
 * ("r"/"rb", no "+"/"w"/"a"); on a hit we fetch the decrypted memfd and
 * wrap it with the REAL fdopen so the caller gets a FILE* over plaintext. */
static int should_redirect_stream(const char *path, const char *mode) {
    return is_patch_path(path) && mode && mode[0] == 'r' && !strchr(mode, '+');
}

static FILE *patch_fopen_common(const char *path, const char *mode,
                                FILE *(*real)(const char *, const char *)) {
    if (real && g_real_fdopen && should_redirect_stream(path, mode)) {
        int fd = fetch_patch(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            FILE *f = g_real_fdopen(fd, mode);
            if (f) { LOG("fopen %s: OK (memfd via fdopen)\n", path); return f; }
            close(fd);
        }
    }
    if (!real) { errno = ENOSYS; return NULL; }
    return real(path, mode);
}

__attribute__((visibility("default")))
FILE *fopen(const char *path, const char *mode) {
    init_reals();
    return patch_fopen_common(path, mode, g_real_fopen);
}

__attribute__((visibility("default")))
FILE *fopen64(const char *path, const char *mode) {
    init_reals();
    return patch_fopen_common(path, mode, g_real_fopen64);
}
