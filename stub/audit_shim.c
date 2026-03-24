/*
 * antirev rtld-audit shim — loaded via LD_AUDIT into the target binary.
 *
 * Reads the AES-256 key from the fd given in ANTIREV_KEY_FD (a memfd written
 * by the stub before fexecve), or from ANTIREV_KEY_HEX env var as fallback
 * (survives daemon fd-close).  In la_objsearch(), intercepts any absolute
 * path that points to an antirev-encrypted .so file (magic "ANTREV01"),
 * decrypts it to a new memfd, and returns "/proc/self/fd/<N>" so the dynamic
 * linker maps the plaintext image.  Decrypted fds are cached so each library
 * is only decrypted once.  Unknown paths pass through unchanged.
 *
 * Thread safety: cache uses atomic slot reservation (lock-free).
 * Daemon compat: self-healing cache re-decrypts if fds were closed.
 * seccomp compat: falls back to /dev/shm or /tmp if memfd_create is blocked.
 */

#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdint.h>
#include "crypto.h"

/* Use raw syscall instead of glibc wrapper — the wrapper may not be
 * available when loaded via LD_AUDIT into a process whose libc lacks
 * the memfd_create symbol (glibc < 2.27) or during early linker init. */
#ifndef __NR_memfd_create
#  if defined(__x86_64__)
#    define __NR_memfd_create 319
#  elif defined(__aarch64__)
#    define __NR_memfd_create 279
#  endif
#endif
static inline int raw_memfd_create(const char *name, unsigned int flags)
{
    return (int)syscall(__NR_memfd_create, name, flags);
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define MAGIC        "ANTREV01"
#define MAGIC_LEN    8
#define IV_SIZE      12
#define TAG_SIZE     16
#define HDR_SIZE     (MAGIC_LEN + IV_SIZE + TAG_SIZE)   /* 36 bytes */
#define KEY_SIZE     32
#define CHUNK        (1 << 20)   /* 1 MB I/O buffer */
#define MAX_CACHE    128

/* ------------------------------------------------------------------ */
/*  Anonymous fd creation with fallback (Fix #4: seccomp compat)       */
/* ------------------------------------------------------------------ */

static int make_anon_fd(const char *name)
{
    /* Try memfd_create first (most secure: never touches disk) */
    int fd = raw_memfd_create(name, 0);
    if (fd >= 0)
        return fd;

    /* Fallback: /dev/shm (tmpfs, usually not blocked by seccomp) */
    char path[256];
    snprintf(path, sizeof(path), "/dev/shm/.antirev_%d_%s", (int)getpid(), name);
    fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0700);
    if (fd >= 0) {
        unlink(path);   /* immediate unlink — fd stays valid */
        return fd;
    }

    /* Last resort: /tmp (briefly visible on disk until unlink) */
    snprintf(path, sizeof(path), "/tmp/.antirev_%d_%s", (int)getpid(), name);
    fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0700);
    if (fd >= 0) {
        unlink(path);
        return fd;
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/*  Key storage (Fix #1: daemon fd-close compat)                       */
/* ------------------------------------------------------------------ */

static uint8_t g_key[KEY_SIZE];
static int     g_key_ready = 0;

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        int hi, lo;
        char c;

        c = hex[2 * i];
        if      (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return -1;

        c = hex[2 * i + 1];
        if      (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return -1;

        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void load_key(void)
{
    if (g_key_ready)
        return;

    /* Primary: read from key fd (set by stub) */
    const char *s = getenv("ANTIREV_KEY_FD");
    if (s) {
        int kfd = atoi(s);
        if (pread(kfd, g_key, KEY_SIZE, 0) == KEY_SIZE) {
            g_key_ready = 1;
            return;
        }
    }

    /* Fallback: hex-encoded key in env (survives daemon fd-close) */
    const char *hex = getenv("ANTIREV_KEY_HEX");
    if (hex && strlen(hex) >= KEY_SIZE * 2) {
        if (hex_to_bytes(hex, g_key, KEY_SIZE) == 0)
            g_key_ready = 1;
    }
}

/* ------------------------------------------------------------------ */
/*  Decrypted-library cache (Fix #7: thread-safe, Fix #1: self-heal)   */
/* ------------------------------------------------------------------ */

static struct {
    char     src_path[512];
    char     fd_path[32];    /* "/proc/self/fd/N" */
    int      fd;
    volatile int ready;      /* set with release store after entry is written */
} g_cache[MAX_CACHE];
static volatile int g_cache_n = 0;

static const char *cache_lookup(const char *path)
{
    int n = __atomic_load_n(&g_cache_n, __ATOMIC_ACQUIRE);
    for (int i = 0; i < n; i++) {
        if (!__atomic_load_n(&g_cache[i].ready, __ATOMIC_ACQUIRE))
            continue;
        if (strcmp(g_cache[i].src_path, path) == 0) {
            /* Self-healing: check if the fd is still valid */
            if (fcntl(g_cache[i].fd, F_GETFD) == -1) {
                /* fd was closed (daemon fd-close); invalidate entry */
                __atomic_store_n(&g_cache[i].ready, 0, __ATOMIC_RELEASE);
                return NULL;
            }
            return g_cache[i].fd_path;
        }
    }
    return NULL;
}

static const char *cache_insert(const char *path, int fd)
{
    int slot = __atomic_fetch_add(&g_cache_n, 1, __ATOMIC_SEQ_CST);
    if (slot >= MAX_CACHE) {
        /* Undo the increment — slot is invalid */
        __atomic_fetch_sub(&g_cache_n, 1, __ATOMIC_SEQ_CST);
        return NULL;
    }
    strncpy(g_cache[slot].src_path, path, sizeof(g_cache[slot].src_path) - 1);
    g_cache[slot].src_path[sizeof(g_cache[slot].src_path) - 1] = '\0';
    g_cache[slot].fd = fd;
    snprintf(g_cache[slot].fd_path, sizeof(g_cache[slot].fd_path),
             "/proc/self/fd/%d", fd);
    __atomic_store_n(&g_cache[slot].ready, 1, __ATOMIC_RELEASE);
    return g_cache[slot].fd_path;
}

/* ------------------------------------------------------------------ */
/*  Two-pass streaming decryption → anonymous fd                       */
/* ------------------------------------------------------------------ */

static int decrypt_to_memfd(int src_fd, off_t ct_off, uint64_t ct_size,
                             const uint8_t iv[IV_SIZE], const uint8_t tag[TAG_SIZE],
                             const char *name)
{
    uint8_t *buf = malloc(CHUNK);
    if (!buf)
        return -1;

    aes256gcm_ctx ctx;

    /* Pass A: GHASH — verify authentication tag */
    aes256gcm_init(&ctx, g_key, iv);
    uint64_t rem = ct_size;
    off_t    pos = ct_off;
    while (rem > 0) {
        size_t  n   = rem < CHUNK ? (size_t)rem : CHUNK;
        ssize_t got = pread(src_fd, buf, n, pos);
        if (got != (ssize_t)n) { free(buf); return -1; }
        aes256gcm_ghash_update(&ctx, buf, n);
        pos += (off_t)n;
        rem -= n;
    }
    if (aes256gcm_ghash_verify(&ctx, tag) != 0) {
        fprintf(stderr, "[antirev] auth failed for '%s'\n", name);
        free(buf);
        return -1;
    }

    /* Pass B: CTR decrypt → anonymous fd */
    int mfd = make_anon_fd(name);
    if (mfd < 0) { free(buf); return -1; }

    aes256gcm_init(&ctx, g_key, iv);
    rem = ct_size;
    pos = ct_off;
    while (rem > 0) {
        size_t  n   = rem < CHUNK ? (size_t)rem : CHUNK;
        ssize_t got = pread(src_fd, buf, n, pos);
        if (got != (ssize_t)n) { free(buf); close(mfd); return -1; }
        aes256gcm_ctr_decrypt(&ctx, buf, buf, n);
        for (size_t w = 0; w < n; ) {
            ssize_t wr = write(mfd, buf + w, n - w);
            if (wr < 0) { free(buf); close(mfd); return -1; }
            w += (size_t)wr;
        }
        pos += (off_t)n;
        rem -= n;
    }
    lseek(mfd, 0, SEEK_SET);
    free(buf);
    return mfd;
}

/* ------------------------------------------------------------------ */
/*  Try to decrypt an absolute path; returns fd_path or NULL          */
/* ------------------------------------------------------------------ */

static const char *try_decrypt(const char *path)
{
    /* Cache hit (with self-healing: returns NULL if cached fd was closed) */
    const char *cached = cache_lookup(path);
    if (cached)
        return cached;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    uint8_t hdr[HDR_SIZE];
    if (read(fd, hdr, HDR_SIZE) != HDR_SIZE ||
        memcmp(hdr, MAGIC, MAGIC_LEN) != 0) {
        close(fd);
        return NULL;
    }

    load_key();
    if (!g_key_ready) {
        close(fd);
        return NULL;
    }

    uint8_t *iv  = hdr + MAGIC_LEN;
    uint8_t *tag = hdr + MAGIC_LEN + IV_SIZE;

    off_t    fsize   = lseek(fd, 0, SEEK_END);
    uint64_t ct_size = (uint64_t)(fsize - HDR_SIZE);

    /* Basename for the memfd label */
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    int mfd = decrypt_to_memfd(fd, (off_t)HDR_SIZE, ct_size, iv, tag, base);
    close(fd);
    if (mfd < 0)
        return NULL;

    return cache_insert(path, mfd);
}

/* ------------------------------------------------------------------ */
/*  rtld-audit interface                                               */
/* ------------------------------------------------------------------ */

__attribute__((visibility("default")))
unsigned int la_version(unsigned int version)
{
    (void)version;
    load_key();
    return LAV_CURRENT;
}

__attribute__((visibility("default")))
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
    (void)cookie;
    (void)flag;

    /* Only intercept absolute paths — bare names pass through so the linker
     * resolves them to full paths, which we then intercept on the next call. */
    if (name[0] != '/')
        return (char *)name;

    const char *fd_path = try_decrypt(name);
    return fd_path ? (char *)fd_path : (char *)name;
}
