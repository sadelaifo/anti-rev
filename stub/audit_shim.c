/*
 * antirev rtld-audit shim — loaded via LD_AUDIT into the target binary.
 *
 * Reads the AES-256 key from the fd given in ANTIREV_KEY_FD (a memfd written
 * by the stub before fexecve).  In la_objsearch(), intercepts any absolute
 * path that points to an antirev-encrypted .so file (magic "ANTREV01"),
 * decrypts it to a new memfd, and returns "/proc/self/fd/<N>" so the dynamic
 * linker maps the plaintext image.  Decrypted fds are cached so each library
 * is only decrypted once.  Unknown paths pass through unchanged.
 */

#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include "crypto.h"

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
/*  Key storage                                                        */
/* ------------------------------------------------------------------ */

static uint8_t g_key[KEY_SIZE];
static int     g_key_ready = 0;

static void load_key(void)
{
    if (g_key_ready)
        return;
    const char *s = getenv("ANTIREV_KEY_FD");
    if (!s)
        return;
    int kfd = atoi(s);
    if (read(kfd, g_key, KEY_SIZE) == KEY_SIZE)
        g_key_ready = 1;
    close(kfd);
}

/* ------------------------------------------------------------------ */
/*  Decrypted-library cache                                            */
/* ------------------------------------------------------------------ */

static struct {
    char src_path[512];
    char fd_path[32];    /* "/proc/self/fd/N" — persistent, returned to linker */
    int  fd;
} g_cache[MAX_CACHE];
static int g_cache_n = 0;

static const char *cache_lookup(const char *path)
{
    for (int i = 0; i < g_cache_n; i++)
        if (strcmp(g_cache[i].src_path, path) == 0)
            return g_cache[i].fd_path;
    return NULL;
}

static const char *cache_insert(const char *path, int fd)
{
    if (g_cache_n >= MAX_CACHE)
        return NULL;
    int i = g_cache_n++;
    strncpy(g_cache[i].src_path, path, sizeof(g_cache[i].src_path) - 1);
    g_cache[i].src_path[sizeof(g_cache[i].src_path) - 1] = '\0';
    g_cache[i].fd = fd;
    snprintf(g_cache[i].fd_path, sizeof(g_cache[i].fd_path), "/proc/self/fd/%d", fd);
    return g_cache[i].fd_path;
}

/* ------------------------------------------------------------------ */
/*  Two-pass streaming decryption → memfd                             */
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

    /* Pass B: CTR decrypt → memfd */
    int mfd = memfd_create(name, 0 /* no MFD_CLOEXEC */);
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
    /* Cache hit */
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
