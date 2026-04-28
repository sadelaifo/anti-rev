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
#include "daemon_client.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

static void *(*real_dlopen_fn)(const char *, int) = NULL;

static char g_symlink_dir[256] = {0};

/* Cache of libs we have already fetched lazily (names + fds held open). */
static char g_cache_names[DC_MAX_FILES][DC_MAX_NAME + 1];
static int  g_cache_fds[DC_MAX_FILES];
static int  g_cache_count = 0;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Escape hatch: if ANTIREV_NO_PRELOAD is set in the environment, skip
 * the per-dep preload loop in fetch_closure and rely on glibc's normal
 * recursive DT_NEEDED walk (triggered by the caller's real_dlopen of
 * the root lib) to load the whole dependency tree in one atomic go.
 *
 * Why this matters: the per-dep preload loop dlopens each dep
 * individually, which runs each dep's ctors in isolation with an
 * incomplete link-map state.  Business software whose libs carry
 * implicit symbol dependencies (a dep references a symbol provided by
 * a sibling dep with no DT_NEEDED edge between them) then hits lazy
 * binding failures mid-ctor.  Plaintext glibc loads avoid this by
 * mapping everything before running any ctor.  Setting this env var
 * reproduces that plaintext-equivalent load pattern, at the cost of
 * losing the DT_RPATH-hits-ciphertext protection for libs that set
 * DT_RPATH to the encrypted on-disk dir. */
static int g_no_preload = 0;

/* Diagnostic log file opened at ctor time if ANTIREV_DLOPEN_LOG is set
 * in the environment.  Records every dlopen decision and fetch outcome
 * so we can diagnose "dlopen(enc A) -> DT_NEEDED(enc B)" failures in
 * production binaries without needing stderr. */
static FILE *g_log = NULL;
#define LOG(...) do { if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)

/* ------------------------------------------------------------------ */
/*  Little-endian helper                                               */
/* ------------------------------------------------------------------ */
static inline void put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
}

/* ------------------------------------------------------------------ */
/*  Cache lookup                                                       */
/* ------------------------------------------------------------------ */

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

/* Send the OP_GET_CLOSURE request for `base`.  Returns 0 on success,
 * -1 on name-length / send failure. */
static int send_closure_request(const char *base) {
    uint16_t nlen = (uint16_t)strlen(base);
    if (nlen == 0 || nlen > DC_MAX_NAME)
        return -1;

    uint8_t req[2 + DC_MAX_NAME];
    put_u16le(req, nlen);
    memcpy(req + 2, base, nlen);
    if (daemon_client_send(DC_OP_GET_CLOSURE, req, (uint32_t)(2 + nlen)) < 0) {
        LOG("  send OP_GET_CLOSURE failed\n");
        return -1;
    }
    return 0;
}

/* Materialize a just-received (name, fd) pair: either drop it as a
 * duplicate / overflow, or install it into the cache + create the
 * symlink dir entry.  Returns 1 if newly installed (caller should
 * append `name` to new_names), 0 if the fd was consumed (cached or
 * dropped), -1 on symlink failure (fd already closed). */
static int install_closure_member(const char *name, size_t nlen, int fd) {
    if (cache_find(name) >= 0) {
        LOG("    dup %s (closed fresh fd)\n", name);
        close(fd);
        return 0;
    }
    if (g_cache_count >= DC_MAX_FILES) {
        close(fd);
        return 0;
    }

    char lpath[512], target[64];
    snprintf(lpath, sizeof(lpath), "%s/%s", g_symlink_dir, name);
    snprintf(target, sizeof(target), "/proc/self/fd/%d", fd);

    /* Overwrite any stale symlink that points at a closed fd (e.g., a
     * DT_NEEDED lib whose stub-era fd was reaped by exe_shim).  The
     * in-memory mapping stays live regardless. */
    unlink(lpath);
    if (symlink(target, lpath) < 0) {
        LOG("    symlink %s -> %s FAILED errno=%d\n", lpath, target, errno);
        close(fd);
        return -1;
    }
    LOG("    new  %s (fd=%d)\n", name, fd);
    memcpy(g_cache_names[g_cache_count], name, nlen + 1);
    g_cache_fds[g_cache_count] = fd;
    g_cache_count++;
    return 1;
}

/* Parse one OP_BATCH payload, installing each (name, fd) pair.
 * Returns 0 on success, -1 on wire-format error (caller disconnects).
 * Any fd not consumed by install_closure_member is closed. */
static int process_closure_batch(const uint8_t *payload, uint32_t plen, int *fds, int nf,
                                 char (*new_names)[DC_MAX_NAME + 1], int *new_count, int *n_received) {
    if (plen < 4)
        goto wire_error;
    uint32_t nl = (uint32_t)payload[0]
                | ((uint32_t)payload[1] << 8)
                | ((uint32_t)payload[2] << 16)
                | ((uint32_t)payload[3] << 24);
    if ((int) nl != nf)
        goto wire_error;

    size_t poff = 4;
    for (uint32_t i = 0; i < nl; i++) {
        if (poff + 2 > plen)
            goto wire_error_from_i;
        uint16_t l = (uint16_t) payload[poff] | ((uint16_t) payload[poff + 1] << 8);
        poff += 2;
        if (l == 0 || l > DC_MAX_NAME || poff + l > plen)
            goto wire_error_from_i;

        char name[DC_MAX_NAME + 1];
        memcpy(name, payload + poff, l);
        name[l] = '\0';
        poff += l;

        (*n_received)++;
        int added = install_closure_member(name, l, fds[i]);
        if (added == 1 && *new_count < DC_MAX_FILES) {
            memcpy(new_names[*new_count], name, (size_t) l + 1);
            (*new_count)++;
        }
        continue;

    wire_error_from_i:
        for (uint32_t k = i; k < nl; k++)
            close(fds[k]);
        return -1;
    }
    return 0;

wire_error:
    for (int i = 0; i < nf; i++)
        close(fds[i]);
    return -1;
}

/* Drain OP_BATCH messages until OP_END.  Populates new_names with the
 * libs newly added to the cache (in daemon-returned topological order)
 * and returns the total count received.  Negative return on error. */
static int recv_closure(char (*new_names)[DC_MAX_NAME + 1], int *new_count) {
    int n_received = 0;
    for (;;) {
        uint32_t op, plen;
        uint8_t  payload[DC_MAX_PAYLOAD];
        int      fds[DC_SCM_BATCH];
        int      nf = 0;
        if (daemon_client_recv(&op, payload, &plen, DC_MAX_PAYLOAD,
                               fds, &nf, DC_SCM_BATCH) < 0)
            return -1;
        if (op == DC_OP_END)
            return n_received;
        if (op != DC_OP_BATCH) {
            for (int i = 0; i < nf; i++)
                close(fds[i]);
            return -1;
        }
        if (process_closure_batch(payload, plen, fds, nf, new_names, new_count, &n_received) < 0)
            return -1;
    }
}

/* Pre-load each newly-cached dep via its symlink path, in the order
 * the daemon returned them (topological: leaves first).  Each load
 * registers the dep's SONAME in glibc's link map so the caller's
 * outer real_dlopen(base) finds its DT_NEEDED chain in the link map
 * instead of falling back to DT_RPATH/DT_RUNPATH on disk.
 *
 * `base` is explicitly skipped: pinning the root's refcount here
 * prevents the caller from ever fully dlclose()ing it, which breaks
 * plugin systems that unload one plugin before loading the next —
 * notably libprotobuf's "File already exists in database" when two
 * plugins carry overlapping descriptors.
 *
 * RTLD_GLOBAL is mandatory — generated .pb.cc code exports
 * `descriptor_table_<file>_2eproto` with default visibility and
 * registers it via std::call_once on the table's own once_flag*.  If
 * two DSOs statically link the same .pb.o, RTLD_LOCAL leaves their
 * tables in separate symbol scopes, both ctors' call_once fire, and
 * libprotobuf sees duplicate registrations.  RTLD_GLOBAL lets the
 * first-loaded copy interpose, matching plaintext load-time semantics. */
static void preload_closure_deps(const char *base, const char (*new_names)[DC_MAX_NAME + 1], int new_count) {
    for (int i = 0; i < new_count; i++) {
        if (strcmp(new_names[i], base) == 0) {
            LOG("    skip-root %s\n", new_names[i]);
            continue;
        }
        char spath[512];
        snprintf(spath, sizeof(spath), "%s/%s", g_symlink_dir, new_names[i]);
        void *h = real_dlopen_fn(spath, RTLD_LAZY | RTLD_GLOBAL);
        if (!h) {
            const char *err = dlerror();
            LOG("    preload(%s) FAILED: %s\n", new_names[i], err ? err : "(null)");
        } else {
            LOG("    preload(%s) OK handle=%p\n", new_names[i], h);
        }
        /* Deps stay pinned — typically shared across plugins
         * (libc++, libprotobuf, libQtCore, etc.) so repeated plugin
         * loads don't drop and re-register them. */
    }
}

/* Request `base` and its transitive encrypted closure from the daemon,
 * materialize symlinks for any names we don't already have cached,
 * keep the fds open for the process lifetime, and pre-load each new
 * dep so glibc resolves DT_NEEDED through the link map instead of the
 * on-disk encrypted directory.  Caller must hold g_lock. */
static void fetch_closure(const char *base) {
    if (cache_find(base) >= 0) {
        LOG("  cache-hit %s\n", base);
        return;
    }
    if (daemon_client_sock() < 0 || !g_symlink_dir[0]) {
        LOG("  no-sock (sock=%d dir='%s')\n", daemon_client_sock(), g_symlink_dir);
        return;
    }

    if (send_closure_request(base) < 0)
        return;

    char new_names[DC_MAX_FILES][DC_MAX_NAME + 1];
    int new_count = 0;
    int n_received = recv_closure(new_names, &new_count);
    if (n_received < 0)
        return;
    LOG("  closure for %s: %d libs total\n", base, n_received);

    /* Escape hatch — see g_no_preload.  Skip the loop entirely when
     * the user wants plaintext-equivalent natural-load semantics. */
    if (g_no_preload) {
        LOG("  preload skipped (ANTIREV_NO_PRELOAD=1)\n");
        return;
    }

    preload_closure_deps(base, new_names, new_count);
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

    daemon_client_init();

    const char *dir = getenv("ANTIREV_SYMLINK_DIR");
    if (dir && *dir) {
        snprintf(g_symlink_dir, sizeof(g_symlink_dir), "%s", dir);
    }

    const char *npe = getenv("ANTIREV_NO_PRELOAD");
    if (npe && *npe && strcmp(npe, "0") != 0) {
        g_no_preload = 1;
    }

    LOG("[dlopen_shim] sock=%d dir=%s fd_map=%s no_preload=%d\n",
        daemon_client_sock(), g_symlink_dir,
        daemon_client_have_fd_map() ? "yes" : "no", g_no_preload);
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
    if (daemon_client_have_fd_map()) {
        char redir[64];
        if (daemon_client_eager_lookup_path(base, redir, sizeof(redir)))
            return real_dlopen_fn(redir, flags);
        return real_dlopen_fn(filename, flags);
    }

    /* Lazy path. */
    int enc = daemon_client_is_encrypted(base);
    if (daemon_client_sock() < 0 || !enc) {
        LOG("dlopen(%s) flags=0x%x -> passthrough (enc=%d)\n",
            filename, flags, enc);
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
