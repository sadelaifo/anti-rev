/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * arev_gate.c — qemu-user per-guest decrypt gate.
 *
 * Responsibilities (all policy; NO crypto and NO key ever live here):
 *   - open the /dev/vcachefs control device (host kernel);
 *   - at guest-ELF load, ask the kernel to verify the guest's vendor signature
 *     and remember whether THIS guest process is authorized;
 *   - at open() of a protected file:
 *       authorized guest   -> passthrough (-2): the normal open hits the
 *                             decrypting vcachefs mount -> plaintext, shared
 *                             page cache;
 *       unauthorized guest -> ask the kernel for the KEYLESS ciphertext and hand
 *                             the guest that fd (cp/objdump get a useless
 *                             container, never plaintext).
 *
 * Degrades safely: if /dev/vcachefs is absent (plaintext / non-vcachefs
 * deployment) the gate is INACTIVE and every hook is a passthrough, so a qemu
 * built with these hooks still runs everything normally.
 */
#include "qemu/osdep.h"

#include <sys/ioctl.h>

#include "arev_gate.h"
#include "arev_uapi.h"

/* Per qemu process (linux-user forks/re-execs per guest, so this is per-guest). */
static int   g_ctl = -1;        /* /dev/vcachefs fd, or -1 */
static bool  g_active;          /* device opened */
static bool  g_inited;          /* arev_gate_init() ran */
static bool  g_authorized;      /* current guest authorized? */
static char **g_roots;          /* protected absolute path prefixes */
static int   g_nroots;
static FILE *g_log;

static void arev_logf(const char *fmt, ...)
{
    va_list ap;
    if (!g_log) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

void arev_gate_init(void)
{
    const char *env;

    if (g_inited) {
        return;
    }
    g_inited = true;

    env = getenv("AREV_GATE_LOG");
    if (env && *env) {
        g_log = fopen(env, "ae");
    }

    env = getenv("AREV_GATE");
    if (env && (!strcmp(env, "off") || !strcmp(env, "0"))) {
        arev_logf("gate: disabled via AREV_GATE=%s", env);
        return;                 /* stays inactive */
    }

    /* Parse AREV_PROTECT_ROOTS (colon-separated absolute prefixes). */
    env = getenv("AREV_PROTECT_ROOTS");
    if (env && *env) {
        char *dup = strdup(env);
        char *save = NULL, *tok;
        for (tok = strtok_r(dup, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
            if (tok[0] != '/') {
                continue;       /* only absolute prefixes are meaningful */
            }
            g_roots = g_renew(char *, g_roots, g_nroots + 1);
            g_roots[g_nroots++] = g_strdup(tok);
        }
        free(dup);
    }

    g_ctl = open(AREV_DEV_PATH, O_RDWR | O_CLOEXEC);
    if (g_ctl < 0) {
        arev_logf("gate: %s not available (%s) -> inactive (passthrough)",
                  AREV_DEV_PATH, strerror(errno));
        return;
    }
    g_active = true;
    arev_logf("gate: active; %d protected root(s)", g_nroots);
}

bool arev_gate_active(void)
{
    return g_active;
}

/* True iff `path` is absolute and sits under one of the protected roots, with a
 * '/' (or exact) boundary so "/root/SWx" does not match root "/root/SW". */
static bool arev_is_protected(const char *path)
{
    int i;

    if (!path || path[0] != '/') {
        return false;
    }
    for (i = 0; i < g_nroots; i++) {
        size_t n = strlen(g_roots[i]);
        if (strncmp(path, g_roots[i], n) == 0 &&
            (path[n] == '/' || path[n] == '\0')) {
            return true;
        }
    }
    return false;
}

void arev_gate_set_guest(const char *guest_filename)
{
    int fd, ret;

    arev_gate_init();
    g_authorized = false;
    if (!g_active || !guest_filename) {
        return;
    }

    fd = open(guest_filename, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        arev_logf("guest '%s': open failed (%s) -> unauthorized",
                  guest_filename, strerror(errno));
        return;
    }
    ret = ioctl(g_ctl, AREV_IOC_AUTHORIZE_FD, (unsigned long)fd);
    close(fd);
    g_authorized = (ret == 0);
    arev_logf("guest '%s': %s", guest_filename,
              g_authorized ? "AUTHORIZED" : "unauthorized");
}

/* Ask the kernel for the keyless ciphertext of `path`.  Returns an fd, or -1
 * with errno set. */
static int arev_open_cipher(const char *path)
{
    struct arev_cipher_arg arg;
    size_t len = strlen(path) + 1;

    if (len > AREV_PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(&arg, 0, sizeof(arg));
    arg.path = (uint64_t)(uintptr_t)path;
    arg.path_len = (uint32_t)len;
    arg.out_fd = -1;
    if (ioctl(g_ctl, AREV_IOC_OPEN_CIPHER, &arg) != 0) {
        return -1;              /* errno set by ioctl */
    }
    return arg.out_fd;
}

int arev_gate_open(int dirfd, const char *host_pathname, int flags)
{
    int fd;

    (void)dirfd;                /* only absolute paths are gated for now */
    if (!g_active) {
        return -2;              /* inactive: normal open */
    }
    /* Only read-only opens can leak file content; writes (the RO mount rejects
     * them anyway) and create/trunc go the normal path. */
    if ((flags & O_ACCMODE) != O_RDONLY) {
        return -2;
    }
    if (!arev_is_protected(host_pathname)) {
        return -2;              /* not a protected file */
    }
    if (g_authorized) {
        /* Authorized guest: let the normal open hit the decrypting mount so the
         * kernel serves plaintext from the SHARED page cache. */
        return -2;
    }

    /* Unauthorized guest reading a protected file: serve keyless ciphertext.
     * NEVER fall through to a normal open here (that would leak plaintext). */
    fd = arev_open_cipher(host_pathname);
    if (fd >= 0) {
        arev_logf("open '%s': unauthorized -> keyless ciphertext (fd %d)",
                  host_pathname, fd);
        return fd;
    }
    switch (errno) {
    case ENOENT:
    case ENOTDIR:
    case EISDIR:
    case EINVAL:
        /* Not a gateable regular file (missing / directory / non-container):
         * dirs & metadata are not a plaintext-leak vector -> normal open. */
        arev_logf("open '%s': unauthorized, not a gateable file (%s) -> passthrough",
                  host_pathname, strerror(errno));
        return -2;
    default:
        /* Anything else (EACCES = we are not the signed qemu, EIO, ...) must
         * DENY rather than risk leaking plaintext. */
        arev_logf("open '%s': unauthorized, cipher fetch failed (%s) -> DENY",
                  host_pathname, strerror(errno));
        errno = EACCES;
        return -1;
    }
}
