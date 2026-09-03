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

/*
 * Compile-time default protected roots (colon-separated absolute prefixes).
 * The gate protects these even when AREV_PROTECT_ROOTS is unset, so the
 * environment cannot be used to disable protection (fail-closed).  Edit for your
 * deployment, or override at build time with
 *   -DAREV_DEFAULT_PROTECT_ROOTS='"/root/SW:/opt/app"'
 */
#ifndef AREV_DEFAULT_PROTECT_ROOTS
#define AREV_DEFAULT_PROTECT_ROOTS "/root/SW"
#endif

/* Per qemu process (linux-user forks/re-execs per guest, so this is per-guest). */
static int   g_ctl = -1;        /* /dev/vcachefs fd, or -1 */
static bool  g_active;          /* device opened */
static bool  g_inited;          /* arev_gate_init() ran */
static bool  g_authorized;      /* current guest authorized? */
static char **g_roots;          /* protected absolute path prefixes */
static int   g_nroots;
static FILE *arev_logfile;

static void __attribute__((format(printf, 1, 2)))
arev_logf(const char *fmt, ...)
{
    va_list ap;
    if (!arev_logfile) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(arev_logfile, fmt, ap);
    va_end(ap);
    fputc('\n', arev_logfile);
    fflush(arev_logfile);
}

/* Append the colon-separated absolute prefixes in `s` to the protected-root
 * list.  NULL/empty is ignored; non-absolute entries are skipped. */
static void arev_add_roots(const char *s)
{
    char *dup, *save = NULL, *tok;

    if (!s || !*s) {
        return;
    }
    dup = strdup(s);
    for (tok = strtok_r(dup, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
        if (tok[0] != '/') {
            continue;           /* only absolute prefixes are meaningful */
        }
        g_roots = g_renew(char *, g_roots, g_nroots + 1);
        g_roots[g_nroots++] = g_strdup(tok);
    }
    free(dup);
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
        arev_logfile = fopen(env, "ae");
    }

    env = getenv("AREV_GATE");
    if (env && (!strcmp(env, "off") || !strcmp(env, "0"))) {
        arev_logf("gate: disabled via AREV_GATE=%s", env);
        return;                 /* stays inactive */
    }

    /* Protected roots: a compile-time DEFAULT (fail-closed — the gate protects
     * these even with no env set, so an SSH shell / cron / forgotten launch
     * path cannot bypass it) PLUS whatever AREV_PROTECT_ROOTS adds. */
    arev_add_roots(AREV_DEFAULT_PROTECT_ROOTS);
    arev_add_roots(getenv("AREV_PROTECT_ROOTS"));

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

/*
 * Resolve `path` (possibly relative, possibly openat-relative to `dirfd`) to an
 * absolute, canonical path in `out`, so relative paths / cwd tricks / .. /
 * symlinks cannot bypass the protected-root check.  Returns true on success.
 */
static bool arev_resolve(int dirfd, const char *path, char *out, size_t outsz)
{
    char joined[PATH_MAX];

    if (path[0] == '/') {
        if (realpath(path, out)) {
            return true;
        }
        /* file may not exist yet — keep the absolute path as-is */
        if (strlen(path) >= outsz) {
            return false;
        }
        strcpy(out, path);
        return true;
    }
    /* relative: prepend cwd (AT_FDCWD) or the dirfd's directory */
    if (dirfd == AT_FDCWD) {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) {
            return false;
        }
        if (snprintf(joined, sizeof(joined), "%s/%s", cwd, path) >= (int)sizeof(joined)) {
            return false;
        }
    } else {
        char link[64], base[PATH_MAX];
        ssize_t n;
        snprintf(link, sizeof(link), "/proc/self/fd/%d", dirfd);
        n = readlink(link, base, sizeof(base) - 1);
        if (n < 0) {
            return false;
        }
        base[n] = '\0';
        if (snprintf(joined, sizeof(joined), "%s/%s", base, path) >= (int)sizeof(joined)) {
            return false;
        }
    }
    if (realpath(joined, out)) {
        return true;
    }
    if (strlen(joined) >= outsz) {
        return false;
    }
    strcpy(out, joined);
    return true;
}

int arev_gate_open(int dirfd, const char *host_pathname, int flags)
{
    char resolved[PATH_MAX];
    const char *p;
    int fd;

    if (!g_active) {
        return -2;              /* inactive: normal open */
    }
    /* Only read-only opens can leak file content; writes (the RO mount rejects
     * them anyway) and create/trunc go the normal path. */
    if ((flags & O_ACCMODE) != O_RDONLY) {
        return -2;
    }
    /* Resolve to an absolute canonical path FIRST — a relative path (e.g.
     * `objdump FOO` from inside the dir) or openat(dirfd,...) must not slip past
     * the protected-root check.  If we cannot resolve it, be conservative: a
     * path we can't classify is treated as unprotected only when the gate is
     * off anyway; here we fall through to a normal open (resolution failure is
     * effectively never for a real open the guest is about to do). */
    if (!arev_resolve(dirfd, host_pathname, resolved, sizeof(resolved))) {
        return -2;
    }
    p = resolved;
    if (!arev_is_protected(p)) {
        return -2;              /* not a protected file */
    }
    if (g_authorized) {
        /* Authorized guest: let the normal open hit the decrypting mount so the
         * kernel serves plaintext from the SHARED page cache. */
        return -2;
    }

    /* Unauthorized guest reading a protected file: serve keyless ciphertext.
     * NEVER fall through to a normal open here (that would leak plaintext). */
    fd = arev_open_cipher(p);
    if (fd >= 0) {
        arev_logf("open '%s': unauthorized -> keyless ciphertext (fd %d)",
                  p, fd);
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
                  p, strerror(errno));
        return -2;
    default:
        /* Anything else (EACCES = we are not the signed qemu, EIO, ...) must
         * DENY rather than risk leaking plaintext. */
        arev_logf("open '%s': unauthorized, cipher fetch failed (%s) -> DENY",
                  p, strerror(errno));
        errno = EACCES;
        return -1;
    }
}
