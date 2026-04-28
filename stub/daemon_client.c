/*
 * antirev daemon-client — see daemon_client.h.
 *
 * One copy of the daemon-protocol state (socket fd, fd-map env pointer,
 * encrypted-name set) shared by every shim in this DSO.  Each shim used
 * to keep its own private copies, which was harmless when they shipped
 * as separate DSOs but became a coupling concern once the shims were
 * folded into a single antirev_shim.so.  Centralising the state behind
 * accessors removes that concern: every reader/writer goes through the
 * same functions, so there is only one init path and one source of
 * truth.
 */

#define _GNU_SOURCE
#include "daemon_client.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

static int         g_initialized = 0;
static int         g_sock        = -1;
static const char *g_fd_map      = NULL;

static char g_enc_names[DC_MAX_FILES][DC_MAX_NAME + 1];
static int  g_enc_count = 0;

/* ------------------------------------------------------------------ */
/*  Little-endian helpers                                              */
/* ------------------------------------------------------------------ */

static inline void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline uint32_t u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/*  Init                                                                */
/* ------------------------------------------------------------------ */

void daemon_client_init(void)
{
    if (g_initialized) return;
    g_initialized = 1;

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
                 tok && g_enc_count < DC_MAX_FILES;
                 tok = strtok_r(NULL, ",", &save)) {
                size_t len = strlen(tok);
                if (len == 0 || len > DC_MAX_NAME) continue;
                memcpy(g_enc_names[g_enc_count], tok, len + 1);
                g_enc_count++;
            }
            free(buf);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Accessors                                                           */
/* ------------------------------------------------------------------ */

int daemon_client_sock(void)         { return g_sock; }
int daemon_client_have_fd_map(void)  { return g_fd_map != NULL; }

int daemon_client_is_encrypted(const char *base)
{
    for (int i = 0; i < g_enc_count; i++) {
        if (strcmp(g_enc_names[i], base) == 0) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  ANTIREV_FD_MAP lookup ("name=fd,name=fd,...")                      */
/* ------------------------------------------------------------------ */

int daemon_client_eager_lookup_fd(const char *base)
{
    if (!g_fd_map || !base) return -1;
    size_t blen = strlen(base);
    const char *p = g_fd_map;
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

int daemon_client_eager_lookup_path(const char *base, char *out_path, size_t out_sz)
{
    int fd = daemon_client_eager_lookup_fd(base);
    if (fd < 0) return 0;
    snprintf(out_path, out_sz, "/proc/self/fd/%d", fd);
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Framed v2 protocol helpers                                          */
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

int daemon_client_send(uint32_t op, const void *payload, uint32_t plen)
{
    if (g_sock < 0) return -1;
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
    ssize_t n = sendmsg(g_sock, &msg, 0);
    if (n < 0) return -1;
    if ((size_t)n == total) return 0;
    /* Partial send — finish header then payload. */
    size_t sent = (size_t)n;
    if (sent < 8) {
        if (send(g_sock, hdr + sent, 8 - sent, 0) != (ssize_t)(8 - sent)) return -1;
        sent = 8;
    }
    size_t prem = total - sent;
    if (prem > 0) {
        if (send(g_sock, (const uint8_t *)payload + (sent - 8), prem, 0)
            != (ssize_t)prem) return -1;
    }
    return 0;
}

int daemon_client_recv(uint32_t *op,
                       uint8_t *payload, uint32_t *plen, uint32_t max_payload,
                       int *fds, int *nfds, int max_fds)
{
    if (g_sock < 0) return -1;

    *nfds = 0;
    uint8_t hdr[8];
    struct iovec iov = { hdr, sizeof(hdr) };
    char cmsg_buf[CMSG_SPACE(DC_SCM_BATCH * sizeof(int))];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    struct msghdr msg = {0};
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    ssize_t got = recvmsg(g_sock, &msg, 0);
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
        if (recv_full(g_sock, hdr + got, sizeof(hdr) - (size_t)got) < 0)
            return -1;
    }
    *op = u32le(hdr);
    uint32_t p = u32le(hdr + 4);
    if (p > max_payload) return -1;
    *plen = p;
    if (p > 0) {
        if (recv_full(g_sock, payload, p) < 0) return -1;
    }
    return 0;
}
