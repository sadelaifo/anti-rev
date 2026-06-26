/*
 * patch_fetch — shared .pat suffix check + OP_GET_PATCH fetch.
 * See patch_fetch.h.  Compiled into antirev_shim on all arches.
 */
#define _GNU_SOURCE
#include "patch_fetch.h"
#include "daemon_client.h"

#include <string.h>
#include <stdint.h>
#include <unistd.h>

int patch_is_pat_path(const char *path)
{
    if (!path) return 0;
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    size_t len = strlen(b);
    return len > 4 && strcmp(b + len - 4, ".pat") == 0;
}

int patch_fetch_fd(const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    size_t blen = strlen(base);
    if (daemon_client_sock() < 0 || blen == 0 || blen > DC_MAX_NAME)
        return -1;

    /* Request payload: [name_len:2 LE][basename] — matches the daemon's
     * handle_get_patch and lrxd.so's send_get_patch. */
    uint8_t req[2 + DC_MAX_NAME];
    req[0] = (uint8_t)(blen & 0xffu);
    req[1] = (uint8_t)((blen >> 8) & 0xffu);
    memcpy(req + 2, base, blen);

    int got = -1;
    /* Serialize send+recv on the shared daemon socket so a concurrent
     * dlopen_shim / aarch64_extend_shim request can't steal our reply. */
    daemon_client_io_lock();
    if (daemon_client_send(DC_OP_GET_PATCH, req, (uint32_t)(2 + blen)) == 0) {
        uint32_t op = 0, plen = 0;
        uint8_t  resp[16];
        int      fds[1];
        int      nfds = 0;
        if (daemon_client_recv(&op, resp, &plen, sizeof(resp),
                               fds, &nfds, 1) == 0
            && op == DC_OP_LIB && plen >= 4) {
            uint32_t status = (uint32_t)resp[0]
                            | ((uint32_t)resp[1] << 8)
                            | ((uint32_t)resp[2] << 16)
                            | ((uint32_t)resp[3] << 24);
            if (status == DC_ST_OK && nfds == 1)
                got = fds[0];
            else
                for (int i = 0; i < nfds; i++) close(fds[i]);
        }
    }
    daemon_client_io_unlock();
    return got;
}
