/*
 * antirev daemon-client — shared by dlopen_shim and aarch64_extend_shim.
 *
 * Owns the per-process daemon socket fd, the ANTIREV_FD_MAP env pointer,
 * and the parsed ANTIREV_ENC_LIBS basename set.  Provides accessors plus
 * the framed send/recv protocol helpers so each shim talks to the daemon
 * through one set of functions instead of carrying its own duplicate
 * client state.
 *
 * Init is idempotent and safe to call from any number of constructors.
 */

#ifndef ANTIREV_DAEMON_CLIENT_H
#define ANTIREV_DAEMON_CLIENT_H

#include <stddef.h>
#include <stdint.h>

/* Protocol constants — must match stub.c and the daemon. */
#define DC_MAX_NAME       255
#define DC_MAX_FILES      1024
#define DC_SCM_BATCH      250
#define DC_MAX_PAYLOAD    (4u + DC_SCM_BATCH * (2u + DC_MAX_NAME))

/* Daemon opcodes used by the shims. */
#define DC_OP_GET_LIB     0x02u
#define DC_OP_GET_CLOSURE 0x05u
#define DC_OP_BATCH       0x81u
#define DC_OP_END         0x82u
#define DC_OP_LIB         0x83u

/* Daemon reply status. */
#define DC_ST_OK          0u

#ifdef __cplusplus
extern "C" {
#endif

/* Read ANTIREV_LIBD_SOCK / ANTIREV_FD_MAP / ANTIREV_ENC_LIBS once and
 * cache the results.  Subsequent calls are no-ops. */
void daemon_client_init(void);

/* Inherited daemon socket fd, or -1 if unset / disabled. */
int  daemon_client_sock(void);

/* True iff ANTIREV_FD_MAP was set in the environment. */
int  daemon_client_have_fd_map(void);

/* True iff `base` appears in the parsed ANTIREV_ENC_LIBS set. */
int  daemon_client_is_encrypted(const char *base);

/* Eager-mode FD_MAP lookup.  On hit fills out_path with the canonical
 * "/proc/self/fd/N" string and returns 1; returns 0 on miss or when no
 * fd_map was provided. */
int  daemon_client_eager_lookup_path(const char *base, char *out_path, size_t out_sz);

/* Eager-mode FD_MAP lookup.  Returns the fd on hit, -1 on miss / no
 * fd_map. */
int  daemon_client_eager_lookup_fd(const char *base);

/* Send a framed message on the daemon socket.  Returns 0 on success,
 * -1 on socket / send failure (including no daemon socket configured). */
int  daemon_client_send(uint32_t op, const void *payload, uint32_t plen);

/* Receive one framed reply on the daemon socket.  *nfds is set to the
 * number of fds received via SCM_RIGHTS (0 if none).  Returns 0 on
 * success, -1 on wire / framing error or oversize payload — any fds
 * already consumed during the failed recv are closed before return,
 * so callers do not need to clean up on failure. */
int  daemon_client_recv(uint32_t *op,
                        uint8_t *payload, uint32_t *plen, uint32_t max_payload,
                        int *fds, int *nfds, int max_fds);

/* Serialize an entire request+reply sequence on the daemon socket.
 *
 * Both shims (dlopen_shim, aarch64_extend_shim) talk to the same
 * daemon over a single fd.  Each shim already serializes its own
 * concurrent callers via its per-shim mutex, but those mutexes are
 * independent — without a shared lock, dlopen_shim's send + multi-
 * batch recv could interleave on the wire with aarch64_extend_shim's
 * send + recv and either side would read the wrong reply.  Callers
 * MUST bracket their request+reply with these calls.
 *
 * Lock order (top-down): per-shim mutex → daemon_client_io_lock.
 * daemon_client never reaches back into shim-owned state, so this
 * order is deadlock-free as long as callers don't acquire shim
 * mutexes while holding the IO lock. */
void daemon_client_io_lock(void);
void daemon_client_io_unlock(void);

#ifdef __cplusplus
}
#endif

#endif  /* ANTIREV_DAEMON_CLIENT_H */
