/*
 * antirev daemon-client — shared by dlopen_shim and aarch64_extend_shim.
 *
 * Owns the per-process daemon socket fd, the __r_FM env pointer,
 * and the parsed __r_EL basename set.  Provides accessors plus
 * the framed send/recv protocol helpers so each shim talks to the daemon
 * through one set of functions instead of carrying its own duplicate
 * client state.
 *
 * Init is idempotent and safe to call from any number of constructors.
 *
 * ─── Stub→shim env-var name map ─────────────────────────────────────
 *
 * The stub passes runtime context to the LD_PRELOAD'd shim through a
 * fixed set of env vars.  Their names used to be ANTIREV_*; renamed
 * to opaque __r_* tokens so `cat /proc/<PID>/environ` no longer
 * fingerprints the protected process as antirev.  Keep this table
 * in sync with stub.c's env_is_antirev_managed() prefix list and
 * with tools/antirev_client.py if/when it grows env-var awareness.
 *
 *   ┌─────────────────────┬────────┐
 *   │         OLD          │  NEW  │
 *   ├─────────────────────┼────────┤
 *   │ ANTIREV_REAL_EXE    │ __r_RE │  real on-disk path of protected exe
 *   │ ANTIREV_MAIN_FD     │ __r_MF │  memfd fd of decrypted main exe
 *   │ ANTIREV_FD_MAP      │ __r_FM │  comma list  name=fd  for enc libs
 *   │ ANTIREV_CLOSE_FDS   │ __r_CF │  comma list of fds the shim ctor closes
 *   │ ANTIREV_LIBD_SOCK   │ __r_LS │  inherited daemon socket fd
 *   │ ANTIREV_ENC_LIBS    │ __r_EL │  comma list of encrypted lib basenames
 *   │ ANTIREV_SYMLINK_DIR │ __r_SD │  /tmp/<rand><pid>_XXXXXX symlink dir
 *   │ ANTIREV_NO_PRELOAD  │ __r_NP │  escape hatch — disable per-dep preload
 *   └─────────────────────┴────────┘
 *
 * Vars that intentionally KEEP their ANTIREV_* names — they're either
 * user-facing knobs or opt-in debug switches and any leak only
 * happens when the user explicitly sets them:
 *
 *   ANTIREV_LOG                 stderr gate for stub.c
 *   ANTIREV_DLOPEN_LOG          dlopen_shim debug log path
 *   ANTIREV_AARCH64_EXTEND_LOG  aarch64_extend_shim debug log path
 *   ANTIREV_KEY / ANTIREV_KEY_FD  Python client key discovery
 *   ANTIREV_TMP_PREFIX          CMake build-time + Python tmp prefix override
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
#define DC_OP_GET_PATCH   0x06u  /* lazy-decrypt a .patch by basename (antirev_patch.so) */
#define DC_OP_BATCH       0x81u
#define DC_OP_END         0x82u
#define DC_OP_LIB         0x83u

/* Daemon reply status. */
#define DC_ST_OK          0u

#ifdef __cplusplus
extern "C" {
#endif

/* Read __r_LS / __r_FM / __r_EL once and
 * cache the results.  Subsequent calls are no-ops. */
void daemon_client_init(void);

/* Shared owner-process flag.  exe_shim's constructor decides ownership
 * (/proc/self/exe "memfd:" or the __r_MF marker) and calls mark_owner
 * BEFORE it unsets __r_MF.  aarch64_extend_shim's constructor runs later
 * and, under QEMU where /proc/self/exe is the qemu binary (so __r_MF was
 * its only ownership signal and is now consumed), reads is_owner instead.
 * Without this, ANTI_LoadProcess interception silently no-ops on QEMU. */
void daemon_client_mark_owner(void);
int  daemon_client_is_owner(void);

/* Inherited daemon socket fd, or -1 if unset / disabled. */
int  daemon_client_sock(void);

/* True iff __r_FM was set in the environment. */
int  daemon_client_have_fd_map(void);

/* True iff `base` appears in the parsed __r_EL set. */
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
