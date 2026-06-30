/*
 * patch_fetch — shared hot-patch (.pat) helpers for antirev_shim.
 *
 * Both entry points into .pat redirection use these:
 *   - patch_redirect.c  (fopen/fopen64, ALL arches)
 *   - aarch64_extend_shim.c  (open/openat, aarch64 only — .pat rides
 *     alongside the existing .elf redirect)
 *
 * The .pat suffix check and the OP_GET_PATCH fetch live here ONCE so the
 * two hook sites stay in lockstep.  Fetch goes through the shared
 * daemon_client connection (__r_LS) — no key, no discovery file, no
 * separate lrxd.so: a protected process already holds the daemon socket.
 */
#ifndef ANTIREV_PATCH_FETCH_H
#define ANTIREV_PATCH_FETCH_H

#ifdef __cplusplus
extern "C" {
#endif

/* True iff `path`'s basename ends in ".pat" (the hot-patch artifact). */
int patch_is_pat_path(const char *path);

/* Fetch a FRESH decrypted memfd for the .pat named by `path`'s basename,
 * via the daemon's OP_GET_PATCH.  Returns the fd (caller owns it), or -1
 * on any miss/error.  No caching — each call yields its own memfd
 * (independent file offset). */
int patch_fetch_fd(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* ANTIREV_PATCH_FETCH_H */
