/*
 * runtime_paths.h — accessors for the per-build-random /tmp prefix.
 *
 * antirev creates per-process symlink dirs under /tmp at runtime, and
 * the daemon sweeps stale ones at startup/shutdown.  The naming used
 * to be a fixed "/tmp/antirev_<pid>_<rand>", which made the binary's
 * runtime footprint trivial to fingerprint:
 *
 *     $ ls /tmp/antirev_*
 *
 * Now the prefix is generated fresh on every CMake configure, baked
 * into a generated .c (cmake/runtime_paths.c.in) as an OBFSTR-wrapped
 * literal, and exposed to callers through this header.  Each release
 * build gets a different runtime fingerprint.
 *
 * Why functions, not a #define:
 *   - obfstr_gen.py only obfuscates literals appearing as direct
 *     function-call arguments.  A `#define PREFIX "...."` macro
 *     would be invisible to the codegen and end up cleartext in
 *     .rodata, defeating the whole point.
 *   - Wrapping the literal in an OBFSTR(...) call inside a generated
 *     helper function makes obfstr_gen catch it cleanly.
 *
 * Lifetime: every helper writes into a caller-owned buffer.  None
 * return the OBFSTR pointer directly — that pointer would be alloca'd
 * on the helper's stack frame and dangle the moment the helper
 * returns.
 */

#ifndef ANTIREV_RUNTIME_PATHS_H
#define ANTIREV_RUNTIME_PATHS_H

#include <stddef.h>

/* Fill `buf` with the mkdtemp template "/tmp/<rand><pid>_XXXXXX". */
void antirev_make_link_dir_template(char *buf, size_t sz, int pid);

/* Fill `buf` with the /tmp directory prefix "/tmp/<rand>" — used by
 * exe_shim's owner-side cleanup to strip our runtime dirs out of
 * inherited LD_LIBRARY_PATH. */
void antirev_get_tmp_dir_prefix(char *buf, size_t sz);

/* Match a /tmp dirent name against "<rand><pid>_<chars>".  Returns
 * 1 + sets *out_pid if it's one of ours, 0 otherwise.  Used by the
 * daemon's stale-dir reaper. */
int antirev_dir_name_matches_us(const char *name, int *out_pid);

/* Fill `buf` with the daemon's deps-graph debug log path. */
void antirev_make_deps_log_path(char *buf, size_t sz);

#endif /* ANTIREV_RUNTIME_PATHS_H */
