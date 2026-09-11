/*
 * gate.h — decrypt-authorization gate for fusefs.
 *
 * Only an authorized caller may reach plaintext of an encrypted file; everyone
 * else gets the keyless passthrough container or -EACCES (decided in fs.c).
 * Authorization keys on the CALLER's executable identity, resolved from
 * /proc/<pid>/exe (pid supplied by FUSE via fuse_get_context()).
 *
 * NOTE (documented in DESIGN.md): resolving identity from /proc after the call
 * arrives is inherently racy (TOCTOU / PID reuse) — unlike kmod2's atomic
 * in-open check.  Acceptable under the project threat model, not equivalent.
 */
#ifndef FUSEFS_GATE_H
#define FUSEFS_GATE_H

#include <stdbool.h>
#include <sys/types.h>

struct gate_config {
	bool enforce;		/* false = allow-all (bring-up / dev) */
	const char *authz_path;	/* optional allow-list file (dev); NULL = none */
};

void gate_init(const struct gate_config *cfg);

/* True if the process `pid` is authorized to decrypt.  On any resolution
 * failure while enforcing, returns false (fail-closed). */
bool gate_task_authorized(pid_t pid);

#endif /* FUSEFS_GATE_H */
