/*
 * libplainprov — a PLAINTEXT (never encrypted) third-party-style lib
 * that provides plain_impl().  It is DT_NEEDED only by the *root*
 * encrypted lib (libencroot), NOT by the encrypted consumer
 * (libenccons) that actually calls plain_impl().  This is the Class-3
 * implicit-dep shape: the provider is a plaintext lib the daemon
 * cannot infer a closure edge for, so only natural load (__r_NP)
 * resolves it.
 */

__attribute__((visibility("default")))
int plain_impl(void) { return 99; }
