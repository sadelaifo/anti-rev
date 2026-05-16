/*
 * libplainprov — a PLAINTEXT (never encrypted) third-party-style lib
 * that provides plain_impl().  It is DT_NEEDED only by the *root*
 * encrypted lib (libencroot), NOT by the encrypted consumer
 * (libenccons) that actually calls plain_impl().  This is the Class-3
 * implicit-dep shape the daemon-side symbol-completion closure cannot
 * fix (it only scans the encrypted lib set), so only natural load
 * (__r_NP) resolves it.
 */

__attribute__((visibility("default")))
int plain_impl(void) { return 99; }
