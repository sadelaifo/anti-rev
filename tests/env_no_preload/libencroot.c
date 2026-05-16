/*
 * libencroot — the encrypted lib the test exe dlopens.  DT_NEEDEDs
 * BOTH libenccons (encrypted) and libplainprov (plaintext).  The
 * plaintext provider therefore only enters the picture via the root's
 * DT_NEEDED — never libenccons's — so the per-dep preload loop loads
 * libenccons before libplainprov exists.
 */

extern int enccons_get(void);
extern int libenccons_marker;

__attribute__((visibility("default")))
int encroot_get(void)
{
    return enccons_get() + (libenccons_marker - 1);
}
