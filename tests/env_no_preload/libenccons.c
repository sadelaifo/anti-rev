/*
 * libenccons — encrypted consumer.  Strong undefined reference to
 * plain_impl(), called from its constructor, with NO DT_NEEDED edge to
 * libplainprov (the provider is plaintext and only reachable through
 * the root's DT_NEEDED, not this lib's).
 *
 * Default preload path: dlopen_shim preloads libenccons in isolation
 * BEFORE the root (and thus libplainprov) is loaded; the ctor calls
 * plain_impl() -> "symbol lookup error" -> process abort.  That is the
 * exact Class-3 failure.
 *
 * Natural load (__r_NP): the caller's real_dlopen(root, ...|RTLD_GLOBAL)
 * maps root + libenccons + libplainprov before running any ctor, so
 * plain_impl() resolves and returns 99.
 */

#include <stdio.h>

extern int plain_impl(void);

static int g_v = -1;

__attribute__((constructor))
static void enc_ctor(void)
{
    g_v = plain_impl();
    fprintf(stderr, "[enccons] ctor g_v=%d\n", g_v);
}

__attribute__((visibility("default")))
int enccons_get(void) { return g_v; }

/* Pins libenccons as a DT_NEEDED of libencroot under --no-as-needed. */
__attribute__((visibility("default")))
int libenccons_marker = 1;
