/*
 * test_env_no_preload — proves two things at once:
 *
 *   1. The stub honors an *inherited* __r_NP=1 from the launch
 *      environment (the exe is NOT in exe_is_no_preload_blacklisted),
 *      so natural-load can be enabled suite-wide via one env var.
 *   2. Natural load resolves a Class-3 implicit dep (encrypted
 *      libenccons -> plaintext libplainprov, no DT_NEEDED edge) that
 *      no daemon-side closure heuristic can infer (the provider is a
 *      plaintext lib outside the encrypted set).
 *
 * Run with __r_NP=1 in the environment:
 *   - stub honors it -> natural load -> libplainprov mapped before any
 *     ctor -> encroot_get() == 99 -> exit 0.
 *   - Without the stub change the inherited __r_NP is scrubbed, the
 *     exe falls onto the default preload path, libenccons is preloaded
 *     in isolation, its ctor calls the still-unresolved plain_impl(),
 *     and the process aborts with a symbol lookup error (nonzero exit).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
    void *h = dlopen("libencroot.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "FAIL: dlopen(libencroot.so): %s\n", dlerror());
        return 1;
    }

    int (*f)(void) = (int (*)(void)) dlsym(h, "encroot_get");
    if (!f) {
        fprintf(stderr, "FAIL: dlsym(encroot_get): %s\n", dlerror());
        dlclose(h);
        return 1;
    }

    int v = f();
    if (v != 99) {
        fprintf(stderr, "FAIL: encroot_get()=%d, expected 99\n", v);
        dlclose(h);
        return 1;
    }

    dlclose(h);
    printf("PASS: env_no_preload (inherited __r_NP=1 honored; natural "
           "load resolved the plaintext-provider implicit dep)\n");
    return 0;
}
