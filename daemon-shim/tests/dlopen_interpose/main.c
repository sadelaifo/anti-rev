/*
 * test_dlopen_interpose — regression test for the symbol-interposition
 * dedup rule in dlopen_shim::fetch_closure.
 *
 * Scenario: dlopen(libroot.so), which DT_NEEDs libdup1.so and
 * libdup2.so, both of which independently contain a ctor that
 * registers the name "foo" with libregistrar.  libdup1 and libdup2
 * each carry their own copy of a `once`-style guard flag with default
 * visibility, mirroring how generated .pb.cc code exports the
 * `descriptor_table_<file>_2eproto` symbol used by libprotobuf to
 * avoid re-registration.
 *
 * Expected behavior:
 *   - dlopen_shim preloads libdup1 / libdup2 (skipping the root) with
 *     RTLD_LAZY | RTLD_GLOBAL, which places both DSOs in the global
 *     symbol scope.  The first-loaded DSO's `interpose_already_ran`
 *     copy interposes the second DSO's reference, the second ctor
 *     reads the already-set flag and short-circuits, and the
 *     registrar is called exactly once.
 *   - Without RTLD_GLOBAL in the preload (regression: plain RTLD_LAZY
 *     which defaults to RTLD_LOCAL), each DSO has its own `_already_ran`
 *     copy at 0, both ctors run, and the registrar aborts on the second
 *     call.  The test exits with SIGABRT and prints a diagnostic
 *     naming the bug.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(void)
{
    void *h = dlopen("libroot.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "FAIL: dlopen(libroot.so): %s\n", dlerror());
        return 1;
    }

    int (*touch)(void) = (int (*)(void))dlsym(h, "libroot_touch");
    if (!touch) {
        fprintf(stderr, "FAIL: dlsym(libroot_touch): %s\n", dlerror());
        dlclose(h);
        return 1;
    }

    int sum = touch();
    /* touch() returns libdup1_marker + libdup2_marker + interpose_already_ran
     * = 1 + 2 + 1 = 4 when everything is loaded and the interposed flag
     * was set once (by whichever dup ran first). */
    if (sum != 4) {
        fprintf(stderr, "FAIL: libroot_touch=%d, expected 4\n", sum);
        dlclose(h);
        return 1;
    }

    dlclose(h);
    printf("PASS: dlopen_interpose (single registration under RTLD_GLOBAL)\n");
    return 0;
}
