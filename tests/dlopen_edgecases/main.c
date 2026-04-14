/*
 * Edge-case tests for the antirev dlopen shim / LD_PRELOAD interception.
 *
 * Exercises code paths beyond the basic "bare name" dlopen:
 *   1. dlopen(NULL)             — main program handle, must not crash
 *   2. dlclose + reopen         — re-dlopen after close still works
 *   3. Double dlopen            — same lib opened twice, both handles valid
 *   4. Unmapped fallthrough     — unknown lib falls through to real dlopen
 *   5. RTLD_LAZY                — lazy binding works with dlopen_shim
 *
 * Note: RTLD_NOLOAD and dlsym(RTLD_DEFAULT, ...) cases were removed with
 * the symlink-dir-only architecture shift.  Under the current design libs
 * are loaded on-demand via dlopen_shim with RTLD_LOCAL, so they are not
 * present in RTLD_DEFAULT after dlclose and RTLD_NOLOAD's "already loaded"
 * semantics depend on link-map dedup by filename, which /proc/self/fd/N
 * paths break.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, fmt, ...) do {                                  \
    checks++;                                                       \
    if (!(cond)) {                                                  \
        fprintf(stderr, "FAIL [%d]: " fmt "\n", checks,            \
                ##__VA_ARGS__);                                     \
        failures++;                                                 \
    }                                                               \
} while (0)

int main(void)
{
    /* 1. dlopen(NULL) — returns handle to main program, must not crash */
    {
        void *h = dlopen(NULL, RTLD_NOW);
        CHECK(h != NULL, "dlopen(NULL) returned NULL: %s", dlerror());
        if (h) dlclose(h);
    }

    /* 2. dlclose + reopen — lib stays available via LD_PRELOAD/memfd */
    {
        void *h1 = dlopen("mylib.so", RTLD_NOW);
        CHECK(h1 != NULL,
              "dlopen(mylib.so) first open: %s", dlerror());
        if (h1) {
            dlclose(h1);
            void *h2 = dlopen("mylib.so", RTLD_NOW);
            CHECK(h2 != NULL,
                  "dlopen(mylib.so) reopen after close: %s", dlerror());
            if (h2) {
                int (*add_fn)(int, int) = dlsym(h2, "add");
                CHECK(add_fn && add_fn(1, 1) == 2,
                      "add(1,1) after reopen failed");
                dlclose(h2);
            }
        }
    }

    /* 3. Double dlopen — same lib opened twice without closing */
    {
        void *h1 = dlopen("mylib.so", RTLD_NOW);
        void *h2 = dlopen("mylib.so", RTLD_NOW);
        CHECK(h1 != NULL, "double-open first: %s", dlerror());
        CHECK(h2 != NULL, "double-open second: %s", dlerror());
        if (h1 && h2) {
            int (*fn1)(int, int) = dlsym(h1, "add");
            int (*fn2)(int, int) = dlsym(h2, "add");
            CHECK(fn1 && fn2, "dlsym(add) on double-open handles");
            if (fn1 && fn2) {
                CHECK(fn1(2, 3) == 5,
                      "add(2,3) via h1 = %d", fn1(2, 3));
                CHECK(fn2(4, 5) == 9,
                      "add(4,5) via h2 = %d", fn2(4, 5));
            }
        }
        if (h2) dlclose(h2);
        if (h1) dlclose(h1);
    }

    /* 4. Unmapped library — must fall through to real dlopen and fail */
    {
        void *h = dlopen("libnonexistent_antirev_test_ZZZZ.so", RTLD_NOW);
        CHECK(h == NULL,
              "dlopen(nonexistent) should return NULL but got a handle");
        if (h) dlclose(h);
        if (!h) {
            const char *err = dlerror();
            CHECK(err != NULL,
                  "dlerror() returned NULL after failed fallthrough dlopen");
        }
    }

    /* 5. RTLD_LAZY — lazy binding should work */
    {
        void *h = dlopen("mylib.so", RTLD_LAZY);
        CHECK(h != NULL,
              "dlopen(mylib.so, RTLD_LAZY) returned NULL: %s", dlerror());
        if (h) {
            const char *(*greet)(void) = dlsym(h, "greeting");
            CHECK(greet != NULL,
                  "dlsym(greeting) with RTLD_LAZY: %s", dlerror());
            if (greet) {
                const char *msg = greet();
                CHECK(msg && msg[0] != '\0',
                      "greeting() returned empty/null with RTLD_LAZY");
            }
            dlclose(h);
        }
    }

    if (failures == 0)
        printf("PASS: dlopen_edgecases (%d checks passed)\n", checks);
    else
        printf("FAIL: dlopen_edgecases (%d/%d failed)\n",
               failures, checks);

    return failures ? 1 : 0;
}
