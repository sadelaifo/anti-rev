/*
 * Edge-case tests for the antirev dlopen shim / LD_PRELOAD interception.
 *
 * Exercises code paths beyond the basic "bare name" dlopen:
 *   1. dlopen(NULL)             — main program handle, must not crash
 *   2. dlclose + reopen         — re-dlopen after close still works
 *   3. Double dlopen            — same lib opened twice, both handles valid
 *   4. Unmapped fallthrough     — unknown lib falls through to real dlopen
 *   5. RTLD_LAZY                — lazy binding works with preloaded libs
 *   6. RTLD_NOLOAD              — query already-loaded lib without loading
 *   7. dlsym(RTLD_DEFAULT)      — find symbol across all loaded libs
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

    /* 6. RTLD_NOLOAD — query without loading; lib already preloaded */
    {
        /* mylib.so is preloaded via LD_PRELOAD, so RTLD_NOLOAD should find it */
        void *h = dlopen("mylib.so", RTLD_NOW | RTLD_NOLOAD);
        CHECK(h != NULL,
              "dlopen(mylib.so, RTLD_NOLOAD) returned NULL: %s", dlerror());
        if (h) {
            int (*add_fn)(int, int) = dlsym(h, "add");
            CHECK(add_fn != NULL, "dlsym(add) via RTLD_NOLOAD: %s", dlerror());
            if (add_fn) {
                CHECK(add_fn(100, 200) == 300,
                      "add(100,200) via RTLD_NOLOAD = %d", add_fn(100, 200));
            }
            dlclose(h);
        }
    }

    /* 7. dlsym(RTLD_DEFAULT) — find symbol from preloaded lib */
    {
        int (*add_fn)(int, int) = dlsym(RTLD_DEFAULT, "add");
        CHECK(add_fn != NULL,
              "dlsym(RTLD_DEFAULT, add) returned NULL: %s", dlerror());
        if (add_fn) {
            CHECK(add_fn(7, 8) == 15,
                  "add(7,8) via RTLD_DEFAULT = %d", add_fn(7, 8));
        }
    }

    if (failures == 0)
        printf("PASS: dlopen_edgecases (%d checks passed)\n", checks);
    else
        printf("FAIL: dlopen_edgecases (%d/%d failed)\n",
               failures, checks);

    return failures ? 1 : 0;
}
