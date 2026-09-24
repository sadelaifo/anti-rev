/*
 * test_dlopen_reload — verify that plugin libs come and go properly
 * across dlopen / dlclose cycles under the lazy-fetch daemon path.
 *
 * Business software (Foo's GUI plugin loader, libprotobuf-generated
 * plugins, etc.) often loads one plugin, drops it with dlclose,
 * then loads the next.  If two plugins carry overlapping static
 * state — the classic libprotobuf descriptor_pool "File already
 * exists in database: xxx.proto" case — keeping the first plugin
 * pinned in the address space when the second loads is a hard
 * error.  This test catches that case by counting constructor runs
 * across two dlopen cycles: the constructor must fire twice.
 *
 * How it fails without the fix: if dlopen_shim's fetch_closure
 * preloads the root lib, there are two refs to libreload.so after
 * the first dlopen (one from preload, one from the caller).  dlclose
 * drops only one, the constructor never re-fires, and the log ends
 * up with a single "ctor" line instead of two.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

static const char *LOG_PATH = "/tmp/test_dlopen_reload.log";

static int count_lines(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int count = 0;
    char buf[64];
    while (fgets(buf, sizeof(buf), f)) {
        if (strncmp(buf, needle, strlen(needle)) == 0)
            count++;
    }
    fclose(f);
    return count;
}

static int load_and_drop(int round)
{
    void *h = dlopen("libreload.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "FAIL [round %d]: dlopen: %s\n", round, dlerror());
        return -1;
    }
    int *sym = (int *)dlsym(h, "libreload_symbol");
    if (!sym || *sym != 42) {
        fprintf(stderr, "FAIL [round %d]: dlsym libreload_symbol\n", round);
        dlclose(h);
        return -1;
    }
    if (dlclose(h) != 0) {
        fprintf(stderr, "FAIL [round %d]: dlclose: %s\n", round, dlerror());
        return -1;
    }
    return 0;
}

int main(void)
{
    setenv("LIBRELOAD_LOG", LOG_PATH, 1);
    unlink(LOG_PATH);  /* fresh log per run */

    if (load_and_drop(1) != 0) return 1;
    if (load_and_drop(2) != 0) return 1;

    int ctors = count_lines(LOG_PATH, "ctor");
    int dtors = count_lines(LOG_PATH, "dtor");
    printf("[reload] log shows %d ctor / %d dtor lines\n", ctors, dtors);

    if (ctors < 2) {
        fprintf(stderr,
                "FAIL: expected >= 2 ctor lines (one per dlopen round), got %d.\n"
                "  dlopen_shim appears to be pinning the root lib's refcount,\n"
                "  so dlclose never unloaded it and the second dlopen was a\n"
                "  no-op refcount bump instead of a real reload.\n",
                ctors);
        return 1;
    }

    printf("PASS: dlopen_reload\n");
    return 0;
}
