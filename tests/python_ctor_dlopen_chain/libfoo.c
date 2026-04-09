/*
 * libfoo.so — top-level library, dlopen'd by Python.
 *
 * Constructor dlopens libbar.so (which DT_NEEDs libzzz.so).
 */

#include <dlfcn.h>
#include <stdio.h>

static int (*bar_fn)(void);

__attribute__((constructor))
static void foo_init(void)
{
    void *h = dlopen("libbar.so", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "foo_init: dlopen libbar.so failed: %s\n", dlerror());
        return;
    }
    bar_fn = (int (*)(void))dlsym(h, "bar_compute");
    if (!bar_fn)
        fprintf(stderr, "foo_init: dlsym bar_compute failed: %s\n", dlerror());
}

int foo_result(void)
{
    return bar_fn ? bar_fn() * 3 : -1;  /* 426 */
}
