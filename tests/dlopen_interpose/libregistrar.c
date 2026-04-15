/*
 * Central "registrar" library — plays the role libprotobuf's
 * DescriptorPool does for .pb.cc-generated code.  It tracks which
 * descriptor names have been registered and aborts on duplicates,
 * the same way libprotobuf's GOOGLE_LOG(FATAL) path behaves.
 *
 * The libdup1 / libdup2 ctors each call interpose_register("foo")
 * through a per-DSO `once_flag`-style guard.  If the guards are in
 * the global symbol scope (RTLD_GLOBAL preload), only one call ever
 * reaches interpose_register and the test passes.  If they're in
 * per-DSO local scopes (plain RTLD_LAZY), both calls arrive and the
 * second one aborts — matching the libprotobuf "File already exists
 * in database" failure mode.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAMES 64

static const char *g_registered[MAX_NAMES];
static int g_count = 0;

__attribute__((visibility("default")))
void interpose_register(const char *name)
{
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_registered[i], name) == 0) {
            fprintf(stderr,
                    "[interpose FATAL] %s already registered — the "
                    "preload did NOT put the guarding symbol into the "
                    "global scope, so both DSOs' ctors ran\n", name);
            abort();
        }
    }
    if (g_count < MAX_NAMES) {
        g_registered[g_count++] = name;
    }
    fprintf(stderr, "[interpose] registered %s (total=%d)\n",
            name, g_count);
}
