/*
 * libdup2 — identical pattern to libdup1.  Defines its own copy of
 * `interpose_already_ran` and its own `libdup2_init` constructor
 * that checks the flag and calls interpose_register("foo").
 *
 * Under a working RTLD_GLOBAL preload the flag is interposed to
 * libdup1's already-set copy and the body short-circuits.  Under
 * an RTLD_LOCAL preload libdup2's local flag is still 0 and the
 * ctor re-registers "foo" — at which point libregistrar aborts.
 */

extern void interpose_register(const char *name);

int interpose_already_ran = 0;

int libdup2_marker = 2;

__attribute__((constructor))
static void libdup2_init(void)
{
    if (interpose_already_ran) {
        return;
    }
    interpose_already_ran = 1;
    interpose_register("foo");
}
