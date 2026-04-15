/*
 * libroot — the "plugin" the test exe dlopens.  It DT_NEEDEDs both
 * libdup1 and libdup2, so when dlopen_shim's fetch_closure walks
 * libroot's dependency graph it pulls both dup libraries into the
 * same closure and pre-loads them back-to-back.  That's the exact
 * layout the real GUI crash had: one dlopen() call whose transitive
 * dep set contains two libs with overlapping static state.
 */

/* Force the linker to keep libdup1 and libdup2 as DT_NEEDED deps
 * by referencing a distinct symbol from each.  Without this, the
 * linker's default --as-needed drops the second lib because the
 * shared `interpose_already_ran` name only needs one definition. */
extern int libdup1_marker;
extern int libdup2_marker;
extern int interpose_already_ran;  /* interposed across dup1/dup2 */

__attribute__((visibility("default")))
int libroot_touch(void)
{
    /* Touch all three symbols so:
     *   - libdup1_marker keeps libdup1 in DT_NEEDED
     *   - libdup2_marker keeps libdup2 in DT_NEEDED
     *   - interpose_already_ran is what the test actually checks */
    return libdup1_marker + libdup2_marker + interpose_already_ran;
}
