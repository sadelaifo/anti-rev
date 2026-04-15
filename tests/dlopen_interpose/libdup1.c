/*
 * libdup1 — one of two plugin helpers that each carry a copy of the
 * "descriptor for foo" registration code, mirroring the real-world
 * case where two business libs each statically link the same
 * generated .pb.cc object file.
 *
 * The `interpose_already_ran` flag is exported with default
 * visibility so it behaves the same way libprotobuf's
 * `descriptor_table_foo_2eproto` (or its `once_flag` sub-object)
 * behaves: under RTLD_GLOBAL the first-loaded DSO's copy interposes
 * every subsequent reference, so libdup2's ctor will read the
 * already-set flag and skip re-registration.  Under RTLD_LOCAL each
 * DSO has its own copy, both flags start at 0, and both ctors call
 * interpose_register("foo") — the second one aborts.
 */

extern void interpose_register(const char *name);

/* Exported, default visibility — subject to symbol interposition. */
int interpose_already_ran = 0;

/* Distinct marker so libroot can reference it and the linker has to
 * keep libdup1 in libroot's DT_NEEDED set. */
int libdup1_marker = 1;

__attribute__((constructor))
static void libdup1_init(void)
{
    if (interpose_already_ran) {
        return;
    }
    interpose_already_ran = 1;
    interpose_register("foo");
}
