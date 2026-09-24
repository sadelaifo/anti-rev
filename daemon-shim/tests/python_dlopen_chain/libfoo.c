/*
 * libfoo.so — encrypted top-level library, dlopen'd by Python.
 *
 * DT_NEEDED: libbar.so (unencrypted).
 *
 * Topology:
 *   Python ──dlopen──→ libfoo.so (encrypted)
 *                           │
 *                       DT_NEEDED
 *                           ↓
 *                       libbar.so  (unencrypted)
 *                           │
 *                       DT_NEEDED
 *                           ↓
 *                       libtee.so  (encrypted)
 */

extern int bar_compute(void);

int foo_result(void)
{
    return bar_compute() * 2;  /* 1556 */
}
