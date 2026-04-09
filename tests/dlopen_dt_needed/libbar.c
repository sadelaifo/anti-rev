/*
 * Encrypted leaf library — provides bar_value().
 * DT_NEEDED by libfoo.so (also encrypted).
 *
 * Topology under test:
 *   exe (encrypted)
 *     |
 *   dlopen()
 *     v
 *   libfoo.so (encrypted)
 *     |
 *   DT_NEEDED
 *     v
 *   libbar.so (encrypted, this file)
 *
 * This is the critical link: when the dynamic linker loads libfoo.so
 * from a memfd, it must also find libbar.so's decrypted memfd — not
 * the encrypted copy on disk.  Without LD_LIBRARY_PATH pointing to
 * soname->memfd symlinks, this resolution fails.
 */

int bar_value(void)
{
    return 77;
}
