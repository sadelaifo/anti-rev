/*
 * Encrypted library — DT_NEEDs libbar.so (also encrypted).
 * Loaded at runtime via dlopen() from the encrypted exe.
 *
 * Topology:
 *   exe (encrypted) --dlopen--> libfoo.so (this) --DT_NEEDED--> libbar.so
 *
 * The linker must resolve the DT_NEEDED for libbar.so from a decrypted
 * memfd, not the encrypted file on disk.
 */

extern int bar_value(void);

int foo_combined(void)
{
    /* Return a value that proves both libfoo and libbar loaded correctly.
     * foo's own contribution (100) + bar's value (77) = 177.  */
    return 100 + bar_value();
}
