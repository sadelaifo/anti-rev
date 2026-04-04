/*
 * libbar.so — unencrypted intermediary library.
 *
 * DT_NEEDED: libtee.so (encrypted).
 * Provides bar_compute(), called by libfoo.so.
 */

extern int tee_value(void);

int bar_compute(void)
{
    return tee_value() + 1;  /* 778 */
}
