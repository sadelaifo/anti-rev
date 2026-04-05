/*
 * libbar.so — middle library, DT_NEEDED on libzzz.so.
 * dlopen'd by libfoo.so's constructor.
 */

extern int zzz_value(void);

int bar_compute(void)
{
    return zzz_value() + 100;  /* 142 */
}
