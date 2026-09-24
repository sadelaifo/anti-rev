/*
 * libzzz.so — leaf library.
 * Provides zzz_value(), linked by libbar.so via DT_NEEDED.
 */

int zzz_value(void)
{
    return 42;
}
