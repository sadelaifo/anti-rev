/* libtwo.so — the other lib exporting the same strong symbol `who`. */
const char *who(void)
{
    return "two";
}
