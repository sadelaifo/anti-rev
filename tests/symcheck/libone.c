/* libone.so — one of two libs that both export a strong symbol `who`. */
const char *who(void)
{
    return "one";
}
