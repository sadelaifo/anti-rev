/*
 * Inner library for nested dlopen test.
 * Loaded at runtime by libcaller.so via dlopen("libcallee.so").
 * No dependencies on other encrypted libs.
 */

int callee_value(void)
{
    return 42;
}

int callee_add(int a, int b)
{
    return a + b;
}
