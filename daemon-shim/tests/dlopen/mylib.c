/*
 * Test shared library for the dlopen test.
 * Compiled as mylib.so and loaded at runtime via dlopen("mylib.so").
 */
#include "mylib.h"

int add(int a, int b)
{
    return a + b;
}

const char *greeting(void)
{
    return "hello from protected mylib.so";
}
