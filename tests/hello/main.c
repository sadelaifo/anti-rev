#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    printf("hello from protected binary! argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("  argv[%d] = %s\n", i, argv[i]);
    const char *key = getenv("ANTIREV_KEY");
    printf("ANTIREV_KEY present: %s\n", key ? "yes" : "no");
    return 42;  /* distinct exit code so we can verify it passes through */
}
