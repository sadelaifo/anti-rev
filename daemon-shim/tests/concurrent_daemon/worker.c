/* Worker binary — linked against libshared.so (DT_NEEDED).
 * Multiple instances launched concurrently to stress the daemon. */

#include <stdio.h>
#include <unistd.h>

extern int shared_getpid(void);
extern int shared_add(int, int);

int main(void)
{
    int pid = shared_getpid();
    int actual = (int)getpid();
    if (pid != actual) {
        fprintf(stderr, "FAIL: pid mismatch %d != %d\n", pid, actual);
        return 1;
    }

    int sum = shared_add(100, 200);
    if (sum != 300) {
        fprintf(stderr, "FAIL: shared_add %d != 300\n", sum);
        return 1;
    }

    printf("PASS: worker pid=%d\n", pid);
    return 0;
}
