/*
 * proc_self_exe test — verifies that readlink("/proc/self/exe") returns the
 * real on-disk binary path, not "/memfd:... (deleted)", after the antirev
 * stub launches this binary via fexecve().
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len < 0) { perror("readlink /proc/self/exe"); return 1; }
    buf[len] = '\0';

    printf("/proc/self/exe = %s\n", buf);

    if (strstr(buf, "memfd") != NULL) {
        fprintf(stderr, "FAIL: path contains 'memfd': %s\n", buf);
        return 1;
    }
    if (strstr(buf, "(deleted)") != NULL) {
        fprintf(stderr, "FAIL: path contains '(deleted)': %s\n", buf);
        return 1;
    }

    printf("PASS: /proc/self/exe returned real path\n");
    return 0;
}
