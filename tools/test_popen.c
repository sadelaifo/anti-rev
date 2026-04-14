/*
 * Test popen behavior under anti-rev environment.
 * Compile: gcc -o test_popen test_popen.c
 * Or cross: aarch64-linux-gnu-gcc -static -o test_popen test_popen.c
 *
 * Usage: ./test_popen
 *        LD_PRELOAD=/proc/self/fd/3 ./test_popen   (simulate anti-rev env)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_popen(const char *cmd)
{
    char buf[256];
    memset(buf, 0, sizeof(buf));

    fprintf(stderr, "[test] popen(\"%s\")...\n", cmd);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "[test] FAIL: popen returned NULL\n");
        return 1;
    }

    char *ret = fgets(buf, sizeof(buf), fp);
    int status = pclose(fp);

    if (!ret) {
        fprintf(stderr, "[test] FAIL: fgets returned NULL (pipe empty or error)\n");
        fprintf(stderr, "[test] pclose status: %d\n", status);
        return 1;
    }

    /* Remove trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

    fprintf(stderr, "[test] OK: buf=[%s] pclose_status=%d\n", buf, status);
    return 0;
}

int main(void)
{
    fprintf(stderr, "\n=== popen test under anti-rev ===\n");

    /* Show relevant env */
    const char *preload = getenv("LD_PRELOAD");
    const char *fdmap = getenv("ANTIREV_FD_MAP");
    const char *realexe = getenv("ANTIREV_REAL_EXE");
    fprintf(stderr, "LD_PRELOAD:       %s\n", preload ? preload : "(not set)");
    fprintf(stderr, "ANTIREV_FD_MAP:   %s\n", fdmap ? fdmap : "(not set)");
    fprintf(stderr, "ANTIREV_REAL_EXE: %s\n", realexe ? realexe : "(not set)");
    fprintf(stderr, "\n");

    int fail = 0;
    fail += test_popen("echo hello");
    fail += test_popen("date +%z");
    fail += test_popen("date '+%Y-%m-%d %H:%M:%S'");
    fail += test_popen("/bin/sh -c 'echo popen_works'");

    fprintf(stderr, "\n=== Result: %d/%d passed ===\n", 4 - fail, 4);
    return fail;
}
