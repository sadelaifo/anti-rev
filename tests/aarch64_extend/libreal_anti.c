/* "Real" ANTI_LoadProcess for the aarch64_extend test.  Loaded via
 * DT_NEEDED so dlsym(RTLD_NEXT, "ANTI_LoadProcess") inside the
 * LD_PRELOAD'd shim resolves here.
 *
 * This stand-in just verifies the shim has done its job: info->ltrBin
 * must already be a "/proc/self/fd/<N>" path, and reading from that fd
 * must return content starting with the "PG_BLOB_OK" sentinel that
 * run_test.sh wrote into the memfd.
 *
 * Returns 0 on a passing rewrite, non-zero with a stderr message on
 * mismatch.  The driver in main.c also re-checks info->ltrBin after we
 * return to make sure the rewrite is persistent across the call. */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct ANTI_ProcessInfo {
    const char *pgName;
    const char *ltrBin;
};

__attribute__((visibility("default")))
int ANTI_LoadProcess(struct ANTI_ProcessInfo *info)
{
    if (!info || !info->ltrBin) {
        fprintf(stderr, "[real_anti] info or ltrBin null\n");
        return 1;
    }
    if (strncmp(info->ltrBin, "/proc/self/fd/", 14) != 0) {
        fprintf(stderr, "[real_anti] ltrBin not rewritten: '%s'\n", info->ltrBin);
        return 2;
    }
    /* Open the rewritten path and check the sentinel. */
    int fd = open(info->ltrBin, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[real_anti] open('%s') failed\n", info->ltrBin);
        return 3;
    }
    char buf[16] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 9 || strncmp(buf, "PG_BLOB_OK", 10) != 0) {
        fprintf(stderr, "[real_anti] sentinel mismatch: read %zd bytes '%s'\n", n, buf);
        return 4;
    }
    return 0;
}
