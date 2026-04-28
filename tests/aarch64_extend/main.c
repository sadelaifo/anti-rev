/* aarch64_extend_shim end-to-end test driver.  aarch64-only.
 *
 * Exercises the two interceptors hosted in aarch64_extend_shim.c:
 *
 *   1. ANTI_LoadProcess hijack: the shim must rewrite info->ltrBin from
 *      the on-disk path to "/proc/self/fd/N" using the fd map seeded via
 *      ANTIREV_FD_MAP.  We provide our own "real" ANTI_LoadProcess in
 *      libreal_anti.so so dlsym(RTLD_NEXT, "ANTI_LoadProcess") inside
 *      the shim resolves to it; libreal_anti's implementation just asserts
 *      the rewritten path looks right and reads the fd's contents.
 *
 *   2. popen / pclose: with the shim active and owner detection succeeding
 *      (ANTIREV_MAIN_FD set in the env), popen("echo …", "r") must work
 *      end-to-end and pclose must reap the right child.
 *
 * Returns 0 on success, non-zero with a diagnostic on failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward decl matching the shim's struct layout (offset 0 = pgName,
 * offset 8 = ltrBin).  The "real" ANTI_LoadProcess in libreal_anti.so
 * uses the same layout. */
struct ANTI_ProcessInfo {
    const char *pgName;
    const char *ltrBin;
    /* remainder unused for the test */
};

/* Provided by libreal_anti.so — gets called via dlsym(RTLD_NEXT) inside
 * the shim.  Returns 0 if info->ltrBin matches "/proc/self/fd/<digits>"
 * and the fd's contents start with "PG_BLOB_OK".  Non-zero on mismatch. */
extern int ANTI_LoadProcess(struct ANTI_ProcessInfo *info);

static int test_anti_loadprocess(void)
{
    struct ANTI_ProcessInfo info = {
        .pgName = "fake_pg",
        .ltrBin = "/some/disk/path/fake.elf",  /* what the shim should rewrite */
    };
    int rc = ANTI_LoadProcess((void *)&info);
    if (rc != 0) {
        fprintf(stderr, "[test] ANTI_LoadProcess returned %d (real impl rejected "
                        "rewritten path or content)\n", rc);
        return 1;
    }
    /* The shim's rewrite is persistent — info->ltrBin must now point at
     * /proc/self/fd/<N>, not the original disk path. */
    if (strncmp(info.ltrBin, "/proc/self/fd/", 14) != 0) {
        fprintf(stderr, "[test] ltrBin not rewritten, still '%s'\n", info.ltrBin);
        return 1;
    }
    fprintf(stderr, "[test] ANTI_LoadProcess hijack OK -> %s\n", info.ltrBin);
    return 0;
}

static int test_popen(void)
{
    FILE *fp = popen("echo aarch64_popen_ok", "r");
    if (!fp) {
        fprintf(stderr, "[test] popen returned NULL\n");
        return 1;
    }
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), fp)) {
        fprintf(stderr, "[test] fgets from popen failed\n");
        pclose(fp);
        return 1;
    }
    int rc = pclose(fp);
    if (rc != 0) {
        fprintf(stderr, "[test] pclose returned %d (expected 0)\n", rc);
        return 1;
    }
    /* fgets keeps the trailing newline */
    if (strcmp(buf, "aarch64_popen_ok\n") != 0) {
        fprintf(stderr, "[test] unexpected popen output: '%s'\n", buf);
        return 1;
    }
    fprintf(stderr, "[test] popen/pclose relocation OK\n");
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_anti_loadprocess();
    fails += test_popen();
    if (fails) {
        fprintf(stderr, "[test] %d sub-test(s) failed\n", fails);
        return 1;
    }
    fprintf(stderr, "[test] all aarch64_extend_shim sub-tests passed\n");
    return 0;
}
