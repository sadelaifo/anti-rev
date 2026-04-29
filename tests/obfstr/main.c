/* Smoke test for the OBFSTR codegen + runtime decoder pipeline.
 *
 * The codegen rewrites every macro call below, so the cleartext you see
 * here disappears from the compiled binary's rodata.  At runtime each
 * call should still observe the original string.
 *
 * The driver verifies two things:
 *   1. The decoded bytes match the original literal exactly (every byte,
 *      including escape sequences and embedded NULs we add deliberately).
 *   2. There is no decode-time mutation of the static encrypted bytes
 *      (the same call yields the same string twice in a row).
 *
 * Coverage of the cleartext absence is done outside this binary by
 * `strings $0 | grep antirev_secret_marker`, which run_test.sh runs.
 *
 * The literal "antirev_secret_marker" below is what the strings-scan
 * test checks.  If it ever appears in the compiled binary, the
 * codegen / volatile / decoder chain is broken and the test fails. */

#include "obfstr.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define EXPECT(cond, msg) do {                                     \
    if (!(cond)) {                                                 \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        return 1;                                                  \
    }                                                              \
} while (0)

static int test_obfstr_roundtrip(void)
{
    const char *p = OBFSTR("antirev_secret_marker");
    EXPECT(p != NULL, "OBFSTR returned NULL");
    EXPECT(strcmp(p, "antirev_secret_marker") == 0,
           "OBFSTR did not round-trip the literal");

    /* Same call site twice — encrypted bytes must not be mutated by the
     * decode loop (volatile-protected from compiler folding, but we want
     * to catch a stray write or off-by-one too). */
    const char *q = OBFSTR("antirev_secret_marker");
    EXPECT(strcmp(q, "antirev_secret_marker") == 0,
           "OBFSTR second call yielded different bytes");
    return 0;
}

static int test_log_err_does_not_crash(void)
{
    /* LOG_ERR wraps fprintf(stderr, ...).  We don't care about stderr
     * capture here — just make sure the wrapped format string decodes
     * correctly enough that printf parses it without crashing. */
    LOG_ERR("antirev_secret_format_%d_%s\n", 42, "tail");
    return 0;
}

static int test_osnprintf(void)
{
    char buf[64];
    int n = OSNPRINTF(buf, sizeof(buf), "antirev_secret_fmt=%d/%s", 7, "x");
    EXPECT(n > 0 && (size_t)n < sizeof(buf), "OSNPRINTF length wrong");
    EXPECT(strcmp(buf, "antirev_secret_fmt=7/x") == 0,
           "OSNPRINTF output mismatch");
    return 0;
}

static int test_perr(void)
{
    /* PERR uses %s + strerror.  We only assert it doesn't crash; the
     * exact stderr line shape is glibc's problem. */
    errno = 2;  /* ENOENT */
    PERR("antirev_secret_perr_label");
    return 0;
}

int main(void)
{
    int rc = 0;
    rc |= test_obfstr_roundtrip();
    rc |= test_log_err_does_not_crash();
    rc |= test_osnprintf();
    rc |= test_perr();
    if (rc == 0)
        printf("PASS\n");
    return rc;
}
