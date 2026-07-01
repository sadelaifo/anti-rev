/*
 * test_parse.c — unit test for ksv_parse() (stub/keysplit_version.h), the
 * runtime version-field extraction used in the keysplit key derivation.
 *
 * Verifies the parse rule matches the Python mirrors
 * (protect.parse_version_field / antirev_client._parse_version_field) and the
 * value the packer feeds from config.yaml `version:`.  No daemon, no root.
 */
#include "keysplit_version.h"

#include <stdio.h>
#include <string.h>

/* Run ksv_parse over a NUL-terminated input string.  When `expect` is NULL we
 * assert failure (marker absent / empty field); otherwise the produced field
 * must equal `expect` exactly. */
static int check(const char *in, const char *expect) {
    uint8_t out[256];
    size_t  n = 0;
    int r = ksv_parse((const uint8_t *)in, strlen(in),
                      "Version: ", "SPC", out, sizeof(out), &n);
    if (expect == NULL)
        return r != 0;                 /* expected to fail */
    if (r != 0)
        return 0;
    return n == strlen(expect) && memcmp(out, expect, n) == 0;
}

int main(void) {
    struct { const char *in; const char *out; } cases[] = {
        /* Huawei-style contiguous SPC */
        { "Version: V100R001C00SPC010\n",              "V100R001C00" },
        /* marker mid-stream, space-separated SPC, trailing junk dropped */
        { "prod\nVersion: 1.2.3 SPC b05 foo\nother\n", "1.2.3" },
        /* no SPC -> whole line (stripped) */
        { "Version: 1.2.3 build 2024\n",               "1.2.3 build 2024" },
        /* extra whitespace around the value */
        { "Version:    V1   \n",                       "V1" },
        /* no trailing newline (marker line is EOF) */
        { "Version: V100R001C00SPC010",                "V100R001C00" },
        /* marker absent -> fail */
        { "no version marker here\n",                  NULL },
        /* value is entirely SPC... -> empty after cut -> fail */
        { "Version: SPC123\n",                         NULL },
        /* value only whitespace -> empty -> fail */
        { "Version:    \n",                            NULL },
    };

    int failed = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!check(cases[i].in, cases[i].out)) {
            printf("FAIL case %zu: in=%s\n", i, cases[i].in);
            failed = 1;
        }
    }

    if (failed) {
        printf("keysplit_version: FAIL\n");
        return 1;
    }
    printf("keysplit_version: PASS (%zu cases)\n",
           sizeof(cases) / sizeof(cases[0]));
    return 0;
}
