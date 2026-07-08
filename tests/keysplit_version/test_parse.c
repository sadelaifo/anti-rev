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
                      "Version: DY", "SPC", out, sizeof(out), &n);
    if (expect == NULL)
        return r != 0;                 /* expected to fail */
    if (r != 0)
        return 0;
    return n == strlen(expect) && memcmp(out, expect, n) == 0;
}

int main(void) {
    struct { const char *in; const char *out; } cases[] = {
        /* ── dotted (test) format: everything after the first '.' ── */
        { "Version: V1.2.3.4\n",                       "2.3.4" },
        { "Version: DYV300R001.B011\n",                "B011" },
        /* dot anywhere in stdout wins; marker/SPC ignored */
        { "anything.HELLO WORLD\n",                    "HELLO WORLD" },
        /* after-dot then stripped (trailing newline removed) */
        { "x.abc  \n",                                 "abc" },

        /* ── DY (formal) format: after "Version: DY", before "SPC" ── */
        { "Version: DYV100R001C00SPC010\n",            "V100R001C00" },
        { "Version: DY V100R001 SPC010\n",             "V100R001" },
        /* no SPC -> whole line after DY (stripped) */
        { "Version: DYV100R001C00\n",                  "V100R001C00" },
        /* no trailing newline (marker line is EOF) */
        { "Version: DYV100R001C00SPC010",              "V100R001C00" },

        /* ── failures ── */
        /* no '.' and no DY marker -> fail */
        { "no marker here\n",                          NULL },
        /* dotted but empty after the dot -> fail */
        { "abc.\n",                                    NULL },
        /* DY value entirely SPC... -> empty after cut -> fail */
        { "Version: DYSPC123\n",                       NULL },
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
