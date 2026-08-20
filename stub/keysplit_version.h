/*
 * keysplit_version.h — extract the "version" component of the key-split key
 * from the version script's raw stdout.
 *
 * The keysplit real key is SHA256( part1 || SHA256(lrxd) || version_field ).
 * version_field is parsed from the stdout produced by EXECUTING
 * $HOME/SW/version with this rule (MUST stay byte-for-byte identical to the
 * Python mirrors in encryptor/protect.py:parse_version_field() and
 * tools/antirev_client.py:_parse_version_field(), and to the value the packer
 * feeds verbatim from config.yaml `version:` / protect.py --version).  Two
 * formats (test builds carry a dotted version, formal builds a DY-marker one):
 *
 *   IF the whole stdout contains a '.':
 *       field = everything AFTER the first '.' (excluding the dot), to the end
 *       of the stdout, whitespace-stripped.  The marker / "SPC" are IGNORED.
 *   ELSE (no '.'):
 *       find `marker` ("Version: DY"); take from just after it to end of line
 *       ('\n'/EOF), truncate before any `spc` ("SPC"), whitespace-stripped.
 *
 * Examples:
 *   "Version: V1.2.3.4"          -> "2.3.4"            (has '.')
 *   "Version: DYV300R001.B011"   -> "B011"             (has '.')
 *   "Version: DYV100R001C00SPC010" -> "V100R001C00"    (no '.')
 *   "Version: DY V100R001 SPC010"  -> "V100R001"       (no '.')
 *
 * The marker/spc tokens are passed in by the caller so stub.c can hand them
 * through OBFSTR (keeping them out of `strings`) while this header stays free
 * of sensitive literals and remains directly unit-testable from plain C.
 */
#ifndef ANTIREV_KEYSPLIT_VERSION_H
#define ANTIREV_KEYSPLIT_VERSION_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ASCII whitespace set — matches Python bytes.strip(): space, \t, \n, \r,
 * \v (0x0b), \f (0x0c). */
static inline int ksv_is_ws(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\n' ||
           c == '\r' || c == '\v' || c == '\f';
}

/* memmem without depending on _GNU_SOURCE's memmem being declared. */
static inline const void *ksv_memmem(const void *hay, size_t haylen,
                                     const void *needle, size_t nlen) {
    if (nlen == 0) return hay;
    if (haylen < nlen) return NULL;
    const uint8_t *h = (const uint8_t *)hay;
    const uint8_t *n = (const uint8_t *)needle;
    for (size_t i = 0; i + nlen <= haylen; i++)
        if (h[i] == n[0] && memcmp(h + i, n, nlen) == 0)
            return h + i;
    return NULL;
}

/* Parse the version field out of `buf` (the version script's raw stdout).
 * `marker` is the DY version marker (e.g. "Version: DY"), `spc` the cut token
 * (e.g. "SPC").  See the two-format rule in the file header.  On success writes
 * up to *out_len bytes into out (capacity out_cap) and returns 0.  Returns -1
 * if the field is empty after parsing, the DY marker is absent (no-dot case),
 * or it would not fit in out_cap. */
static inline int ksv_parse(const uint8_t *buf, size_t buf_len,
                            const char *marker, const char *spc,
                            uint8_t *out, size_t out_cap, size_t *out_len) {
    const uint8_t *start;
    size_t len;

    /* Dotted (test) format: field = everything after the FIRST '.' in the whole
     * stdout, to the end.  marker/SPC are irrelevant here. */
    const uint8_t *dot = (const uint8_t *)ksv_memmem(buf, buf_len, ".", 1);
    if (dot) {
        start = dot + 1;
        len   = (size_t)((buf + buf_len) - start);
    } else {
        /* DY (formal) format: text after `marker`, to end of line, cut at `spc`. */
        size_t mlen = strlen(marker);
        const uint8_t *m = (const uint8_t *)ksv_memmem(buf, buf_len, marker, mlen);
        if (!m) return -1;
        start = m + mlen;
        len   = (size_t)((buf + buf_len) - start);

        const uint8_t *nl = (const uint8_t *)ksv_memmem(start, len, "\n", 1);
        if (nl) len = (size_t)(nl - start);

        const uint8_t *s = (const uint8_t *)ksv_memmem(start, len, spc, strlen(spc));
        if (s) len = (size_t)(s - start);
    }

    /* strip leading/trailing ASCII whitespace (both formats) */
    while (len > 0 && ksv_is_ws(start[0])) { start++; len--; }
    while (len > 0 && ksv_is_ws(start[len - 1])) { len--; }

    if (len == 0 || len > out_cap) return -1;
    memcpy(out, start, len);
    *out_len = len;
    return 0;
}

#endif /* ANTIREV_KEYSPLIT_VERSION_H */
