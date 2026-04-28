/*
 * obf.h — runtime decoder for compile-time-obfuscated strings.
 *
 * Encoded byte arrays + length defines live in obf_strings_data.h, which
 * is generated at build time by tools/gen_obf.py from a canonical list of
 * sensitive strings.  The generator picks a fresh per-build XOR key so
 * that an offline deobfuscator built against one release does not work
 * against the next.
 *
 * Use-site form:
 *
 *     getenv(OBF(ENV_FD_MAP));
 *     fprintf(stderr, "%s", OBF(PATH_PROC_SELF_EXE));
 *
 * Each call site gets its own per-thread static buffer.  Decoding is
 * cheap (≤ 40 bytes per string, single XOR per byte) and runs every
 * call — the buffer doesn't cache between calls so decoded plaintext
 * does not linger between uses, which keeps the `strings`-on-running-
 * process surface as small as possible.  __thread is used so concurrent
 * calls from different threads don't race on a shared buffer.
 *
 * Limitations:
 *   - The returned pointer is valid only for the lifetime of the calling
 *     thread + as long as no other OBF(...) call in the same thread
 *     overwrites the same per-call-site buffer.  Each call site has its
 *     own buffer (different statement-expression scope), so OBF(A) and
 *     OBF(B) on the same line don't collide.  Two OBF(A) calls on the
 *     same line in the same thread *do* collide — copy out if you need
 *     to retain.
 *   - Strings are still plaintext in memory between decode and use.  This
 *     defeats `strings binary` (static analysis) but not a debugger
 *     attached at the right moment (Layer 4's job).
 */

#ifndef ANTIREV_OBF_H
#define ANTIREV_OBF_H

#include <stddef.h>

#include "obf_strings_data.h"

/* The decode loop is intentionally inline (not a separately-named
 * function) so it doesn't show up by name in the symbol table even
 * before stripping, and so the optimizer can specialize the length
 * for each call site. */
#define OBF(NAME)                                                          \
    ({                                                                     \
        static __thread char _obf_buf[OBF_LEN_##NAME + 1];                 \
        for (size_t _obf_i = 0;                                            \
             _obf_i < (size_t)OBF_LEN_##NAME;                              \
             ++_obf_i) {                                                   \
            _obf_buf[_obf_i] = (char)((unsigned char)OBF_DATA_##NAME[_obf_i] \
                ^ ((OBF_KEY + _obf_i + OBF_SALT) & 0xff));                 \
        }                                                                  \
        _obf_buf[OBF_LEN_##NAME] = '\0';                                   \
        (const char *)_obf_buf;                                            \
    })

#endif /* ANTIREV_OBF_H */
