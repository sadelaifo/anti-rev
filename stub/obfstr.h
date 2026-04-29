/*
 * obfstr.h — string-literal obfuscation for antirev components.
 *
 * The threat: even though `antirev` keeps the protected binary
 * encrypted at rest, the moment the stub decrypts it into a memfd the
 * memfd is mapped into the process address space and `strings
 * /proc/<PID>/maps` will see every printf format, perror message,
 * env-var name, and dlsym symbol that the source code referenced as a
 * literal.  Architecture markers like "ANTIREV_LIBD_SOCK=", function
 * names like "ANTI_LoadProcess", and the prefix "[antirev]" all leak
 * the entire defensive design.
 *
 * The fix in two pieces:
 *
 *   1. tools/obfstr_gen.py runs *before* the C preprocessor.  It scans
 *      each .c we feed it for calls to the macros listed below, and
 *      replaces every string-literal argument with a pre-encrypted byte
 *      sequence:
 *
 *        LOG_ERR("hello %s\n", x)        // source as written
 *        LOG_ERR(_OBF(0x32, 0x2c, ...), x)   // after codegen
 *
 *      The transformed .c is what actually gets compiled, so the
 *      cleartext "hello %s\n" never makes it into .rodata.
 *
 *   2. _OBF(...) is a statement expression that materialises a small
 *      `const volatile uint8_t[]` of the encrypted bytes on the stack
 *      (or rodata, compiler's choice — either way the bytes are
 *      ciphertext, not the original literal), XORs them with
 *      _OBF_K(i) into a stack buffer, and yields a `const char *`
 *      pointing at the freshly-decoded plaintext.  The buffer lives
 *      until the enclosing function returns.
 *
 * Lifetime caveat: the decoded buffer is on the caller's stack, so
 *
 *      printf(LOG_ERR_arg, ...);   // safe — call eats it before return
 *      const char *p = OBFSTR("x"); some_callback_later(p);  // UB
 *
 * Don't squirrel the pointer away across function calls.
 *
 * The `volatile` qualifier on the encrypted byte array is mandatory:
 * without it, gcc -O2 happily folds the entire decode loop at compile
 * time and writes the cleartext back into .rodata, defeating the
 * whole point.  Volatile forces a real memory load per byte.
 */

#ifndef ANTIREV_OBFSTR_H
#define ANTIREV_OBFSTR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

/* Per-position deobfuscation key.  KEEP IN SYNC with obf_key() in
 * tools/obfstr_gen.py — they encrypt and decrypt with the same formula,
 * so any change here must mirror there or every protected string will
 * decode to garbage.
 *
 * The formula is intentionally non-trivial enough that a casual reader
 * can't infer it from a single decoded byte, but cheap enough that the
 * decode loop stays in the noise on a release build. */
#define _OBF_K(i) ((uint8_t)(0x5a ^ (((((unsigned)(i)) * 7u) + 13u) & 0xffu)))

/* Decode `__VA_ARGS__` (a comma-separated list of encrypted bytes
 * produced by the codegen) back to a NUL-terminated string on the
 * caller's stack.  Yields a `const char *` that's valid until the
 * enclosing FUNCTION returns.
 *
 * Why __builtin_alloca instead of `char buf[N]`: GCC's lifetime rule
 * for variables declared inside a statement-expression `({...})` is
 * not consistently the enclosing function — depending on version the
 * storage may be released the moment the SE ends, after which a
 * subsequent SE can reuse the slot for *its* own encrypted byte
 * array.  Caller code that held the pointer (`p = OBFSTR("a"); ...
 * q = OBFSTR("b"); strcmp(p, "a")`) then reads the second call's
 * ciphertext through the first call's pointer — strcmp returns
 * non-zero, the test reports "second call yielded different bytes",
 * and from outside it looks like the decoder is broken.  alloca'd
 * memory survives the SE because it lives on the caller's frame, not
 * inside the SE block. */
#define _OBF(...)                                                         \
    ({                                                                    \
        const volatile uint8_t _antirev_obf_e[] = { __VA_ARGS__ };        \
        size_t _antirev_obf_n = sizeof(_antirev_obf_e);                   \
        char *_antirev_obf_buf =                                          \
            (char *)__builtin_alloca(_antirev_obf_n + 1);                 \
        for (size_t _antirev_obf_i = 0;                                   \
             _antirev_obf_i < _antirev_obf_n; _antirev_obf_i++)           \
            _antirev_obf_buf[_antirev_obf_i] =                            \
                (char)(_antirev_obf_e[_antirev_obf_i]                     \
                       ^ _OBF_K(_antirev_obf_i));                         \
        _antirev_obf_buf[_antirev_obf_n] = '\0';                          \
        (const char *)_antirev_obf_buf;                                   \
    })

/* OBFSTR is the bare marker — a function-style macro that the codegen
 * recognises and rewrites.  The fall-through definition (passthrough)
 * matters only when somebody compiles a single source file by hand
 * without running the codegen first; in that case the literal sits in
 * .rodata as it would have without obfuscation, the build still
 * compiles, and the output is functionally correct.  In the regular
 * CMake flow obfstr_gen.py replaces every OBFSTR("...") with _OBF(...)
 * before the preprocessor runs. */
#define OBFSTR(s) (s)

/* Convenience wrappers around the most common log / format / lookup
 * patterns in the antirev sources.  After codegen, the literal arg is
 * already an _OBF(...) call, so OBFSTR(fmt) further wraps it in the
 * passthrough macro and the expansion stays a `const char *`. */
#define LOG_ERR(fmt, ...) \
    fprintf(stderr, OBFSTR(fmt), ##__VA_ARGS__)

#define PERR(msg) \
    fprintf(stderr, OBFSTR("%s: %s\n"), OBFSTR(msg), strerror(errno))

#define OSNPRINTF(buf, n, fmt, ...) \
    snprintf(buf, n, OBFSTR(fmt), ##__VA_ARGS__)

#define ODLSYM(handle, name) \
    dlsym(handle, OBFSTR(name))

#endif /* ANTIREV_OBFSTR_H */
