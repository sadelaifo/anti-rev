/*
 * obfstr.h — string-literal obfuscation for antirev components.
 *
 * ─── Threat model ─────────────────────────────────────────────────────
 *
 * antirev keeps the protected binary encrypted at rest.  But the
 * moment the stub decrypts it into a memfd the memfd is mapped into
 * the process address space, and `strings /proc/<PID>/maps` (or
 * `strings` on the memfd file itself) reveals every string literal
 * the source code referenced:
 *
 *      printf format strings   "[antirev] failed to connect to lib daemon"
 *      perror messages         "memfd_create"
 *      env-var names           "ANTIREV_LIBD_SOCK="  "ANTIREV_FD_MAP="
 *      dlsym symbol names      "ANTI_LoadProcess"  "popen"  "openat"
 *      path templates          "/proc/self/fd/%d"  "/tmp/.antirev-..."
 *      socket name prefix      "antirev_%s"
 *
 * The whole defensive design is in the clear.  obfstr keeps these
 * literals as XOR-encrypted bytes in .rodata and only briefly decodes
 * them onto the caller's stack at the moment of use.
 *
 * ─── Two-stage architecture ───────────────────────────────────────────
 *
 *      source (stub/*.c)
 *          │   perror("memfd_create");
 *          │   fprintf(stderr, "[antirev] failed");
 *          │   dlsym(RTLD_NEXT, "ANTI_LoadProcess");
 *          ▼
 *      [1] tools/obfstr_gen.py        ← compile-time, runs before gcc
 *          │   scan call sites, encrypt literal arguments
 *          ▼
 *      build/obf/*.c (rewritten source)
 *          │   perror(_OBF(0x3a, 0x2b, 0x2c, ...));
 *          │   fprintf(stderr, _OBF(0x0c, 0x2f, ...));
 *          │   dlsym(RTLD_NEXT, _OBF(0x16, 0x00, ...));
 *          ▼
 *      [2] gcc compile  +  this header (runtime decoder)
 *          │   ciphertext bytes land in .rodata (volatile prevents
 *          │   the compiler folding them back to cleartext)
 *          ▼
 *      final binary — `strings` only sees noise bytes
 *
 * ─── Stage 1: tools/obfstr_gen.py ─────────────────────────────────────
 *
 * CMake runs this Python pass before compiling each stub/*.c, writing
 * the rewritten source to build/obf/<basename>.  The scanner pattern-
 * matches calls to a fixed set of functions/macros:
 *
 *      antirev wrappers:   OBFSTR LOG_ERR PERR OSNPRINTF ODLSYM LOG
 *      libc print:         fprintf snprintf perror
 *      libc symbol/env:    dlsym getenv setenv unsetenv
 *      libc strcmp/like:   strcmp strncmp strstr
 *      libc file/exec:     fopen open openat syscall execl/execve/...
 *      project helpers:    strip_env_path_entries find_env_value make_memfd
 *
 * For each match the scanner:
 *   - parses the argument list (handling nested parens, concatenated
 *     literals "a" "b", escape sequences \n \xNN \ooo)
 *   - replaces every pure string-literal argument with
 *     _OBF(0xNN, 0xNN, ...)
 *   - leaves non-literal arguments (variables, expressions) alone
 *
 * Encryption formula (obf_key(i) in obfstr_gen.py):
 *
 *      key(i) = 0x5a XOR (((i * 7) + 13) & 0xff)
 *
 * Position-dependent: byte i is XORed with key(i).  encode and decode
 * use the same formula so the codegen-time ciphertext decodes cleanly
 * at runtime.
 *
 * Caveat: the scanner only recognises literals in *function-call
 * argument* position.  These patterns are invisible to it and must be
 * refactored at the source:
 *
 *      static const char *arr[] = {"X", NULL};   // array initializer
 *      const char *p = "X";                      // var initializer
 *      struct s = {.name = "X"};                 // struct initializer
 *      out[i] = "X";                             // bare assignment
 *      #define MACRO "X"                         // macro-internal literal
 *
 * In this codebase such sites have been hand-wrapped as OBFSTR("X")
 * (which IS a function-call position the scanner sees) or
 * strdup(OBFSTR("X")) when the decoded buffer must outlive the
 * function that built it.
 *
 * ─── Stage 2: runtime decoder (this header) ───────────────────────────
 *
 * _OBF(...) is a GCC statement expression — see the implementation
 * below.  Two non-obvious design choices, both load-bearing:
 *
 *   ① `const volatile uint8_t _e[]` — volatile is *mandatory*.
 *      Without it gcc -O2 sees through the XOR, computes the entire
 *      decode loop at compile time, and writes the cleartext back
 *      into .rodata, defeating the whole protection.  volatile
 *      forces a real memory load per byte and blocks const-folding.
 *
 *   ② `__builtin_alloca` for the decoded buffer.
 *      An earlier draft used `char buf[N]` declared inside the
 *      statement-expression block.  Older GCC marks that buf
 *      "destroyed" at the SE boundary, after which a *subsequent*
 *      OBFSTR's encrypted byte array can reuse the same stack slot —
 *      a caller that held the first pointer then reads the second
 *      call's ciphertext through it.  __builtin_alloca allocates on
 *      the *calling function's* frame, so the buffer survives the
 *      SE and stays alive until that function returns.
 *
 * Lifetime: the decoded buffer's lifetime is the *calling function*.
 * It dies when that function returns.
 *
 *      fprintf(stderr, OBFSTR("hello"));           ✅ safe
 *      printf(LOG_ERR_arg, ...);                   ✅ consumed inline
 *      const char *p = OBFSTR("x"); later_call(p); ❌ UB — buffer dead
 *      static const char *p = OBFSTR("x");         ❌ UB — alloca can't
 *                                                       outlive the call
 *
 * Don't stash the OBFSTR pointer in static/global storage, and don't
 * pass it across a function-return boundary.  If you need the string
 * to survive that long, copy it (`strdup(OBFSTR(...))` or memcpy into
 * a caller-owned buffer).
 *
 * ─── Convenience wrappers ─────────────────────────────────────────────
 *
 * A few macros wrap the most common patterns with cleaner names:
 *
 *      LOG_ERR(fmt, ...)            → fprintf(stderr, fmt, ...)
 *      PERR(msg)                    → "msg: <strerror>\n" to stderr
 *      OSNPRINTF(buf, n, fmt, ...)  → snprintf with obfuscated fmt
 *      ODLSYM(handle, name)         → dlsym(handle, name)
 *
 * They're optional — fprintf / snprintf / perror / dlsym are already
 * in the codegen scanner list, so existing call sites get encrypted
 * literals without any source change.  The wrappers exist as a
 * semantically nicer entry point for new code.
 *
 * ─── Attack-surface coverage ──────────────────────────────────────────
 *
 * Defended:
 *   ✓ offline `strings` on the encrypted on-disk binary
 *   ✓ `strings` on a copied-out memfd file
 *   ✓ static analysis of a process core dump
 *   ✓ static dump of the .rodata mapping in /proc/<PID>/maps
 *
 * NOT defended:
 *   ✗ ptrace-attached attacker watching during a printf — the OBFSTR
 *     output spends microseconds-to-milliseconds in the alloca'd
 *     stack buffer, long enough to catch with the right timing
 *   ✗ /proc/<PID>/mem high-frequency snapshotting — same window
 *   ✗ the printf output itself (stdout / stderr / syslog sinks)
 *   ✗ third-party libs linked in (glibc's error-message table, etc.)
 *     — they're not part of our source so the codegen never sees them
 *   ✗ exported symbol names (ANTI_LoadProcess and friends) — LD_PRELOAD
 *     interposition requires those names in .dynsym, otherwise the
 *     dynamic linker can't find the interception entry point
 *   ✗ compiler/linker-injected strings (.comment GCC version, build-id)
 *
 * In short: tier-1 (offline static analysis) is fully blocked, tier-2
 * (live ptrace attacker) is raised in cost but not blocked, tier-3
 * (output sinks / linked-in third party) is out of scope.
 *
 * ─── Performance ──────────────────────────────────────────────────────
 *
 * Each _OBF call = one alloca + an N-byte XOR loop.  For typical
 * strings (N ≈ 30) one decode is ~10-30 ns.  Negligible on log/error
 * paths.  Avoid OBFSTR inside million-call-per-second hot loops —
 * the alloca + loop overhead amplifies there.
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
