/* No-op audit shim — does absolutely nothing, just passes through.
 * Used to test if LD_AUDIT itself breaks things on this glibc version.
 *
 * GATE TEST (resurrected from ceb3edd). History: on glibc 2.26 a no-op
 * audit module still broke the business software's RPC connections
 * (ceb3edd no-op isolation -> 612eceb removal), so LD_AUDIT was
 * abandoned as the core architecture (it was once the core arch:
 * e728c09 / 9bea67f). BUT that verdict is glibc-2.26-specific and was
 * found on the x86 build box; the machines that actually fail are the
 * aarch64 lower-machine (下位机), glibc 2.34, which reworked rtld-audit
 * across 8 releases. So the verdict MUST be re-proven on aarch64/2.34,
 * not assumed — this is the cheap, decisive gate before any full
 * audit_shim rearchitecture.
 *
 * Procedure (on the aarch64/2.34 下位机):
 *   cmake --build build --target audit_shim_noop
 *   <real RPC business binary> <args>                       # baseline
 *   LD_AUDIT=/abs/.../audit_shim_noop.so <same binary> <args>
 * Drive a real RPC connection/call, not just process start.
 *   RPC survives  -> LD_AUDIT itself is OK on 2.34; the la_objsearch
 *                    decrypt-on-demand design (old stub/audit_shim.c,
 *                    recoverable via `git show fc4dbb9^:stub/audit_shim.c`)
 *                    becomes the right structural fix — it redirects
 *                    encrypted libs to memfds BEFORE glibc consults
 *                    RPATH, so it kills the DT_RPATH/ciphertext problem
 *                    outright and uses natural ctor ordering.
 *   RPC breaks    -> LD_AUDIT stays dead on 2.34 too; do not invest in
 *                    the rearchitecture.
 *
 * Deliberately minimal: only la_version + la_objsearch (NO la_symbind /
 * pltenter), the least-invasive audit form — so a failure here is a
 * true LD_AUDIT-itself failure, not our logic. */
#define _GNU_SOURCE
#include <link.h>

__attribute__((visibility("default")))
unsigned int la_version(unsigned int version)
{
    (void)version;
    return LAV_CURRENT;
}

__attribute__((visibility("default")))
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
    (void)cookie;
    (void)flag;
    return (char *)name;
}
