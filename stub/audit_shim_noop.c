/* No-op audit shim — does absolutely nothing, just passes through.
 * Used to test if LD_AUDIT itself breaks things on this glibc version.
 *
 * GATE TEST (resurrected from ceb3edd). History: on glibc 2.26 a no-op
 * audit module still broke the business software's RPC connections
 * (commits ceb3edd -> 612eceb), so LD_AUDIT was abandoned as the core
 * architecture. BUT that verdict is glibc-2.26-specific and was found
 * on the x86 build box; the machines that actually fail are
 * aarch64 / glibc 2.34, which reworked rtld-audit across 8 releases.
 * So the verdict must be RE-PROVEN on aarch64/2.34, not assumed.
 *
 * Procedure: build this on the aarch64/2.34 box, then
 *     LD_AUDIT=/path/to/audit_shim_noop.so <real RPC business binary>
 * If RPC survives, LD_AUDIT itself is compatible on 2.34 and the
 * decrypt-on-demand la_objsearch design (cf. old stub/audit_shim.c,
 * recoverable from git fc4dbb9^) becomes the right structural fix —
 * it kills the entire DT_RPATH/ciphertext problem (no pack-time
 * patchelf) and uses natural ctor ordering. If RPC still breaks,
 * LD_AUDIT stays dead and we go natural-load + RPATH neutralization.
 *
 * Deliberately minimal: only la_version + la_objsearch (NO la_symbind /
 * pltenter), the least-invasive audit form — maximizes compatibility,
 * so a failure here is a true LD_AUDIT-itself failure, not our logic. */
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
