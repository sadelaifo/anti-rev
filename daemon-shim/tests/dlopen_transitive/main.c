/*
 * Transitive DT_NEEDED through unencrypted intermediary test.
 *
 * Topology:
 *   exe ──DT_NEEDED──→ libbridge.so  (unencrypted, 3rd party)
 *                           │
 *                       DT_NEEDED
 *                           ↓
 *                      libmiddle.so  (encrypted)
 *                           │
 *                        dlopen()
 *                           ↓
 *                      libinner.so   (encrypted)
 *
 * Tests that the packer/stub correctly discovers libmiddle.so as
 * a transitive DT_NEEDED through an unencrypted intermediary, and
 * that libinner.so is available for dlopen at runtime.
 */
#include <stdio.h>

extern int bridge_get_value(void);
extern int bridge_get_inner(void);

int main(void)
{
    int failures = 0;

    /* Test 1: call through bridge → middle (DT_NEEDED chain) */
    int val = bridge_get_value();
    if (val != 42) {
        fprintf(stderr, "FAIL: bridge_get_value() = %d, expected 42\n", val);
        failures++;
    }

    /* Test 2: bridge → middle → dlopen(inner) */
    int inner = bridge_get_inner();
    if (inner != 99) {
        fprintf(stderr, "FAIL: bridge_get_inner() = %d, expected 99\n", inner);
        failures++;
    }

    if (failures == 0)
        printf("PASS: dlopen_transitive (bridge->middle->inner, 2 checks)\n");
    else
        printf("FAIL: dlopen_transitive (%d failure(s))\n", failures);

    return failures ? 1 : 0;
}
