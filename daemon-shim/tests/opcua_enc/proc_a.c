/*
 * proc_a — encrypted process that creates a UA_Client via DT_NEEDED linkage.
 *
 * Tests whether OPC UA client initialization works correctly when the
 * calling binary runs from memfd (antirev encryption).  Does NOT need
 * a real OPC UA server — we only exercise the client creation / config
 * path, which is where the production crash occurs.
 */
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("[proc_a] creating UA_Client...\n");

    UA_Client *client = UA_Client_new();
    if (!client) {
        fprintf(stderr, "FAIL: proc_a: UA_Client_new() returned NULL\n");
        return 1;
    }

    UA_ClientConfig *config = UA_Client_getConfig(client);
    UA_StatusCode rc = UA_ClientConfig_setDefault(config);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "FAIL: proc_a: UA_ClientConfig_setDefault() = 0x%08x\n", rc);
        UA_Client_delete(client);
        return 1;
    }

    printf("[proc_a] config done, attempting connect to localhost:4840...\n");

    /* Connect to a non-existent server — expected to fail with a timeout
     * or connection-refused error.  The point is that the client init and
     * connect code path doesn't crash. */
    rc = UA_Client_connect(client, "opc.tcp://localhost:4840");
    printf("[proc_a] connect returned 0x%08x (failure expected, no server)\n", rc);

    UA_Client_delete(client);
    printf("PASS: proc_a completed without crash\n");
    return 0;
}
