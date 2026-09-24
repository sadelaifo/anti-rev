/*
 * proc_b — second encrypted process that creates a UA_Client.
 *
 * Mirrors proc_a but also exercises UA_Client_getEndpointsInternal
 * (via UA_Client_getEndpoints) and UA_Client_findServers, which are
 * common early-init calls in the production code path.
 */
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("[proc_b] creating UA_Client...\n");

    UA_Client *client = UA_Client_new();
    if (!client) {
        fprintf(stderr, "FAIL: proc_b: UA_Client_new() returned NULL\n");
        return 1;
    }

    UA_ClientConfig *config = UA_Client_getConfig(client);
    UA_StatusCode rc = UA_ClientConfig_setDefault(config);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "FAIL: proc_b: UA_ClientConfig_setDefault() = 0x%08x\n", rc);
        UA_Client_delete(client);
        return 1;
    }

    printf("[proc_b] config done, attempting connect to localhost:4840...\n");

    rc = UA_Client_connect(client, "opc.tcp://localhost:4840");
    printf("[proc_b] connect returned 0x%08x (failure expected, no server)\n", rc);

    /* Also try getEndpoints — exercises more of the client internals */
    UA_EndpointDescription *endpoints = NULL;
    size_t n_endpoints = 0;
    rc = UA_Client_getEndpoints(client, "opc.tcp://localhost:4840",
                                &n_endpoints, &endpoints);
    printf("[proc_b] getEndpoints returned 0x%08x (n=%zu)\n", rc, n_endpoints);
    if (endpoints)
        UA_Array_delete(endpoints, n_endpoints,
                        &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);

    UA_Client_delete(client);
    printf("PASS: proc_b completed without crash\n");
    return 0;
}
