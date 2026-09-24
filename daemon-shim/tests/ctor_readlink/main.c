/*
 * ctor_readlink test — verifies that readlink("/proc/self/exe") returns the
 * real binary path even when called from a C++ global static initializer
 * in a DT_NEEDED library (before exe_shim's constructor may have run).
 */
#include <stdio.h>
#include <string.h>

extern const char *get_ctor_process_name(void);
extern const char *get_runtime_process_name(void);

int main(void)
{
    const char *ctor_name    = get_ctor_process_name();
    const char *runtime_name = get_runtime_process_name();

    printf("ctor process name:    %s\n", ctor_name);
    printf("runtime process name: %s\n", runtime_name);

    int fail = 0;

    if (strstr(ctor_name, "memfd") != NULL) {
        fprintf(stderr, "FAIL: ctor process name contains 'memfd': %s\n",
                ctor_name);
        fail = 1;
    }

    if (strstr(runtime_name, "memfd") != NULL) {
        fprintf(stderr, "FAIL: runtime process name contains 'memfd': %s\n",
                runtime_name);
        fail = 1;
    }

    if (!fail)
        printf("PASS: both ctor and runtime process names are clean\n");

    return fail;
}
