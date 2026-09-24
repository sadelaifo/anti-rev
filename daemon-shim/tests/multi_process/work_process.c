/*
 * multi_process test — work process.
 *
 * Exec'd by grpc_daemon via fork()+exec().  NOT wrapped in the antirev stub
 * directly — it receives the stub-wrapped binary path as its own argv[0].
 * Inherits LD_AUDIT + ANTIREV_KEY_FD from grpc_daemon, which lets the audit
 * shim decrypt the encrypted libwork.so passed as argv[1].
 *
 * Validates:
 *   1. /proc/self/exe returns the correct path (exe_shim working in exec'd child)
 *   2. dlopen on encrypted libwork.so succeeds (audit shim + key fd inherited)
 *   3. compute(21) == 42 (library actually loaded and callable)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

static int check_exe_path(void)
{
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) { perror("readlink"); return 0; }
    buf[n] = '\0';
    printf("[work_process] /proc/self/exe = %s\n", buf);
    if (strstr(buf, "memfd")) {
        fprintf(stderr, "FAIL [work_process]: /proc/self/exe contains 'memfd'\n");
        return 0;
    }
    if (strstr(buf, "(deleted)")) {
        fprintf(stderr, "FAIL [work_process]: /proc/self/exe contains '(deleted)'\n");
        return 0;
    }
    if (!strstr(buf, "work_process")) {
        fprintf(stderr, "FAIL [work_process]: /proc/self/exe doesn't contain 'work_process': %s\n", buf);
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: work_process <encrypted_lib_path>\n");
        return 1;
    }

    if (!check_exe_path()) return 1;

    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL [work_process]: dlopen('%s'): %s\n", argv[1], dlerror());
        return 1;
    }

    typedef int (*compute_fn)(int);
    compute_fn compute = (compute_fn)dlsym(handle, "compute");
    if (!compute) {
        fprintf(stderr, "FAIL [work_process]: dlsym(compute): %s\n", dlerror());
        return 1;
    }

    int result = compute(21);
    if (result != 42) {
        fprintf(stderr, "FAIL [work_process]: compute(21)=%d (expected 42)\n", result);
        return 1;
    }

    printf("[work_process] compute(21)=%d  PASS\n", result);
    dlclose(handle);
    return 0;
}
