/* Plain child process fork+exec'd by the launcher.  Inherits LD_PRELOAD
 * (the aarch64 shim) but is a non-owner process, so the shim must pass
 * through to real libc.  Runs under its own nested qemu translation. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) exe[n] = '\0'; else exe[0] = '\0';
    printf("[worker] argv[0]=%s pid=%d exe=%s\n", argv[0], (int) getpid(), exe);
    return 7;
}
