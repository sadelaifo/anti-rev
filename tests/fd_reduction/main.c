/*
 * fd_reduction test: verify that exe_shim's constructor closes the
 * DT_NEEDED memfds after glibc has finished dynamic linking.
 *
 * Strategy: link against liblinkedmath.so (encrypted DT_NEEDED lib
 * served by the daemon).  By main() time, glibc has mapped the lib
 * and exe_shim's ctor has run.  We then walk /proc/self/fd and
 * readlink every entry; any target whose name contains "linkedmath"
 * indicates the DT_NEEDED memfd is still open — i.e. the close path
 * failed.
 *
 * Exit 0 on success, 1 on any leak.
 */
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "linked/liblinkedmath.h"

int main(void) {
    /* Force DT_NEEDED resolution: call a symbol from the encrypted lib. */
    int a = lm_add(3, 4);
    int m = lm_multiply(6, 7);
    if (a != 7 || m != 42) {
        fprintf(stderr, "FAIL: lm_add/lm_multiply returned wrong values\n");
        return 1;
    }

    DIR *d = opendir("/proc/self/fd");
    if (!d) {
        perror("opendir /proc/self/fd");
        return 1;
    }

    int leaked = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        char target[512];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", ent->d_name);
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n <= 0) continue;
        target[n] = '\0';
        if (strstr(target, "memfd:") != NULL) {
            printf("[fd_reduction] fd %s -> %s\n", ent->d_name, target);
            if (strstr(target, "linkedmath") != NULL) {
                fprintf(stderr,
                        "FAIL: DT_NEEDED memfd still open: %s -> %s\n",
                        ent->d_name, target);
                leaked++;
            }
        }
    }
    closedir(d);

    if (leaked) {
        fprintf(stderr, "FAIL: %d DT_NEEDED memfd(s) leaked\n", leaked);
        return 1;
    }
    printf("PASS: DT_NEEDED memfd closed by exe_shim ctor\n");
    return 0;
}
