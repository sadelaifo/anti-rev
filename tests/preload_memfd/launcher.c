/* launcher.c — load a .so into a memfd, set LD_PRELOAD, exec the binary.
 *
 * Usage: ./launcher <lib.so> <binary> [args...]
 *
 * Strips LD_LIBRARY_PATH so the dynamic linker cannot find the .so on disk.
 * The only way DT_NEEDED can be satisfied is via the LD_PRELOAD memfd. */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char *argv[], char *envp[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <lib.so> <binary> [args...]\n", argv[0]);
        return 1;
    }

    const char *lib_path = argv[1];
    const char *bin_path = argv[2];

    /* --- read .so into a memfd ---------------------------------------- */
    int lib_fd = open(lib_path, O_RDONLY);
    if (lib_fd < 0) { perror("open lib"); return 1; }

    int mfd = (int)syscall(__NR_memfd_create, "pretest", 0);
    if (mfd < 0) { perror("memfd_create"); return 1; }

    char buf[4096];
    ssize_t n;
    while ((n = read(lib_fd, buf, sizeof(buf))) > 0) {
        const char *p = buf;
        ssize_t left = n;
        while (left > 0) {
            ssize_t w = write(mfd, p, (size_t)left);
            if (w <= 0) { perror("write memfd"); return 1; }
            p    += w;
            left -= w;
        }
    }
    close(lib_fd);
    lseek(mfd, 0, SEEK_SET);

    /* --- build LD_PRELOAD env var ------------------------------------- */
    char preload[64];
    snprintf(preload, sizeof(preload), "LD_PRELOAD=/proc/self/fd/%d", mfd);

    /* --- build new environment ---------------------------------------- */
    int envc = 0;
    while (envp[envc]) envc++;

    char **new_env = malloc((size_t)(envc + 2) * sizeof(char *));
    if (!new_env) { perror("malloc"); return 1; }

    int ei = 0;
    for (int i = 0; i < envc; i++) {
        /* strip LD_PRELOAD and LD_LIBRARY_PATH so .so can only come from memfd */
        if (strncmp(envp[i], "LD_PRELOAD=",     11) == 0) continue;
        if (strncmp(envp[i], "LD_LIBRARY_PATH=", 16) == 0) continue;
        new_env[ei++] = envp[i];
    }
    new_env[ei++] = preload;
    new_env[ei]   = NULL;

    /* --- exec the binary ---------------------------------------------- */
    printf("launcher: LD_PRELOAD=/proc/self/fd/%d  exec %s\n", mfd, bin_path);

    execve(bin_path, &argv[2], new_env);
    perror("execve");
    return 1;
}
