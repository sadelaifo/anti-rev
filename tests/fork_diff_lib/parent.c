/*
 * Test 4: parent uses libparent.so, fork+exec's a PROTECTED child
 * that uses a different lib (libchild.so).
 *
 * Parent is protected with --libs libparent.so.
 * Child is itself a protected binary with --libs libchild.so.
 *
 * Usage: parent.protected <child.protected>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <child.protected>\n", argv[0]);
        return 1;
    }

    /* Parent uses its own lib */
    void *handle = dlopen("libparent.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL: parent dlopen(\"libparent.so\"): %s\n", dlerror());
        return 1;
    }
    int (*mul)(int, int) = dlsym(handle, "parent_multiply");
    if (!mul || mul(6, 7) != 42) {
        fprintf(stderr, "FAIL: parent_multiply(6,7) != 42\n");
        return 1;
    }
    printf("parent: parent_multiply(6,7)=%d OK\n", mul(6, 7));

    /* Fork + exec child (which is a protected binary with its own stub) */
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        execl(argv[1], argv[1], NULL);
        perror("execl");
        _exit(1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("PASS: parent used libparent.so, child used libchild.so independently\n");
        return 0;
    }
    fprintf(stderr, "FAIL: child exited with status %d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}
