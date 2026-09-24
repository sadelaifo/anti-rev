/*
 * Test 3: parent fork+exec's a child; child dlopen's the SAME lib as parent.
 *
 * Parent is protected with --libs mylib.so (bundled).
 * Child is a plain binary that inherits LD_PRELOAD from parent.
 * Child calls dlopen("mylib.so") by soname — the inherited LD_PRELOAD
 * already loaded it, so the linker returns the existing handle.
 *
 * Usage: parent.protected <child_binary>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <child_binary>\n", argv[0]);
        return 1;
    }

    /* Parent also uses the lib to prove it works here too */
    void *handle = dlopen("mylib.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "FAIL: parent dlopen(\"mylib.so\"): %s\n", dlerror());
        return 1;
    }
    int (*add_fn)(int, int) = dlsym(handle, "add");
    if (!add_fn || add_fn(10, 20) != 30) {
        fprintf(stderr, "FAIL: parent add(10,20) != 30\n");
        return 1;
    }
    printf("parent: add(10,20)=%d OK\n", add_fn(10, 20));

    /* Fork + exec child */
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
        printf("PASS: fork+exec child loaded same lib via inherited LD_PRELOAD\n");
        return 0;
    }
    fprintf(stderr, "FAIL: child exited with status %d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}
