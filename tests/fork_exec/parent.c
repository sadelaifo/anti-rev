/*
 * fork_exec test — parent binary (run via antirev stub).
 *
 * Spawns the child binary via fork()+exec(), passing the encrypted .so path
 * as argv[1].  The child is a plain (non-stub) binary that inherits LD_AUDIT
 * and ANTIREV_KEY_FD from this process, and must be able to dlopen the
 * encrypted .so through the audit shim.
 *
 * Usage: parent.protected <child_bin> <encrypted_lib_path>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <child_bin> <encrypted_lib>\n", argv[0]);
        return 1;
    }
    const char *child_bin = argv[1];
    const char *lib_path  = argv[2];

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* Child: exec the daemon binary */
        execl(child_bin, child_bin, lib_path, NULL);
        perror("execl");
        _exit(1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("PASS: fork+exec child loaded encrypted .so via inherited shim\n");
        return 0;
    }
    fprintf(stderr, "FAIL: child exited with status %d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}
