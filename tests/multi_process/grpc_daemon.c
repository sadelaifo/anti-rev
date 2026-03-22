/*
 * multi_process test — gRPC daemon simulator.
 *
 * Simulates a commercial gRPC daemon.  Listens on a Unix domain socket,
 * receives an INIT command from the PM, spawns a work process via
 * fork()+exec(), waits for it, and sends the result back.
 *
 * This binary IS wrapped in the antirev stub.  It validates its own
 * /proc/self/exe path (exe_shim must be working), then exercises the
 * fork()+exec() path that was fixed in audit_shim (key fd stays open).
 *
 * Socket protocol (newline terminated):
 *   PM sends:    "INIT <work_bin_path> <lib_path>\n"
 *   Daemon sends: "OK\n" or "FAIL\n"
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

static int check_exe_path(void)
{
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) { perror("readlink"); return 0; }
    buf[n] = '\0';
    printf("[grpc_daemon] /proc/self/exe = %s\n", buf);
    if (strstr(buf, "memfd") || strstr(buf, "(deleted)")) {
        fprintf(stderr, "FAIL [grpc_daemon]: /proc/self/exe is a memfd path\n");
        return 0;
    }
    if (!strstr(buf, "grpc_daemon")) {
        fprintf(stderr, "FAIL [grpc_daemon]: /proc/self/exe doesn't contain 'grpc_daemon': %s\n", buf);
        return 0;
    }
    return 1;
}

static int recv_line(int fd, char *buf, size_t size)
{
    size_t pos = 0;
    while (pos < size - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) break;
        buf[pos++] = c;
        if (c == '\n') break;
    }
    buf[pos] = '\0';
    /* strip trailing newline */
    if (pos > 0 && buf[pos-1] == '\n') buf[--pos] = '\0';
    return (int)pos;
}

static void send_line(int fd, const char *msg)
{
    write(fd, msg, strlen(msg));
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: grpc_daemon <socket_path>\n");
        return 1;
    }
    const char *sock_path = argv[1];

    if (!check_exe_path()) return 1;

    /* Create Unix domain socket */
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    unlink(sock_path);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(srv, 1) < 0) { perror("listen"); return 1; }

    printf("[grpc_daemon] listening on %s\n", sock_path);
    fflush(stdout);

    int conn = accept(srv, NULL, NULL);
    if (conn < 0) { perror("accept"); return 1; }

    /* Read INIT command: "INIT <work_bin> <lib_path>" */
    char line[2048];
    if (recv_line(conn, line, sizeof(line)) <= 0) {
        fprintf(stderr, "[grpc_daemon] empty command\n");
        send_line(conn, "FAIL\n");
        return 1;
    }
    printf("[grpc_daemon] received: %s\n", line);

    char work_bin[1024], lib_path[1024];
    if (sscanf(line, "INIT %1023s %1023s", work_bin, lib_path) != 2) {
        fprintf(stderr, "[grpc_daemon] bad command format\n");
        send_line(conn, "FAIL\n");
        return 1;
    }

    /* Spawn work process via fork()+exec() */
    printf("[grpc_daemon] spawning: %s %s\n", work_bin, lib_path);
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); send_line(conn, "FAIL\n"); return 1; }

    if (pid == 0) {
        execl(work_bin, work_bin, lib_path, NULL);
        perror("execl");
        _exit(1);
    }

    int status = 0;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[grpc_daemon] work_process succeeded\n");
        send_line(conn, "OK\n");
    } else {
        fprintf(stderr, "[grpc_daemon] work_process failed (exit %d)\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        send_line(conn, "FAIL\n");
    }

    close(conn);
    close(srv);
    unlink(sock_path);
    return 0;
}
