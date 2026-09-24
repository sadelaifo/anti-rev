/*
 * multi_process test — Process Manager simulator.
 *
 * Simulates a PM that calls initialize() on a gRPC daemon.  Connects to the
 * daemon's Unix socket, sends an INIT command with the work process binary
 * and encrypted library paths, and waits for OK/FAIL.
 *
 * This binary IS wrapped in the antirev stub.  Validates its own
 * /proc/self/exe path before connecting.
 *
 * Usage: pm <socket_path> <work_bin_path> <lib_path>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static int check_exe_path(void)
{
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) { perror("readlink"); return 0; }
    buf[n] = '\0';
    printf("[pm] /proc/self/exe = %s\n", buf);
    if (strstr(buf, "memfd") || strstr(buf, "(deleted)")) {
        fprintf(stderr, "FAIL [pm]: /proc/self/exe is a memfd path\n");
        return 0;
    }
    if (!strstr(buf, "pm_sim")) {
        fprintf(stderr, "FAIL [pm]: /proc/self/exe doesn't contain 'pm_sim': %s\n", buf);
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
    if (pos > 0 && buf[pos-1] == '\n') buf[--pos] = '\0';
    return (int)pos;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: pm <socket_path> <work_bin> <lib_path>\n");
        return 1;
    }
    const char *sock_path = argv[1];
    const char *work_bin  = argv[2];
    const char *lib_path  = argv[3];

    if (!check_exe_path()) return 1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }
    printf("[pm] connected to grpc_daemon\n");

    /* Send INIT command */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "INIT %s %s\n", work_bin, lib_path);
    write(fd, cmd, strlen(cmd));
    printf("[pm] sent: INIT %s %s\n", work_bin, lib_path);

    /* Wait for response */
    char resp[64];
    recv_line(fd, resp, sizeof(resp));
    printf("[pm] received: %s\n", resp);

    close(fd);

    if (strcmp(resp, "OK") == 0) {
        printf("PASS: full multi-process chain succeeded\n");
        return 0;
    }
    fprintf(stderr, "FAIL: grpc_daemon returned '%s'\n", resp);
    return 1;
}
