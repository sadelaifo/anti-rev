/* Mock of the business "real" ANTI_LoadProcess (e.g. provided by a
 * third-party lib).  Encrypted + DT_NEEDED into the launcher.  The
 * aarch64_extend_shim interposes ANTI_LoadProcess via LD_PRELOAD,
 * rewrites info->ltrBin to /proc/self/fd/N (the decrypted pg.elf memfd),
 * then calls THIS via dlsym(RTLD_NEXT). */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
extern char **environ;

struct ANTI_ProcessInfo { const char *pgName; const char *ltrBin; };

int ANTI_LoadProcess(void *info_raw)
{
    struct ANTI_ProcessInfo *info = info_raw;
    printf("[mockanti] real ANTI_LoadProcess pgName=%s ltrBin=%s\n",
           info->pgName ? info->pgName : "?",
           info->ltrBin ? info->ltrBin : "?");
    int fd = open(info->ltrBin, O_RDONLY);
    if (fd < 0) { perror("[mockanti] open ltrBin"); return -1; }
    pid_t p = fork();
    if (p == 0) {
        char *a[] = { "pg", NULL };
        fexecve(fd, a, environ);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    close(fd);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
