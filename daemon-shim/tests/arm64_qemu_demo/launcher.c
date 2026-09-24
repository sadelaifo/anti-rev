/* arm64_qemu_demo launcher: encrypted exe that dlopens an encrypted
 * plugin (served by the daemon) and forks+execs a plain worker child.
 * Exercises the full antirev flow under qemu-user: memfd+fexecve,
 * shim injection, daemon fd-passing, encrypted dlopen+DT_NEEDED
 * closure, and a fork/exec child. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

int main(void)
{
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) exe[n] = '\0'; else snprintf(exe, sizeof(exe), "<readlink failed>");
    printf("[launcher] /proc/self/exe = %s\n", exe);

    void *h = dlopen("libplugin.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) { printf("[launcher] dlopen libplugin.so FAILED: %s\n", dlerror()); return 10; }
    int (*plugin_run)(void) = (int (*)(void)) dlsym(h, "plugin_run");
    if (!plugin_run) { printf("[launcher] dlsym plugin_run FAILED\n"); return 11; }
    int pr = plugin_run();
    printf("[launcher] plugin_run() = %d (expect 84)\n", pr);

    /* popen/system — exercise aarch64_extend_shim's fork+exec popen
     * replacement under qemu (glibc vfork-popen corrupts memfd procs). */
    int popen_ok = 0;
    FILE *fp = popen("echo popen_ok", "r");
    if (!fp) {
        printf("[launcher] popen FAILED\n");
    } else {
        char pbuf[128] = {0};
        if (fgets(pbuf, sizeof pbuf, fp)) pbuf[strcspn(pbuf, "\n")] = '\0';
        int pc = pclose(fp);
        printf("[launcher] popen read='%s' pclose_exit=%d (expect popen_ok / 0)\n",
               pbuf, WEXITSTATUS(pc));
        popen_ok = (strcmp(pbuf, "popen_ok") == 0);
    }
    int sysrc = system("exit 13");
    int sys_ok = (WIFEXITED(sysrc) && WEXITSTATUS(sysrc) == 13);
    printf("[launcher] system('exit 13') exit=%d (expect 13)\n", WEXITSTATUS(sysrc));

    /* ANTI_LoadProcess — aarch64_extend_shim hijack.  Resolved via
     * DT_NEEDED libmockanti.so (the real impl), but the LD_PRELOAD shim
     * interposes, sees ltrBin basename "pg.elf" is encrypted, fetches its
     * memfd from the daemon, rewrites ltrBin, then forwards to the real. */
    struct ANTI_ProcessInfo { const char *pgName; const char *ltrBin; };
    extern int ANTI_LoadProcess(void *);
    struct ANTI_ProcessInfo pgi = { "myPG", "pg.elf" };
    int alrc = ANTI_LoadProcess(&pgi);
    int anti_ok = (alrc == 55);
    printf("[launcher] ANTI_LoadProcess(pg.elf) rc=%d (expect 55)\n", alrc);

    pid_t pid = fork();
    if (pid == 0) {
        char *wargv[] = { "worker", "from-launcher", NULL };
        execv("./worker", wargv);
        perror("[launcher] execv worker");
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    int wec = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    printf("[launcher] worker exit = %d (expect 7)\n", wec);

    dlclose(h);
    printf("[launcher] summary: plugin=%d worker=%d popen=%d system=%d anti=%d\n",
           pr == 84, wec == 7, popen_ok, sys_ok, anti_ok);
    return (pr == 84 && wec == 7 && popen_ok && sys_ok && anti_ok) ? 0 : 20;
}
