/*
 * path_stress — comprehensive path resolution test
 *
 * Tests every way a program might discover its own location or resolve
 * paths, to find which specific operation breaks under antirev protection
 * with LD_AUDIT active.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/auxv.h>
#include <dlfcn.h>

extern char *program_invocation_name;
extern char *program_invocation_short_name;

static int failures = 0;

static void ok(const char *label)
{
    printf("  OK   [%s]\n", label);
}

static void fail(const char *label, const char *detail)
{
    fprintf(stderr, "  FAIL [%s]: %s\n", label, detail);
    failures++;
}

/* ── 1. /proc/self/exe discovery ────────────────────────────────── */

static void test_readlink_self_exe(void)
{
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) { fail("readlink(/proc/self/exe)", "returned <= 0"); return; }
    buf[n] = '\0';
    if (strstr(buf, "memfd"))
        fail("readlink(/proc/self/exe)", buf);
    else
        ok("readlink(/proc/self/exe)");
}

static void test_readlinkat_self_exe(void)
{
    char buf[PATH_MAX];
    ssize_t n = readlinkat(AT_FDCWD, "/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) { fail("readlinkat(/proc/self/exe)", "returned <= 0"); return; }
    buf[n] = '\0';
    if (strstr(buf, "memfd"))
        fail("readlinkat(/proc/self/exe)", buf);
    else
        ok("readlinkat(/proc/self/exe)");
}

static void test_readlink_proc_pid_exe(void)
{
    char path[64], buf[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)getpid());
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) { fail("readlink(/proc/<pid>/exe)", "returned <= 0"); return; }
    buf[n] = '\0';
    if (strstr(buf, "memfd"))
        fail("readlink(/proc/<pid>/exe)", buf);
    else
        ok("readlink(/proc/<pid>/exe)");
}

/* ── 2. realpath variants ───────────────────────────────────────── */

static void test_realpath_self_exe_buf(void)
{
    char resolved[PATH_MAX];
    char *rp = realpath("/proc/self/exe", resolved);
    if (!rp) { fail("realpath(/proc/self/exe, buf)", strerror(errno)); return; }
    if (strstr(rp, "memfd"))
        fail("realpath(/proc/self/exe, buf)", rp);
    else
        ok("realpath(/proc/self/exe, buf)");
}

static void test_realpath_self_exe_null(void)
{
    char *rp = realpath("/proc/self/exe", NULL);
    if (!rp) { fail("realpath(/proc/self/exe, NULL)", strerror(errno)); return; }
    if (strstr(rp, "memfd"))
        fail("realpath(/proc/self/exe, NULL)", rp);
    else
        ok("realpath(/proc/self/exe, NULL)");
    free(rp);
}

static void test_realpath_proc_pid_exe(void)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)getpid());
    char *rp = realpath(path, NULL);
    if (!rp) { fail("realpath(/proc/<pid>/exe)", strerror(errno)); return; }
    if (strstr(rp, "memfd"))
        fail("realpath(/proc/<pid>/exe)", rp);
    else
        ok("realpath(/proc/<pid>/exe)");
    free(rp);
}

static void test_canonicalize_self_exe(void)
{
    char *rp = canonicalize_file_name("/proc/self/exe");
    if (!rp) { fail("canonicalize_file_name(/proc/self/exe)", strerror(errno)); return; }
    if (strstr(rp, "memfd"))
        fail("canonicalize_file_name(/proc/self/exe)", rp);
    else
        ok("canonicalize_file_name(/proc/self/exe)");
    free(rp);
}

/* ── 3. Passthrough — realpath on regular files/dirs ────────────── */

static void test_realpath_passthrough(const char *path, const char *label)
{
    char *rp = realpath(path, NULL);
    if (!rp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "returned NULL (%s)", strerror(errno));
        fail(label, msg);
    } else {
        printf("  OK   [%s] = %s\n", label, rp);
        free(rp);
    }
}

static void test_canonicalize_passthrough(const char *path, const char *label)
{
    char *rp = canonicalize_file_name(path);
    if (!rp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "returned NULL (%s)", strerror(errno));
        fail(label, msg);
    } else {
        printf("  OK   [%s] = %s\n", label, rp);
        free(rp);
    }
}

/* ── 4. Derive sibling path from exe location ──────────────────── */

static void test_sibling_file_access(void)
{
    /* Get exe directory via readlink + dirname */
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) { fail("sibling: readlink", "failed"); return; }
    buf[n] = '\0';

    char *dir = dirname(buf);

    /* Try to open the directory itself */
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "open(%s) failed: %s", dir, strerror(errno));
        fail("sibling: open(exe_dir)", msg);
    } else {
        ok("sibling: open(exe_dir)");
        close(fd);
    }

    /* Try to stat the exe itself */
    char exe_path[PATH_MAX];
    n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n > 0) {
        exe_path[n] = '\0';
        if (access(exe_path, F_OK) == 0)
            ok("sibling: access(exe_path)");
        else
            fail("sibling: access(exe_path)", strerror(errno));
    }
}

/* ── 5. Derive path via realpath + dirname + open ───────────────── */

static void test_realpath_then_open(void)
{
    char *rp = realpath("/proc/self/exe", NULL);
    if (!rp) { fail("realpath_then_open: realpath", strerror(errno)); return; }

    /* dirname may modify the string, so copy */
    char dir_buf[PATH_MAX];
    strncpy(dir_buf, rp, sizeof(dir_buf) - 1);
    dir_buf[sizeof(dir_buf) - 1] = '\0';
    char *dir = dirname(dir_buf);

    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "open(%s) failed: %s", dir, strerror(errno));
        fail("realpath_then_open: open(dir)", msg);
    } else {
        ok("realpath_then_open: open(dir)");
        close(fd);
    }
    free(rp);
}

/* ── 6. getauxval(AT_EXECFN) ───────────────────────────────────── */

static void test_getauxval_execfn(void)
{
    const char *fn = (const char *)getauxval(AT_EXECFN);
    if (!fn || strlen(fn) == 0) {
        fail("getauxval(AT_EXECFN)", "returned NULL or empty");
        return;
    }
    if (strstr(fn, "memfd"))
        fail("getauxval(AT_EXECFN)", fn);
    else
        printf("  OK   [getauxval(AT_EXECFN)] = %s\n", fn);
}

/* ── 7. program_invocation_name ─────────────────────────────────── */

static void test_program_invocation(void)
{
    if (!program_invocation_name || strlen(program_invocation_name) == 0) {
        fail("program_invocation_name", "NULL or empty");
    } else if (strstr(program_invocation_name, "memfd")) {
        fail("program_invocation_name", program_invocation_name);
    } else {
        printf("  OK   [program_invocation_name] = %s\n", program_invocation_name);
    }

    if (!program_invocation_short_name || strlen(program_invocation_short_name) == 0) {
        fail("program_invocation_short_name", "NULL or empty");
    } else if (strstr(program_invocation_short_name, "memfd")) {
        fail("program_invocation_short_name", program_invocation_short_name);
    } else {
        printf("  OK   [program_invocation_short_name] = %s\n",
               program_invocation_short_name);
    }
}

/* ── 8. argv[0] ─────────────────────────────────────────────────── */

static void test_argv0(const char *argv0)
{
    if (!argv0 || strlen(argv0) == 0) {
        fail("argv[0]", "NULL or empty");
    } else if (strstr(argv0, "memfd")) {
        fail("argv[0]", argv0);
    } else {
        printf("  OK   [argv[0]] = %s\n", argv0);
    }
}

/* ── 9. /proc/self/comm ─────────────────────────────────────────── */

static void test_proc_comm(void)
{
    char buf[64] = {0};
    int fd = open("/proc/self/comm", O_RDONLY);
    if (fd < 0) { fail("/proc/self/comm", strerror(errno)); return; }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) { fail("/proc/self/comm", "empty"); return; }
    /* strip trailing newline */
    if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = '\0';
    if (strstr(buf, "memfd"))
        fail("/proc/self/comm", buf);
    else
        printf("  OK   [/proc/self/comm] = %s\n", buf);
}

/* ── 10. /proc/self/cmdline ─────────────────────────────────────── */

static void test_proc_cmdline(void)
{
    char buf[4096] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) { fail("/proc/self/cmdline", strerror(errno)); return; }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) { fail("/proc/self/cmdline", "empty"); return; }
    /* argv[0] is the first NUL-terminated string */
    if (strstr(buf, "memfd"))
        fail("/proc/self/cmdline argv[0]", buf);
    else
        printf("  OK   [/proc/self/cmdline argv[0]] = %s\n", buf);
}

/* ── 11. readlink on a regular symlink (passthrough) ────────────── */

static void test_readlink_regular_symlink(void)
{
    /* Create a temp symlink and readlink it */
    char target[] = "/tmp/.antirev_test_target_XXXXXX";
    int fd = mkstemp(target);
    if (fd < 0) { fail("readlink_symlink: mkstemp", strerror(errno)); return; }
    close(fd);

    char link_path[PATH_MAX];
    snprintf(link_path, sizeof(link_path), "%s.link", target);
    if (symlink(target, link_path) < 0) {
        fail("readlink_symlink: symlink()", strerror(errno));
        unlink(target);
        return;
    }

    char buf[PATH_MAX];
    ssize_t n = readlink(link_path, buf, sizeof(buf) - 1);
    if (n <= 0) {
        fail("readlink(regular_symlink)", strerror(errno));
    } else {
        buf[n] = '\0';
        if (strcmp(buf, target) == 0)
            ok("readlink(regular_symlink)");
        else {
            char msg[512];
            snprintf(msg, sizeof(msg), "expected '%s', got '%s'", target, buf);
            fail("readlink(regular_symlink)", msg);
        }
    }

    /* Also test realpath on the symlink */
    char *rp = realpath(link_path, NULL);
    if (!rp) {
        fail("realpath(regular_symlink)", strerror(errno));
    } else {
        /* realpath should resolve to the target's canonical path */
        char *expected = realpath(target, NULL);
        if (expected && strcmp(rp, expected) == 0)
            ok("realpath(regular_symlink)");
        else
            fail("realpath(regular_symlink)", rp);
        free(expected);
        free(rp);
    }

    unlink(link_path);
    unlink(target);
}

/* ── 12. dladdr — find own library path ─────────────────────────── */

static void test_dladdr(void)
{
    Dl_info info;
    if (dladdr((void *)test_dladdr, &info)) {
        if (info.dli_fname) {
            if (strstr(info.dli_fname, "memfd"))
                fail("dladdr(self)", info.dli_fname);
            else
                printf("  OK   [dladdr(self)] = %s\n", info.dli_fname);
        } else {
            fail("dladdr(self)", "dli_fname is NULL");
        }
    } else {
        fail("dladdr(self)", "dladdr returned 0");
    }
}

/* ── 13. open(/proc/self/exe) — can we read our own binary? ────── */

static void test_open_self_exe(void)
{
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        fail("open(/proc/self/exe)", strerror(errno));
        return;
    }
    char buf[4];
    ssize_t n = read(fd, buf, 4);
    close(fd);
    if (n == 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F')
        ok("open(/proc/self/exe) → ELF header");
    else
        fail("open(/proc/self/exe)", "not valid ELF header");
}

/* ── 14. getcwd + relative paths ────────────────────────────────── */

static void test_getcwd_realpath(void)
{
    char *cwd = getcwd(NULL, 0);
    if (!cwd) { fail("getcwd()", strerror(errno)); return; }
    printf("  OK   [getcwd()] = %s\n", cwd);

    /* realpath(".") should equal getcwd */
    char *rp = realpath(".", NULL);
    if (!rp) {
        fail("realpath(\".\")", strerror(errno));
    } else if (strcmp(rp, cwd) == 0) {
        ok("realpath(\".\") == getcwd");
    } else {
        char msg[512];
        snprintf(msg, sizeof(msg), "'%s' != '%s'", rp, cwd);
        fail("realpath(\".\") == getcwd", msg);
    }
    free(rp);
    free(cwd);
}

/* ── main ───────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    (void)argc;
    printf("=== path_stress test ===\n\n");

    printf("-- /proc/self/exe discovery --\n");
    test_readlink_self_exe();
    test_readlinkat_self_exe();
    test_readlink_proc_pid_exe();

    printf("\n-- realpath variants --\n");
    test_realpath_self_exe_buf();
    test_realpath_self_exe_null();
    test_realpath_proc_pid_exe();
    test_canonicalize_self_exe();

    printf("\n-- passthrough (regular files) --\n");
    test_realpath_passthrough("/usr/bin/env", "realpath(/usr/bin/env)");
    test_realpath_passthrough("/etc/hosts", "realpath(/etc/hosts)");
    test_realpath_passthrough("/tmp", "realpath(/tmp)");
    test_realpath_passthrough(".", "realpath(\".\")");
    test_canonicalize_passthrough("/usr/bin/env", "canonicalize(/usr/bin/env)");

    printf("\n-- symlink passthrough --\n");
    test_readlink_regular_symlink();

    printf("\n-- derived paths (exe dir) --\n");
    test_sibling_file_access();
    test_realpath_then_open();

    printf("\n-- process identity --\n");
    test_getauxval_execfn();
    test_program_invocation();
    test_argv0(argv[0]);
    test_proc_comm();
    test_proc_cmdline();

    printf("\n-- misc --\n");
    test_dladdr();
    test_open_self_exe();
    test_getcwd_realpath();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
