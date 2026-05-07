/*
 * memfd_name test — verifies that every decrypted memfd visible in
 * /proc/self/fd carries a random per-process name rather than its
 * source artifact's basename.
 *
 * Without obfuscation the kernel-supplied symlink target of
 * /proc/<pid>/fd/N reveals which encrypted blob backs each fd
 * (e.g. /memfd:libfoo.so (deleted)).  The stub instead generates a
 * single random hex name per process and uses it for every memfd
 * (the protected exe, every daemon-decrypted lib, and the shim blob),
 * so the readlinks all look like /memfd:<hex> (deleted) and don't
 * identify which encrypted artifact each fd holds.
 *
 * What this test asserts about every memfd-backed entry under
 * /proc/self/fd:
 *   1. name is non-empty
 *   2. name contains only [0-9a-f] (or matches the "x<pid>" fallback)
 *   3. name does NOT contain any of the artifact-leak markers we'd
 *      see if the rename had been reverted ("antirev", ".so", ".elf")
 *   4. all memfd names within this process are identical (the random
 *      name is generated once per process and reused)
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>

static int is_hex_only(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        int hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return 0;
    }
    return 1;
}

static int is_pid_fallback(const char *s, size_t len)
{
    /* "x" followed by digits — the fallback when /dev/urandom failed. */
    if (len < 2 || s[0] != 'x') return 0;
    for (size_t i = 1; i < len; i++)
        if (!isdigit((unsigned char)s[i])) return 0;
    return 1;
}

int main(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) { perror("opendir /proc/self/fd"); return 1; }

    int memfds = 0, leaks = 0;
    char first_name[256] = { 0 };
    size_t first_len = 0;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);

        char target[4096];
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n < 0) continue;
        target[n] = '\0';

        const char *prefix = strstr(target, "memfd:");
        if (!prefix) continue;
        memfds++;

        const char *name = prefix + 6;                 /* past "memfd:" */
        const char *end  = strstr(name, " (deleted)");
        size_t len = end ? (size_t)(end - name) : strlen(name);

        printf("fd %s -> %s\n", e->d_name, target);

        if (len == 0) {
            fprintf(stderr, "  FAIL: empty memfd name\n");
            leaks++;
            continue;
        }

        /* Reject anything that looks like a leaked source-artifact name. */
        char buf[256];
        size_t copy = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
        memcpy(buf, name, copy);
        buf[copy] = '\0';

        if (strstr(buf, "antirev") != NULL ||
            strstr(buf, ".so")     != NULL ||
            strstr(buf, ".elf")    != NULL) {
            fprintf(stderr, "  FAIL: leaky memfd name '%s'\n", buf);
            leaks++;
            continue;
        }

        if (!is_hex_only(buf, copy) && !is_pid_fallback(buf, copy)) {
            fprintf(stderr, "  FAIL: memfd name '%s' is neither hex nor fallback\n", buf);
            leaks++;
            continue;
        }

        if (first_len == 0) {
            memcpy(first_name, buf, copy);
            first_name[copy] = '\0';
            first_len = copy;
        } else if (copy != first_len || memcmp(buf, first_name, copy) != 0) {
            fprintf(stderr, "  FAIL: memfd name '%s' differs from first '%s' "
                            "— per-process name should be uniform\n",
                    buf, first_name);
            leaks++;
        }
    }
    closedir(d);

    if (memfds == 0) {
        fprintf(stderr, "FAIL: no memfd-backed fds found — test not running under stub?\n");
        return 1;
    }
    if (leaks > 0) {
        fprintf(stderr, "FAIL: %d memfd(s) failed validation\n", leaks);
        return 1;
    }
    printf("PASS: %d memfd(s) all named '%s'\n", memfds, first_name);
    return 0;
}
