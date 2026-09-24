/*
 * realpath test — verifies that realpath(), canonicalize_file_name(), and
 * readlink() on /proc/self/exe all return the real on-disk path (not memfd)
 * after the antirev stub launches via fexecve().
 *
 * This catches the bug where glibc's realpath() uses an internal __readlink
 * that bypasses LD_PRELOAD, so intercepting readlink alone is insufficient.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

static int failures = 0;

static void check_path(const char *label, const char *path)
{
    if (!path) {
        fprintf(stderr, "FAIL [%s]: returned NULL\n", label);
        failures++;
        return;
    }
    printf("  %s = %s\n", label, path);

    if (strstr(path, "memfd") != NULL) {
        fprintf(stderr, "FAIL [%s]: contains 'memfd'\n", label);
        failures++;
    } else if (strstr(path, "(deleted)") != NULL) {
        fprintf(stderr, "FAIL [%s]: contains '(deleted)'\n", label);
        failures++;
    } else if (strlen(path) < 2 || path[0] != '/') {
        fprintf(stderr, "FAIL [%s]: not an absolute path\n", label);
        failures++;
    } else {
        printf("  OK [%s]\n", label);
    }
}

int main(void)
{
    char buf[PATH_MAX];
    char resolved[PATH_MAX];
    char pidpath[64];

    printf("=== realpath interception test ===\n");

    /* 1. readlink (baseline — should already work) */
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        check_path("readlink(/proc/self/exe)", buf);
    } else {
        fprintf(stderr, "FAIL [readlink]: returned %zd\n", len);
        failures++;
    }

    /* 2. realpath with caller-supplied buffer */
    char *rp = realpath("/proc/self/exe", resolved);
    check_path("realpath(/proc/self/exe, buf)", rp);

    /* 3. realpath with NULL (allocates) */
    rp = realpath("/proc/self/exe", NULL);
    check_path("realpath(/proc/self/exe, NULL)", rp);
    free(rp);

    /* 4. canonicalize_file_name (GNU extension) */
    rp = canonicalize_file_name("/proc/self/exe");
    check_path("canonicalize_file_name(/proc/self/exe)", rp);
    free(rp);

    /* 5. realpath on /proc/<pid>/exe */
    snprintf(pidpath, sizeof(pidpath), "/proc/%d/exe", (int)getpid());
    rp = realpath(pidpath, NULL);
    check_path("realpath(/proc/<pid>/exe, NULL)", rp);
    free(rp);

    /* 6. Verify consistency — all paths should match */
    char *path_readlink = NULL;
    char *path_realpath = NULL;
    char *path_canonicalize = NULL;

    len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) { buf[len] = '\0'; path_readlink = strdup(buf); }

    path_realpath = realpath("/proc/self/exe", NULL);
    path_canonicalize = canonicalize_file_name("/proc/self/exe");

    if (path_readlink && path_realpath) {
        if (strcmp(path_readlink, path_realpath) != 0) {
            fprintf(stderr, "FAIL: readlink='%s' != realpath='%s'\n",
                    path_readlink, path_realpath);
            failures++;
        } else {
            printf("  OK [readlink == realpath]\n");
        }
    }
    if (path_realpath && path_canonicalize) {
        if (strcmp(path_realpath, path_canonicalize) != 0) {
            fprintf(stderr, "FAIL: realpath='%s' != canonicalize='%s'\n",
                    path_realpath, path_canonicalize);
            failures++;
        } else {
            printf("  OK [realpath == canonicalize_file_name]\n");
        }
    }

    free(path_readlink);
    free(path_realpath);
    free(path_canonicalize);

    /* 7. Sanity: realpath on a normal path should still work */
    rp = realpath("/usr/bin/env", NULL);
    if (!rp) {
        fprintf(stderr, "FAIL: realpath(/usr/bin/env) returned NULL — passthrough broken\n");
        failures++;
    } else {
        printf("  OK [realpath(/usr/bin/env) = %s] (passthrough works)\n", rp);
        free(rp);
    }

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
