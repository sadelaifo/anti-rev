/*
 * open_patch — stand-in for a hot-patch injector.
 *
 * Opens a ".patch" file, fstat()s the opened fd, and reads it.  With
 * lrxd_<arch>.so preloaded the open() is redirected to the daemon's
 * decrypted memfd, so this sees plaintext (and the fstat size is the
 * plaintext size).  Without the shim it sees the on-disk ciphertext.
 *
 * Usage: open_patch <patch-path> <expected-plaintext>
 * Exit 0 only if the read content equals <expected-plaintext> and is not
 * ANTREV01 ciphertext.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <patch-path> <expected>\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    const char *expected = argv[2];

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 3; }

    struct stat st;
    if (fstat(fd, &st) != 0) { perror("fstat"); close(fd); return 4; }

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) { perror("read"); return 5; }
    buf[n] = '\0';

    if (n >= 8 && memcmp(buf, "ANTREV01", 8) == 0) {
        fprintf(stderr, "saw ciphertext (ANTREV01 magic)\n");
        return 6;
    }
    if (strcmp(buf, expected) != 0) {
        fprintf(stderr, "content mismatch\n got: [%s]\n exp: [%s]\n", buf, expected);
        return 7;
    }
    if ((size_t)st.st_size != strlen(expected)) {
        fprintf(stderr, "fstat size %lld != plaintext len %zu\n",
                (long long)st.st_size, strlen(expected));
        return 8;
    }
    printf("OK: decrypted patch read via shim (%zd bytes)\n", n);
    return 0;
}
