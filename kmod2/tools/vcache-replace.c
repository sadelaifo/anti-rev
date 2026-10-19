// SPDX-License-Identifier: GPL-2.0
/*
 * vcache-replace — live, per-file upgrade of one encrypted executable on an
 * IN-PLACE vcachefs mount, without a remount (so other running subsystems are
 * untouched).
 *
 * Operator model: the same as copying a new file from a USB stick over the old
 * one — except that an in-place vcachefs mount shadows the real ciphertext
 * directory and is read-only, so a plain `cp` to the mount path cannot reach
 * the file to replace.  This tool does the reach-around through the module:
 *
 *     vcache-replace <new-ciphertext-file>  <target-path-in-mount>
 *     e.g.  vcache-replace /media/usb/FOO.new  /root/proj/bin/FOO
 *
 * Steps (all encapsulated so the operator runs one command):
 *   1. sanity-check that <new-ciphertext-file> is an encrypted vcachefs
 *      container (ANTREV magic) so a wrong/plaintext file is caught early;
 *   2. ask /dev/vcachefs (AREV_IOC_LOWER_DIRFD) for an fd to the shadowed LOWER
 *      directory that backs the target's mount directory;
 *   3. write the new ciphertext to a temp file in that lower dir and
 *      atomically renameat() it over the target basename (new lower inode);
 *   4. ask /dev/vcachefs (AREV_IOC_REFRESH_PATH) to drop the target's cached
 *      dentry so the next exec re-reads the new file.
 *
 * Only CIPHERTEXT is ever written; no plaintext and no key cross the interface.
 * The control device gates on the CALLER being authorized (vcache-replace is in
 * the module's compiled whitelist, or signed), not on the operator — so a
 * non-technical operator just runs it.
 *
 * Build: make -C kmod2/tools vcache-replace   (needs ../module/arev_uapi.h on -I)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "arev_uapi.h"

/* Neutral container magic (shared/protect.py FS_MAGIC / module ANTREV_MAGIC).
 * 8 bytes at file offset 0 of every encrypted container. */
static const unsigned char ANTREV_MAGIC[8] = {
	0xa7, 0x4c, 0x2e, 0x91, 0xd6, 0x3b, 0x08, 0x5f
};

static int usage(const char *me)
{
	fprintf(stderr,
		"usage: %s [--force] [--no-refresh] <new-ciphertext-file> <target-path-in-mount>\n"
		"   e.g. %s /media/usb/FOO.new /root/proj/bin/FOO\n"
		"\n"
		"Replaces one encrypted file on a live in-place vcachefs mount and\n"
		"refreshes it, without remounting (other subsystems keep running).\n"
		"--force       skips the ANTREV container-magic sanity check on the input.\n"
		"--no-refresh  installs the new file but skips the cache-refresh ioctl\n"
		"              (the live mount then keeps serving the OLD file until a\n"
		"              later refresh/remount — for advanced/batched use).\n",
		me, me);
	return 2;
}

/* Copy the whole of `in` (from offset 0) into the already-open `outfd`. */
static int copy_all(int in, int outfd)
{
	char buf[1 << 16];
	ssize_t n;

	if (lseek(in, 0, SEEK_SET) == (off_t)-1)
		return -1;
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		char *p = buf;

		while (n > 0) {
			ssize_t w = write(outfd, p, n);

			if (w < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			p += w;
			n -= w;
		}
	}
	return n < 0 ? -1 : 0;
}

int main(int argc, char **argv)
{
	const char *me = argv[0];
	int force = 0, no_refresh = 0, argi = 1;
	const char *src_path, *target;
	char *tdir_dup, *tbase_dup, *dir, *base;
	unsigned char magic[8];
	int srcfd, dev, dirfd, tmpfd, rc = 1;
	char tmpname[64];
	struct arev_cipher_arg a;

	while (argi < argc && argv[argi][0] == '-' && argv[argi][1] == '-') {
		if (strcmp(argv[argi], "--force") == 0)
			force = 1;
		else if (strcmp(argv[argi], "--no-refresh") == 0)
			no_refresh = 1;
		else
			return usage(me);
		argi++;
	}
	if (argc - argi != 2)
		return usage(me);
	src_path = argv[argi];
	target   = argv[argi + 1];

	if (target[0] != '/') {
		fprintf(stderr, "%s: target must be an absolute path under the mount\n", me);
		return 2;
	}

	/* 1. open + sanity-check the input ciphertext. */
	srcfd = open(src_path, O_RDONLY | O_CLOEXEC);
	if (srcfd < 0) {
		fprintf(stderr, "%s: open %s: %s\n", me, src_path, strerror(errno));
		return 1;
	}
	if (!force) {
		if (read(srcfd, magic, sizeof(magic)) != (ssize_t)sizeof(magic) ||
		    memcmp(magic, ANTREV_MAGIC, sizeof(magic)) != 0) {
			fprintf(stderr,
				"%s: %s is not an encrypted vcachefs container "
				"(bad magic); refusing.  Use --force to override.\n",
				me, src_path);
			close(srcfd);
			return 1;
		}
	}

	/* split target into dir + basename (dirname/basename may mutate). */
	tdir_dup  = strdup(target);
	tbase_dup = strdup(target);
	if (!tdir_dup || !tbase_dup) {
		fprintf(stderr, "%s: out of memory\n", me);
		goto out_src;
	}
	dir  = dirname(tdir_dup);
	base = basename(tbase_dup);

	/* 2. get an fd to the shadowed lower directory from the module. */
	dev = open(AREV_DEV_PATH, O_RDWR | O_CLOEXEC);
	if (dev < 0) {
		fprintf(stderr, "%s: open %s: %s (is the module loaded?)\n",
			me, AREV_DEV_PATH, strerror(errno));
		goto out_dups;
	}
	memset(&a, 0, sizeof(a));
	a.path     = (uint64_t)(uintptr_t)dir;
	a.path_len = (uint32_t)strlen(dir) + 1;
	a.out_fd   = -1;
	if (ioctl(dev, AREV_IOC_LOWER_DIRFD, &a) != 0) {
		fprintf(stderr, "%s: LOWER_DIRFD %s: %s%s\n", me, dir, strerror(errno),
			errno == EACCES ? " (tool not authorized by the module)" :
			errno == EINVAL ? " (not a vcachefs directory)" : "");
		goto out_dev;
	}
	dirfd = a.out_fd;

	/* 3. write the new ciphertext to a temp in the lower dir, fsync, then
	 *    atomically rename it over the target basename (new lower inode). */
	snprintf(tmpname, sizeof(tmpname), ".vcache-replace.%ld.tmp",
		 (long)getpid());
	tmpfd = openat(dirfd, tmpname,
		       O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	if (tmpfd < 0) {
		fprintf(stderr, "%s: create temp in lower dir: %s\n",
			me, strerror(errno));
		goto out_dirfd;
	}
	if (copy_all(srcfd, tmpfd) != 0) {
		fprintf(stderr, "%s: writing new ciphertext: %s\n",
			me, strerror(errno));
		close(tmpfd);
		unlinkat(dirfd, tmpname, 0);
		goto out_dirfd;
	}
	if (fsync(tmpfd) != 0) {
		fprintf(stderr, "%s: fsync: %s\n", me, strerror(errno));
		close(tmpfd);
		unlinkat(dirfd, tmpname, 0);
		goto out_dirfd;
	}
	close(tmpfd);
	if (renameat(dirfd, tmpname, dirfd, base) != 0) {
		fprintf(stderr, "%s: rename over %s: %s\n", me, base, strerror(errno));
		unlinkat(dirfd, tmpname, 0);
		goto out_dirfd;
	}

	/* 4. drop the target's cached dentry so the next exec re-reads it. */
	if (no_refresh) {
		printf("%s: installed %s (no refresh — live mount still serves the old file)\n",
		       me, target);
		rc = 0;
		goto out_dirfd;
	}
	memset(&a, 0, sizeof(a));
	a.path     = (uint64_t)(uintptr_t)target;
	a.path_len = (uint32_t)strlen(target) + 1;
	a.out_fd   = -1;
	if (ioctl(dev, AREV_IOC_REFRESH_PATH, &a) != 0) {
		/* The file IS replaced, but the live cache is stale.  Tell the
		 * operator rather than silently leaving the old binary running. */
		fprintf(stderr,
			"%s: WARNING: %s was replaced but REFRESH failed: %s\n"
			"   the new file is in place; re-run `%s --force %s %s`\n"
			"   or remount to pick it up.\n",
			me, target, strerror(errno), me, src_path, target);
		goto out_dirfd;
	}

	printf("%s: replaced %s (live, no remount)\n", me, target);
	rc = 0;

out_dirfd:
	close(dirfd);
out_dev:
	close(dev);
out_dups:
	free(tdir_dup);
	free(tbase_dup);
out_src:
	close(srcfd);
	return rc;
}
