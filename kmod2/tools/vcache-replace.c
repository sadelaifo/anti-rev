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
 * The control device gates on the CALLER being authorized (this binary is in
 * the module's compiled whitelist, or pinned by SHA-256), not on the operator.
 *
 * ---------------------------------------------------------------------------
 * cp CAMOUFLAGE MODE (invoked as "cp")
 * ---------------------------------------------------------------------------
 * When invoked through a symlink named `cp`, this behaves as a `cp` shim:
 *   - a PLAIN two-argument copy `cp SRC DST` (no options) whose destination
 *     directory is an in-place vcachefs mount  ->  do the live replace above;
 *   - ANYTHING ELSE  ->  exec the real coreutils cp (VR_ORIGIN_CP) unchanged.
 *
 * CRITICAL — the gate reads the RESOLVED exe (symlinks followed), so:
 *   (1) authorize THIS binary's real basename (e.g. "vr"), never "cp";
 *   (2) VR_ORIGIN_CP MUST be the plain coreutils cp (basename `cp`, NOT
 *       trusted by the gate) — the fallthrough is an execv() so a copy OUT of
 *       the mount runs under origin-cp's unauthorized identity and gets
 *       ciphertext, never this (authorized) binary's.
 *
 * ---------------------------------------------------------------------------
 * STRING OBFUSCATION
 * ---------------------------------------------------------------------------
 * This source is built through shared/obfstr_gen.py (see kmod2/tools/Makefile),
 * which rewrites every OBFSTR("...") literal into XOR-encrypted bytes before
 * gcc, so `strings` on the shipped binary reveals none of the vcachefs design
 * tokens — important because the camouflage binary is named `cp`.  Rules when
 * editing: keep OBFSTR() strings ASCII-only (the codegen crashes on multibyte
 * — use "--" not a real dash), and never assign an OBFSTR() result to a
 * variable for later use (its decoded buffer dies when the function returns) —
 * consume it inline in the same call.
 *
 * Residuals NOT hidden (accepted): VR_ORIGIN_CP's path (it is a deliberately
 * editable #define used verbatim in execv), and the "cp"/"vr" basenames.  Pick
 * a bland VR_ORIGIN_CP path if even that matters.
 *
 * Build: make -C kmod2/tools vcache-replace
 *   (needs ../module/arev_uapi.h and the obfstr header on the include path)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "arev_uapi.h"
#include "obfstr.h"	/* OBFSTR() — rewritten by shared/obfstr_gen.py */

/* ===========================================================================
 *   >>> EDIT ME: path to the real coreutils cp <<<
 * ---------------------------------------------------------------------------
 * When invoked as `cp` (camouflage mode), every copy that is NOT a live
 * container replace is handed off to the real cp at this path.  Set it to
 * wherever you moved the genuine coreutils cp (e.g. `mv /usr/bin/cp
 * /usr/bin/cp_origin`).
 *
 * It MUST be a binary whose gate identity (resolved basename) is NOT this
 * binary's and is NOT trusted by the gate — i.e. plain `cp`, kept/renamed
 * here — so a copy OUT of the mount falls through to it and the gate hands it
 * ciphertext.  Do NOT point this at another copy of this tool, and do NOT
 * leave it as a name the gate trusts.
 *
 * NOTE: this literal is not string-obfuscated (it is a #define used verbatim
 * in execv), so it is visible in `strings`.  Choose a bland path if that is a
 * concern.  A -DVR_ORIGIN_CP='"..."' build flag still overrides this, but the
 * source value below is the one that ships unless you deliberately override it.
 * =========================================================================== */
#ifndef VR_ORIGIN_CP
#define VR_ORIGIN_CP "/usr/bin/cp_origin"
#endif

/* argv[0] basenames that select cp-camouflage mode.  Invoking the tool by its
 * real name keeps the strict operator/test behaviour below.  (Innocuous names;
 * left un-obfuscated.) */
static const char *const cp_names[] = { "cp", NULL };

/* Neutral container magic (shared/protect.py FS_MAGIC / module ANTREV_MAGIC).
 * 8 bytes at file offset 0 of every encrypted container. */
static const unsigned char ANTREV_MAGIC[8] = {
	0xa7, 0x4c, 0x2e, 0x91, 0xd6, 0x3b, 0x08, 0x5f
};

static int usage(const char *me)
{
	fprintf(stderr,
		OBFSTR("usage: %s [--force] [--no-refresh] <new-ciphertext-file> <target-path-in-mount>\n"
		"   e.g. %s /media/usb/FOO.new /root/proj/bin/FOO\n"
		"\n"
		"Replaces one encrypted file on a live in-place vcachefs mount and\n"
		"refreshes it, without remounting (other subsystems keep running).\n"
		"--force       skips the ANTREV container-magic sanity check on the input.\n"
		"--no-refresh  installs the new file but skips the cache-refresh ioctl\n"
		"              (the live mount then keeps serving the OLD file until a\n"
		"              later refresh/remount -- for batched/advanced use).\n"),
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

/*
 * The actual live replace.  `target` must be an absolute path whose directory
 * is an in-place vcachefs mount.  Returns 0 on success, 1 on failure.
 */
static int do_replace(const char *me, const char *src_path, const char *target,
		      int force, int no_refresh)
{
	char *tdir_dup, *tbase_dup, *dir, *base;
	unsigned char magic[8];
	int srcfd, dev, dirfd, tmpfd, rc = 1;
	char tmpname[64];
	struct arev_cipher_arg a;

	/* 1. open + sanity-check the input ciphertext. */
	srcfd = open(src_path, O_RDONLY | O_CLOEXEC);
	if (srcfd < 0) {
		fprintf(stderr, OBFSTR("%s: open %s: %s\n"), me, src_path, strerror(errno));
		return 1;
	}
	if (!force) {
		if (read(srcfd, magic, sizeof(magic)) != (ssize_t)sizeof(magic) ||
		    memcmp(magic, ANTREV_MAGIC, sizeof(magic)) != 0) {
			fprintf(stderr,
				OBFSTR("%s: %s is not an encrypted container "
				"(bad magic); refusing.  Use --force to override.\n"),
				me, src_path);
			close(srcfd);
			return 1;
		}
	}

	/* split target into dir + basename (dirname/basename may mutate). */
	tdir_dup  = strdup(target);
	tbase_dup = strdup(target);
	if (!tdir_dup || !tbase_dup) {
		fprintf(stderr, OBFSTR("%s: out of memory\n"), me);
		goto out_src;
	}
	dir  = dirname(tdir_dup);
	base = basename(tbase_dup);

	/* 2. get an fd to the shadowed lower directory from the module.
	 *    OBFSTR("/dev/vcachefs") KEEP IN SYNC with AREV_DEV_PATH (arev_uapi.h);
	 *    inlined (not the macro) so the device name is XOR-hidden in strings. */
	dev = open(OBFSTR("/dev/vcachefs"), O_RDWR | O_CLOEXEC);
	if (dev < 0) {
		fprintf(stderr, OBFSTR("%s: cannot open control device: %s (is the module loaded?)\n"),
			me, strerror(errno));
		goto out_dups;
	}
	memset(&a, 0, sizeof(a));
	a.path     = (uint64_t)(uintptr_t)dir;
	a.path_len = (uint32_t)strlen(dir) + 1;
	a.out_fd   = -1;
	if (ioctl(dev, AREV_IOC_LOWER_DIRFD, &a) != 0) {
		fprintf(stderr, OBFSTR("%s: cannot resolve %s: %s%s\n"), me, dir, strerror(errno),
			errno == EACCES ? OBFSTR(" (not authorized)") :
			errno == EINVAL ? OBFSTR(" (not a managed directory)") : "");
		goto out_dev;
	}
	dirfd = a.out_fd;

	/* 3. write the new ciphertext to a temp in the lower dir, fsync, then
	 *    atomically rename it over the target basename (new lower inode).
	 *    Bland dotfile temp name so an `ls` during the window reveals nothing. */
	snprintf(tmpname, sizeof(tmpname), OBFSTR(".cp.%ld.tmp"),
		 (long)getpid());
	tmpfd = openat(dirfd, tmpname,
		       O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	if (tmpfd < 0) {
		fprintf(stderr, OBFSTR("%s: create temp in lower dir: %s\n"),
			me, strerror(errno));
		goto out_dirfd;
	}
	if (copy_all(srcfd, tmpfd) != 0) {
		fprintf(stderr, OBFSTR("%s: writing new ciphertext: %s\n"),
			me, strerror(errno));
		close(tmpfd);
		unlinkat(dirfd, tmpname, 0);
		goto out_dirfd;
	}
	if (fsync(tmpfd) != 0) {
		fprintf(stderr, OBFSTR("%s: fsync: %s\n"), me, strerror(errno));
		close(tmpfd);
		unlinkat(dirfd, tmpname, 0);
		goto out_dirfd;
	}
	close(tmpfd);
	if (renameat(dirfd, tmpname, dirfd, base) != 0) {
		fprintf(stderr, OBFSTR("%s: rename over %s: %s\n"), me, base, strerror(errno));
		unlinkat(dirfd, tmpname, 0);
		goto out_dirfd;
	}

	/* 4. drop the target's cached dentry so the next exec re-reads it. */
	if (no_refresh) {
		printf(OBFSTR("%s: installed %s (no refresh -- live mount still serves the old file)\n"),
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
			OBFSTR("%s: WARNING: %s was replaced but refresh failed: %s\n"
			"   the new file is in place; re-run `%s --force %s %s`\n"
			"   or remount to pick it up.\n"),
			me, target, strerror(errno), me, src_path, target);
		goto out_dirfd;
	}

	printf(OBFSTR("%s: replaced %s (live, no remount)\n"), me, target);
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

/* ---- cp-camouflage mode ------------------------------------------------- */

/* True iff `dir` is a directory backed by an in-place vcachefs mount (the
 * module answers LOWER_DIRFD for it).  Any failure — module not loaded, not a
 * vcachefs dir, not authorized — means "not ours", so the copy falls through
 * to the real cp.  (Detection via LOWER_DIRFD requires this binary to be
 * authorized; an unauthorized build therefore degrades to a plain cp.) */
static int is_vcachefs_dir(const char *dir)
{
	struct arev_cipher_arg a;
	int dev, ok;

	dev = open(OBFSTR("/dev/vcachefs"), O_RDWR | O_CLOEXEC);
	if (dev < 0)
		return 0;
	memset(&a, 0, sizeof(a));
	a.path     = (uint64_t)(uintptr_t)dir;
	a.path_len = (uint32_t)strlen(dir) + 1;
	a.out_fd   = -1;
	ok = (ioctl(dev, AREV_IOC_LOWER_DIRFD, &a) == 0);
	if (ok && a.out_fd >= 0)
		close(a.out_fd);
	close(dev);
	return ok;
}

/* Replace the process image with the real cp, original argv untouched, so the
 * copy runs under origin-cp's (unauthorized) gate identity. */
static int exec_origin(char **argv)
{
	execv(VR_ORIGIN_CP, argv);
	fprintf(stderr, OBFSTR("cp: cannot execute %s: %s\n"),
		VR_ORIGIN_CP, strerror(errno));
	return 127;
}

/*
 * Invoked as `cp`.  Intercept ONLY the exact, flagless two-operand form whose
 * destination resolves into an in-place vcachefs mount; everything else is a
 * verbatim exec of the real cp.
 */
static int cp_dispatch(int argc, char **argv)
{
	const char *pos[3];
	int npos = 0, seen_dd = 0, i;
	const char *src, *dst;
	char dst_dup[PATH_MAX], src_dup[PATH_MAX];
	char parent[PATH_MAX], parent_abs[PATH_MAX], target_abs[PATH_MAX];
	struct stat st;
	int dst_is_dir;
	char *d, *b;

	/* Collect operands.  Any option (before "--") we don't model -> real cp.
	 * This keeps the intercept to the single deliberate upgrade form
	 * `cp NEW /mount/FOO`; a real copy with flags is always just a copy. */
	for (i = 1; i < argc; i++) {
		if (!seen_dd && argv[i][0] == '-' && argv[i][1] != '\0') {
			if (strcmp(argv[i], "--") == 0) {
				seen_dd = 1;
				continue;
			}
			return exec_origin(argv);	/* has options */
		}
		if (npos >= 3)
			return exec_origin(argv);	/* >2 operands */
		pos[npos++] = argv[i];
	}
	if (npos != 2)
		return exec_origin(argv);		/* not SRC DST */

	src = pos[0];
	dst = pos[1];

	/* Resolve the real target file path: if DST is an existing directory or
	 * ends in '/', the target is DST/basename(SRC); else DST itself. */
	{
		size_t dl = strlen(dst);
		dst_is_dir = (dl > 0 && dst[dl - 1] == '/');
		if (!dst_is_dir && stat(dst, &st) == 0 && S_ISDIR(st.st_mode))
			dst_is_dir = 1;
	}

	if (dst_is_dir) {
		if (strlen(dst) >= sizeof(parent) ||
		    strlen(src) >= sizeof(src_dup))
			return exec_origin(argv);
		snprintf(parent, sizeof(parent), "%s", dst);
		snprintf(src_dup, sizeof(src_dup), "%s", src);
		b = basename(src_dup);
	} else {
		if (strlen(dst) >= sizeof(dst_dup))
			return exec_origin(argv);
		snprintf(parent, sizeof(parent), "%s", dst);
		d = dirname(parent);		/* mutates `parent` in place */
		memmove(parent, d, strlen(d) + 1);
		snprintf(dst_dup, sizeof(dst_dup), "%s", dst);
		b = basename(dst_dup);
	}

	/* Canonicalise the parent dir so the kernel-side path match is exact
	 * (and so a relative dest resolves unambiguously).  The dir must exist
	 * — it's a live mount — so realpath() succeeds; if it doesn't, it isn't
	 * our mount, so fall through. */
	if (!realpath(parent, parent_abs))
		return exec_origin(argv);

	if (!is_vcachefs_dir(parent_abs))
		return exec_origin(argv);		/* not a vcachefs mount */

	if (strlen(parent_abs) + 1 + strlen(b) >= sizeof(target_abs))
		return exec_origin(argv);
	snprintf(target_abs, sizeof(target_abs), "%s/%s", parent_abs, b);

	/* It's a protected in-place mount: do the live container replace. */
	return do_replace("cp", src, target_abs, /*force=*/0, /*no_refresh=*/0);
}

/* ---- entry -------------------------------------------------------------- */

static int invoked_as_cp(const char *argv0)
{
	char dup[PATH_MAX];
	const char *b;
	int i;

	snprintf(dup, sizeof(dup), "%s", argv0 ? argv0 : "");
	b = basename(dup);
	for (i = 0; cp_names[i]; i++)
		if (strcmp(b, cp_names[i]) == 0)
			return 1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *me = argv[0];
	int force = 0, no_refresh = 0, argi = 1;
	const char *src_path, *target;

	if (invoked_as_cp(argv[0]))
		return cp_dispatch(argc, argv);

	/* --- strict operator / test mode (real tool name) --------------- */
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
		fprintf(stderr, OBFSTR("%s: target must be an absolute path under the mount\n"), me);
		return 2;
	}
	return do_replace(me, src_path, target, force, no_refresh);
}
