// SPDX-License-Identifier: GPL-2.0
//
// vcache-mount — compiled, statically-linked mount helper for the shipped
// appliance.  It replaces the readable vcache-mount-ro / vcache-mount-rw shell
// scripts on client media: a `cat` of a shell script hands a rookie the entire
// architecture (fstype, options, overlay layout, module params), whereas this
// binary carries no commentary and, built `-static`, runs on any x86-64 box
// regardless of its glibc version.
//
// It performs exactly the two mounts the shell tool did, via the raw mount(2)
// syscall (no /bin/mount, no shell):
//
//     up  --rw  (default):  vcachefs(ro,decrypt) lower  +  overlayfs(rw) upper
//     up  --ro           :  vcachefs(ro,decrypt) only
//     down               :  umount overlay (if any) then the vcachefs lower
//
// The overlay layers live under <dirname(mp)>/.vcache-rw/<basename(mp)>/{dec,
// upper,work} (override with --state), matching vcache-mount-rw so the two are
// interchangeable during bring-up.  The writable upper is where the app's
// runtime lock/log/temp files land; the ciphertext tree is never written.
//
// Optional --insmod <path.ko> loads the module first (finit_module) with the
// production parameter string.  Normally the module is loaded at boot by the
// systemd unit and this is not needed.
//
// Build:  make -C kmod2/tools vcache-mount      (produces a static binary)
//   or:   gcc -O2 -static -o vcache-mount vcache-mount.c

#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define FSTYPE       "vcachefs"
#define OVL_FSTYPE   "overlay"
#define STATE_SUFFIX ".vcache-rw"
/* Production module parameter set by the reference deployment: on an
 * unauthorized data read, serve the lower ciphertext with the key trailer
 * stripped instead of a hard -EACCES. */
#define KO_PARAMS    "gate_passthrough_cipher=1"

static void die(const char *msg)
{
	fprintf(stderr, "vcache-mount: %s: %s\n", msg, strerror(errno));
	exit(1);
}
static void diex(const char *msg)
{
	fprintf(stderr, "vcache-mount: %s\n", msg);
	exit(1);
}

/* dirname/basename without mutating the caller's string. */
static void split_path(const char *p, char *dir, char *base, size_t n)
{
	const char *slash = strrchr(p, '/');
	if (!slash) {
		snprintf(dir, n, ".");
		snprintf(base, n, "%s", p);
		return;
	}
	size_t dl = (size_t)(slash - p);
	if (dl == 0) dl = 1;                 /* path was "/foo" -> dir "/" */
	if (dl >= n) dl = n - 1;
	memcpy(dir, p, dl);
	dir[dl] = '\0';
	snprintf(base, n, "%s", slash + 1);
}

static void default_state(const char *mp, char *out, size_t n)
{
	char dir[PATH_MAX], base[PATH_MAX];
	split_path(mp, dir, base, sizeof(dir));
	snprintf(out, n, "%s/%s/%s", dir, STATE_SUFFIX, base);
}

/* mkdir -p */
static int mkdirs(const char *path)
{
	char tmp[PATH_MAX];
	snprintf(tmp, sizeof(tmp), "%s", path);
	for (char *p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, 0700) && errno != EEXIST) return -1;
			*p = '/';
		}
	}
	if (mkdir(tmp, 0700) && errno != EEXIST) return -1;
	return 0;
}

static int is_dir(const char *p)
{
	struct stat st;
	return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static void load_module(const char *ko)
{
	int fd = open(ko, O_RDONLY | O_CLOEXEC);
	if (fd < 0) die("open module");
	if (syscall(SYS_finit_module, fd, KO_PARAMS, 0) != 0) {
		if (errno != EEXIST)          /* already loaded is fine */
			die("finit_module");
	}
	close(fd);
}

static void usage(void)
{
	fprintf(stderr,
		"usage:\n"
		"  vcache-mount up [--ro|--rw] [--passdata] [--passthrough <exts>]\n"
		"                  [--state <dir>] [--insmod <module.ko>] <encdir> <mountpoint>\n"
		"  vcache-mount down [--state <dir>] <mountpoint>\n");
	exit(2);
}

static int do_up(int argc, char **argv)
{
	int rw = 1, passdata = 0;
	const char *pass = NULL, *state = NULL, *ko = NULL, *enc = NULL, *mp = NULL;

	int i = 0;
	for (; i < argc && argv[i][0] == '-'; i++) {
		if      (!strcmp(argv[i], "--rw"))          rw = 1;
		else if (!strcmp(argv[i], "--ro"))          rw = 0;
		else if (!strcmp(argv[i], "--passdata"))    passdata = 1;
		else if (!strcmp(argv[i], "--passthrough")) pass  = argv[++i];
		else if (!strcmp(argv[i], "--state"))       state = argv[++i];
		else if (!strcmp(argv[i], "--insmod"))      ko    = argv[++i];
		else usage();
	}
	if (argc - i != 2) usage();
	enc = argv[i]; mp = argv[i + 1];

	if (!is_dir(enc)) diex("encdir is not a directory");
	if (!is_dir(mp))  diex("mountpoint is not a directory");

	if (ko) load_module(ko);

	/* vcachefs option string (data), read-only enforced via MS_RDONLY. */
	char data[512];
	size_t off = 0;
	data[0] = '\0';
	if (passdata)
		off += (size_t)snprintf(data + off, sizeof(data) - off, "%spassdata",
					off ? "," : "");
	if (pass)
		off += (size_t)snprintf(data + off, sizeof(data) - off, "%spassthrough=%s",
					off ? "," : "", pass);

	char st[PATH_MAX];
	if (!state) { default_state(mp, st, sizeof(st)); state = st; }

	if (!rw) {
		/* Read-only: a single vcachefs mount directly on the mountpoint. */
		if (mount(enc, mp, FSTYPE, MS_RDONLY, data[0] ? data : NULL) != 0)
			die("vcachefs mount");
		printf("vcache-mount: %s is a read-only decrypted view of %s\n", mp, enc);
		return 0;
	}

	/* Writable: vcachefs lower under state/dec, overlay rw on the mountpoint. */
	char dec[PATH_MAX], upper[PATH_MAX], work[PATH_MAX], ovl[PATH_MAX * 3];
	snprintf(dec,   sizeof(dec),   "%s/dec",   state);
	snprintf(upper, sizeof(upper), "%s/upper", state);
	snprintf(work,  sizeof(work),  "%s/work",  state);
	if (mkdirs(dec) || mkdirs(upper) || mkdirs(work)) die("mkdir state dirs");

	if (mount(enc, dec, FSTYPE, MS_RDONLY, data[0] ? data : NULL) != 0)
		die("vcachefs mount (lower)");

	snprintf(ovl, sizeof(ovl), "lowerdir=%s,upperdir=%s,workdir=%s",
		 dec, upper, work);
	if (mount(OVL_FSTYPE, mp, OVL_FSTYPE, 0, ovl) != 0) {
		int e = errno;
		umount2(dec, 0);
		errno = e;
		die("overlay mount");
	}
	printf("vcache-mount: %s is a writable decrypted view of %s\n", mp, enc);
	printf("  lower(ro,decrypt) = %s\n  upper(writable)   = %s\n", dec, upper);
	return 0;
}

static int do_down(int argc, char **argv)
{
	const char *state = NULL, *mp = NULL;
	int i = 0;
	for (; i < argc && argv[i][0] == '-'; i++) {
		if (!strcmp(argv[i], "--state")) state = argv[++i];
		else usage();
	}
	if (argc - i != 1) usage();
	mp = argv[i];

	char st[PATH_MAX], dec[PATH_MAX];
	if (!state) { default_state(mp, st, sizeof(st)); state = st; }
	snprintf(dec, sizeof(dec), "%s/dec", state);

	/* overlay (on the mountpoint) first, then the vcachefs lower. Tolerate a
	 * plain read-only mount where the mountpoint IS the vcachefs mount. */
	int failed = 0;
	if (umount2(mp, 0) != 0 && errno != EINVAL && errno != ENOENT) {
		fprintf(stderr, "vcache-mount: umount %s: %s\n", mp, strerror(errno));
		failed = 1;
	}
	if (umount2(dec, 0) != 0 && errno != EINVAL && errno != ENOENT) {
		/* EINVAL/ENOENT just means there was no separate lower (ro mode). */
		if (!failed) { /* only report if the overlay umount succeeded */ }
	}
	printf("vcache-mount: torn down %s\n", mp);
	printf("  app-written files persist at: %s/upper\n", state);
	return failed;
}

int main(int argc, char **argv)
{
	if (argc < 2) usage();
	if (!strcmp(argv[1], "up"))   return do_up(argc - 2, argv + 2);
	if (!strcmp(argv[1], "down")) return do_down(argc - 2, argv + 2);
	usage();
	return 2;
}
