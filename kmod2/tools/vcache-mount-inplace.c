// SPDX-License-Identifier: proprietary
//
// vcache-mount-inplace — compiled, statically-linked twin of vcache-mount.sh.
//
// Same UX as the shell orchestrator:
//     vcache-mount-inplace [--mode real|sim] {up|down|status|watch}
// but the logic is compiled, so a `cat`/`strings` of the shipped binary does
// NOT hand a rookie the architecture (comments never reach the binary; only a
// handful of terse log/option strings do).  This is the artifact you SHIP when
// the client runs the qemu/Docker sim stack — where a readable .sh would leak
// the whole design.
//
// It performs IN-PLACE vcachefs mounts (lower == mountpoint) plus tmpfs write
// layers, exactly like the shell tool.  Real mode operates on the host only;
// sim mode operates on the host AND, via docker inspect + setns() into the
// container's mount namespace, the slave software inside the sim container.
// "Only the executor differs": host runs the routines directly; container runs
// the SAME routines after setns(CLONE_NEWNS) redirects '/' to the container
// root (kernel mntns_install), so mount(2) lands inside the container.
//
// Config is baked in below and overridable by the same AREV_* env vars the
// shell tool honors (edit + rebuild, or export at runtime).
//
// Build:  make -C kmod2/tools vcache-mount-inplace   (static binary)
// Run as root (it re-execs with sudo -E; insmod + docker + mount need it).

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

/* ==========================================================================
 *  EDIT ME — per-deployment defaults (compiled in; each is also overridable
 *  at runtime by the matching AREV_* env var).  These string/number literals
 *  live in the source only; see the Makefile's obfuscation note for how they
 *  are kept out of `strings` in the shipped binary.
 * ========================================================================== */
#define CFG_KMOD_DIR      "/root/vcache/kmod2/module"  /* dir holding vcachefs.ko */
#define CFG_KO            ""            /* explicit .ko path; "" => KMOD_DIR/vcachefs.ko */
#define CFG_CONTAINER     "slave"       /* sim: business `docker run --name` */
#define CFG_WATCH_SECS    5             /* watch poll period (s) */
#define CFG_READY_MARKER  ""            /* file the installer touches last; "" => dir-nonempty heuristic */
#define CFG_AUTHZ_PATH    "/etc/authorized_apps.txt"
#define CFG_GATE_ENFORCE  1             /* 1 = enforce (dev .ko only) */
#define CFG_GATE_PASS     1             /* 1 = unauth read -> trailer-stripped cipher */
#define CFG_DEV_MODE      0             /* 1 ONLY for a dev .ko (AREV_DEV_MODE build) */
#define CFG_REQUIRE_SIG   0             /* 1 = signed allow-list (dev .ko) */
#define CFG_RELOAD        0             /* 1 = rmmod+insmod on 'up' */
#define CFG_VCACHE_OPTS   "ro,passdata"
#define CFG_STAGE_MODE    "auto"        /* auto | always | never (overlay-lower staging) */
#define CFG_STAGE_DIR     "/dev/shm/arev"
#define CFG_WRITE_BACKING "/run/vcache-write"
#define CFG_TMPFS_OPTS    "mode=0755,nosuid,nodev"

/* Lists — keep the trailing comma on every entry (empty macro => just NULL). */
#define CFG_MOUNTS        "/root/proj/bin", "/root/proj/lib",
#define CFG_ALLOW                            /* legacy model only; prefer per-exe sigs */
#define CFG_WRITE_DIRS                       /* e.g.  "/root/proj/bin|logs", */
#define CFG_WRITE_FILES                      /* e.g.  "/root/proj/bin|QtApplication.pid", */
/* ======================= end EDIT ME ====================================== */

/* ------------------------------------------------------------------ config */

static const char *KO;                 /* path to vcachefs.ko */
static const char *CONTAINER;          /* sim: business `docker run --name` */
static int         WATCH_INTERVAL;     /* watch poll period (s) */
static const char *READY_MARKER;       /* "" => non-empty-dir heuristic only */
static const char *AUTHZ_PATH;
static const char *AUTHZ_SIG_PATH;
static int         GATE_ENFORCE, GATE_PASSTHROUGH, DEV_MODE, GATE_REQUIRE_SIG;
static int         RELOAD_MODULE;
static const char *VCACHEFS_OPTS;      /* e.g. "ro,passdata" */
static const char *STAGE_MODE;         /* auto | always | never */
static const char *STAGE_DIR;          /* real-fs (tmpfs) staging root */
static const char *WRITE_BACKING;      /* tmpfs source for per-file binds */
static const char *TMPFS_OPTS;

static char      **MOUNTS;             /* NULL-terminated list of mount roots */
static char      **ALLOWL;             /* NULL-terminated allow-list basenames */
static char      **WRITE_DIRS;         /* "root|rel" entries */
static char      **WRITE_FILES;        /* "root|rel" entries */

static int         MODE_SIM;           /* 0 = real, 1 = sim */
static const char *ACTION;             /* up | down | status | watch */

/* current mount target */
static int         IN_CONTAINER;       /* 0 = host, 1 = container */
static pid_t       G_CPID;             /* container init pid (sim) */
static char        CTL_MM[64];         /* host /sys/class/misc/vcachefs/dev */

/* ------------------------------------------------------------- tiny helpers */

static void xlog(const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	fprintf(stderr, "[vc:%s%s] ", MODE_SIM ? "sim" : "real",
		IN_CONTAINER ? ":ctr" : "");
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static void die(const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	fprintf(stderr, "[vc:%s] ERROR: ", MODE_SIM ? "sim" : "real");
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

static const char *env_def(const char *k, const char *d)
{ const char *v = getenv(k); return (v && *v) ? v : d; }

static int env_int(const char *k, int d)
{ const char *v = getenv(k); return (v && *v) ? atoi(v) : d; }

/* Build a NULL-terminated list from a whitespace-separated env var, or copy
 * the compile-time default when unset. */
static char **list_from_env(const char *k, const char *const *def)
{
	const char *v = getenv(k);
	if (!v || !*v) {
		int n = 0; while (def[n]) n++;
		char **a = calloc(n + 1, sizeof *a);
		for (int i = 0; i < n; i++) a[i] = strdup(def[i]);
		return a;
	}
	char *copy = strdup(v);
	int cap = 8, n = 0;
	char **a = calloc(cap, sizeof *a);
	for (char *save, *t = strtok_r(copy, " \t\n", &save); t;
	     t = strtok_r(NULL, " \t\n", &save)) {
		if (n + 1 >= cap) { cap *= 2; a = realloc(a, cap * sizeof *a); }
		a[n++] = strdup(t);
	}
	a[n] = NULL;
	free(copy);
	return a;
}

static int list_len(char **a) { int n = 0; while (a && a[n]) n++; return n; }

/* ------------------------------------------------------------- subprocesses */

/* Run argv, capture stdout (trimmed of trailing newline). Returns exit code. */
static int run_capture(char *const argv[], char *out, size_t outsz)
{
	int pf[2];
	if (pipe(pf) != 0) return -1;
	fflush(NULL);
	pid_t p = fork();
	if (p == 0) {
		dup2(pf[1], 1);
		close(pf[0]); close(pf[1]);
		int nul = open("/dev/null", O_WRONLY);
		if (nul >= 0) dup2(nul, 2);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(pf[1]);
	size_t off = 0; ssize_t r;
	while (off < outsz - 1 && (r = read(pf[0], out + off, outsz - 1 - off)) > 0)
		off += r;
	out[off] = 0;
	close(pf[0]);
	int st; waitpid(p, &st, 0);
	while (off && (out[off - 1] == '\n' || out[off - 1] == '\r'))
		out[--off] = 0;
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Run argv to completion, inheriting stdio. Returns exit code. */
static int run_status(char *const argv[])
{
	fflush(NULL);
	pid_t p = fork();
	if (p == 0) { execvp(argv[0], argv); _exit(127); }
	int st; waitpid(p, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* ------------------------------------------------------------------- docker */

static pid_t container_pid(void)
{
	char buf[64];
	char *av[] = { "docker", "inspect", "-f", "{{.State.Pid}}",
		       (char *)CONTAINER, NULL };
	if (run_capture(av, buf, sizeof buf) != 0) return -1;
	long p = atol(buf);
	return p > 0 ? (pid_t)p : -1;
}

static int container_running(void)
{
	char buf[32];
	char *av[] = { "docker", "inspect", "-f", "{{.State.Running}}",
		       (char *)CONTAINER, NULL };
	if (run_capture(av, buf, sizeof buf) != 0) return 0;
	return strncmp(buf, "true", 4) == 0;
}

/* ------------------------------------------------------- module management */

static int module_loaded(void) { return access("/sys/module/vcachefs", F_OK) == 0; }

static char *insmod_params(char *buf, size_t n)
{
	if (DEV_MODE)
		snprintf(buf, n,
			 "gate_enforce=%d gate_require_sig=%d gate_passthrough_cipher=%d "
			 "authz_path=%s authz_sig_path=%s",
			 GATE_ENFORCE, GATE_REQUIRE_SIG, GATE_PASSTHROUGH,
			 AUTHZ_PATH, AUTHZ_SIG_PATH);
	else
		snprintf(buf, n, "gate_passthrough_cipher=%d", GATE_PASSTHROUGH);
	return buf;
}

static void finit_ko(void)
{
	int fd = open(KO, O_RDONLY);
	if (fd < 0) die("open %s: %s", KO, strerror(errno));
	char p[512];
	if (syscall(SYS_finit_module, fd, insmod_params(p, sizeof p), 0) != 0)
		die("finit_module: %s", strerror(errno));
	close(fd);
}

static void write_param(const char *name, const char *val)
{
	char path[256];
	snprintf(path, sizeof path, "/sys/module/vcachefs/parameters/%s", name);
	int fd = open(path, O_WRONLY);
	if (fd < 0) return;
	if (write(fd, val, strlen(val)) < 0) { /* best-effort */ }
	close(fd);
}

/* Host-side, once, after teardown — the module backs the kernel that serves
 * both host and (privileged, shared-kernel) container mounts. */
static void ensure_module(void)
{
	char p[512];
	if (!module_loaded()) {
		if (access(KO, F_OK) != 0)
			die("module not loaded and .ko missing: %s (set AREV_KO=)", KO);
		xlog("insmod vcachefs (%s)", insmod_params(p, sizeof p));
		finit_ko();
		return;
	}
	if (RELOAD_MODULE) {
		xlog("rmmod vcachefs (reload)");
		if (syscall(SYS_delete_module, "vcachefs", O_NONBLOCK) != 0)
			die("rmmod failed (module pinned by live mounts/mmap); "
			    "run 'down' and stop the app first");
		if (access(KO, F_OK) != 0) die(".ko missing for reload: %s", KO);
		xlog("insmod vcachefs");
		finit_ko();
		return;
	}
	/* keep loaded module; sync runtime-writable params */
	{ char v[8]; snprintf(v, sizeof v, "%d", GATE_PASSTHROUGH);
	  write_param("gate_passthrough_cipher", v); }
	if (DEV_MODE) {
		char v[8];
		snprintf(v, sizeof v, "%d", GATE_ENFORCE);
		write_param("gate_enforce", v);
		snprintf(v, sizeof v, "%d", GATE_REQUIRE_SIG);
		write_param("gate_require_sig", v);
	}
	xlog("vcachefs already loaded; params synced");
}

static void read_ctl_mm(void)
{
	CTL_MM[0] = 0;
	int fd = open("/sys/class/misc/vcachefs/dev", O_RDONLY);
	if (fd < 0) return;
	ssize_t r = read(fd, CTL_MM, sizeof CTL_MM - 1);
	if (r > 0) {
		CTL_MM[r] = 0;
		char *nl = strchr(CTL_MM, '\n'); if (nl) *nl = 0;
	}
	close(fd);
}

/* ------------------------------------------------------------ fs primitives */

static int is_dir(const char *p)
{ struct stat st; return stat(p, &st) == 0 && S_ISDIR(st.st_mode); }

static int mkdir_p(const char *path)
{
	char tmp[4096];
	snprintf(tmp, sizeof tmp, "%s", path);
	size_t len = strlen(tmp);
	if (len && tmp[len - 1] == '/') tmp[len - 1] = 0;
	for (char *p = tmp + 1; *p; p++)
		if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
	if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
	return 0;
}

/* Parse one /proc/self/mountinfo line into mountpoint + fstype. */
static int mi_line(char *line, char *mp, size_t mpn, char *fs, size_t fsn)
{
	char *fields[24]; int i = 0, dash = -1;
	for (char *save, *t = strtok_r(line, " ", &save); t;
	     t = strtok_r(NULL, " ", &save)) {
		if (i < 24) fields[i] = t;
		if (!strcmp(t, "-")) dash = i;
		i++;
	}
	if (i < 5 || dash < 0 || dash + 1 >= i) return -1;
	snprintf(mp, mpn, "%s", fields[4]);
	snprintf(fs, fsn, "%s", fields[dash + 1]);
	return 0;
}

/* Longest-prefix fstype of the mount backing 'path' (current mount ns). */
static void backing_fstype(const char *path, char *out, size_t n)
{
	out[0] = 0;
	FILE *f = fopen("/proc/self/mountinfo", "r");
	if (!f) return;
	char line[8192]; size_t best = 0;
	while (fgets(line, sizeof line, f)) {
		char mp[4096], fs[64], copy[8192];
		snprintf(copy, sizeof copy, "%s", line);
		if (mi_line(copy, mp, sizeof mp, fs, sizeof fs) != 0) continue;
		size_t l = strlen(mp);
		int match = !strcmp(mp, path) ||
			    (!strcmp(mp, "/") ) ||
			    (strncmp(path, mp, l) == 0 && path[l] == '/');
		if (match && l >= best) { best = l; snprintf(out, n, "%s", fs); }
	}
	fclose(f);
}

static int is_mountpoint(const char *path)
{
	FILE *f = fopen("/proc/self/mountinfo", "r");
	if (!f) return 0;
	char line[8192]; int found = 0;
	while (fgets(line, sizeof line, f)) {
		char mp[4096], fs[64], copy[8192];
		snprintf(copy, sizeof copy, "%s", line);
		if (mi_line(copy, mp, sizeof mp, fs, sizeof fs) != 0) continue;
		if (!strcmp(mp, path)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

/* Collect mountpoints == root or under root/, deepest-first. Caller frees. */
static int collect_submounts(const char *root, char ***out)
{
	FILE *f = fopen("/proc/self/mountinfo", "r");
	*out = NULL;
	if (!f) return 0;
	char line[8192];
	int cap = 8, n = 0;
	char **arr = calloc(cap, sizeof *arr);
	size_t rl = strlen(root);
	while (fgets(line, sizeof line, f)) {
		char mp[4096], fs[64], copy[8192];
		snprintf(copy, sizeof copy, "%s", line);
		if (mi_line(copy, mp, sizeof mp, fs, sizeof fs) != 0) continue;
		if (!strcmp(mp, root) ||
		    (strncmp(mp, root, rl) == 0 && mp[rl] == '/')) {
			if (n + 1 >= cap) { cap *= 2; arr = realloc(arr, cap * sizeof *arr); }
			arr[n++] = strdup(mp);
		}
	}
	fclose(f);
	/* sort deepest-first (longest path) */
	for (int a = 0; a < n; a++)
		for (int b = a + 1; b < n; b++)
			if (strlen(arr[b]) > strlen(arr[a])) {
				char *t = arr[a]; arr[a] = arr[b]; arr[b] = t;
			}
	*out = arr;
	return n;
}

/* Split "ro,passdata,nosuid" into MS_* flags + fs-specific data string. */
static unsigned long opts_split(const char *opts, char *data, size_t dn)
{
	unsigned long fl = 0;
	data[0] = 0;
	char tmp[256];
	snprintf(tmp, sizeof tmp, "%s", opts);
	for (char *save, *t = strtok_r(tmp, ",", &save); t;
	     t = strtok_r(NULL, ",", &save)) {
		if      (!strcmp(t, "ro"))     fl |= MS_RDONLY;
		else if (!strcmp(t, "rw"))     ; /* default */
		else if (!strcmp(t, "nosuid")) fl |= MS_NOSUID;
		else if (!strcmp(t, "nodev"))  fl |= MS_NODEV;
		else if (!strcmp(t, "noexec")) fl |= MS_NOEXEC;
		else {
			if (data[0]) strncat(data, ",", dn - strlen(data) - 1);
			strncat(data, t, dn - strlen(data) - 1);
		}
	}
	return fl;
}

static void rm_rf(const char *path)
{ char *av[] = { "rm", "-rf", (char *)path, NULL }; run_status(av); }

/* --------------------------------------------------- per-target operations */
/* These run IN the target's mount namespace (host: current process; container:
 * a forked child after setns).  Absolute paths therefore resolve correctly in
 * whichever namespace we are in. */

static const char *spec_root(const char *spec, char *buf, size_t n)
{ const char *bar = strchr(spec, '|');
  size_t l = bar ? (size_t)(bar - spec) : strlen(spec);
  if (l >= n) l = n - 1; memcpy(buf, spec, l); buf[l] = 0; return buf; }

static const char *spec_rel(const char *spec)
{ const char *bar = strchr(spec, '|'); return bar ? bar + 1 : ""; }

static int do_up(void)
{
	int n = list_len(MOUNTS);
	char **lowers = calloc(n + 1, sizeof *lowers);

	/* 0) choose LOWER per mount: in-place, or staged when lower is overlay. */
	for (int i = 0; i < n; i++) {
		const char *root = MOUNTS[i];
		if (!is_dir(root)) die("not a directory: %s", root);
		if (is_mountpoint(root)) die("already mounted: %s (run 'down' first)", root);
		int stage = 0;
		if      (!strcmp(STAGE_MODE, "always")) stage = 1;
		else if (!strcmp(STAGE_MODE, "never"))  stage = 0;
		else {
			char ft[64]; backing_fstype(root, ft, sizeof ft);
			stage = (!strcmp(ft, "overlay") || !strcmp(ft, "overlayfs"));
		}
		if (stage) {
			char tag[4096], *lower = malloc(4096);
			snprintf(tag, sizeof tag, "%s", root + (root[0] == '/'));
			for (char *p = tag; *p; p++) if (*p == '/') *p = '_';
			snprintf(lower, 4096, "%s/%s", STAGE_DIR, tag);
			rm_rf(lower);
			mkdir_p(lower);
			xlog("stage (overlay lower) %s -> %s", root, lower);
			char src[4096];
			snprintf(src, sizeof src, "%s/.", root);
			char *av[] = { "cp", "-a", src, lower, NULL };
			if (run_status(av) != 0) die("stage copy failed: %s", root);
			lowers[i] = lower;
		} else {
			lowers[i] = strdup(root);
		}
	}

	/* 1) seed write anchors in the LOWER before mounting over it. */
	for (int i = 0; WRITE_DIRS[i]; i++) {
		char root[4096]; spec_root(WRITE_DIRS[i], root, sizeof root);
		for (int j = 0; j < n; j++) if (!strcmp(MOUNTS[j], root)) {
			char p[4096];
			snprintf(p, sizeof p, "%s/%s", lowers[j], spec_rel(WRITE_DIRS[i]));
			mkdir_p(p);
		}
	}
	for (int i = 0; WRITE_FILES[i]; i++) {
		char root[4096]; spec_root(WRITE_FILES[i], root, sizeof root);
		for (int j = 0; j < n; j++) if (!strcmp(MOUNTS[j], root)) {
			char p[4096], d[4096];
			snprintf(p, sizeof p, "%s/%s", lowers[j], spec_rel(WRITE_FILES[i]));
			snprintf(d, sizeof d, "%s", p);
			char *sl = strrchr(d, '/'); if (sl) { *sl = 0; mkdir_p(d); }
			if (access(p, F_OK) != 0) { int fd = open(p, O_CREAT | O_WRONLY, 0644); if (fd >= 0) close(fd); }
		}
	}

	/* 2) vcachefs: lower -> mountpoint (in place or staged). */
	for (int i = 0; i < n; i++) {
		char data[128];
		unsigned long fl = opts_split(VCACHEFS_OPTS, data, sizeof data);
		xlog("vcachefs %s -> %s (%s)", lowers[i], MOUNTS[i], VCACHEFS_OPTS);
		if (mount(lowers[i], MOUNTS[i], "vcachefs", fl,
			  data[0] ? data : NULL) != 0)
			die("mount vcachefs %s: %s", MOUNTS[i], strerror(errno));
	}

	/* 3) anonymous tmpfs over each known write directory. */
	for (int i = 0; WRITE_DIRS[i]; i++) {
		char root[4096]; spec_root(WRITE_DIRS[i], root, sizeof root);
		char mp[4096], data[128];
		snprintf(mp, sizeof mp, "%s/%s", root, spec_rel(WRITE_DIRS[i]));
		unsigned long fl = opts_split(TMPFS_OPTS, data, sizeof data);
		xlog("tmpfs %s", mp);
		if (mount("tmpfs", mp, "tmpfs", fl, data[0] ? data : NULL) != 0)
			die("tmpfs %s: %s", mp, strerror(errno));
	}

	/* 4) per-file writable binds (tmpfs-backed source). */
	if (WRITE_FILES[0]) {
		char data[128];
		unsigned long fl = opts_split(TMPFS_OPTS, data, sizeof data);
		mkdir_p(WRITE_BACKING);
		if (!is_mountpoint(WRITE_BACKING) &&
		    mount("tmpfs", WRITE_BACKING, "tmpfs", fl,
			  data[0] ? data : NULL) != 0)
			die("tmpfs %s: %s", WRITE_BACKING, strerror(errno));
		for (int i = 0; WRITE_FILES[i]; i++) {
			char root[4096]; spec_root(WRITE_FILES[i], root, sizeof root);
			const char *rel = spec_rel(WRITE_FILES[i]);
			char tag[4096], srcp[4096], dst[4096];
			snprintf(tag, sizeof tag, "%s/%s", root + (root[0] == '/'), rel);
			for (char *p = tag; *p; p++) if (*p == '/') *p = '_';
			snprintf(srcp, sizeof srcp, "%s/%s", WRITE_BACKING, tag);
			int fd = open(srcp, O_CREAT | O_WRONLY, 0644); if (fd >= 0) close(fd);
			snprintf(dst, sizeof dst, "%s/%s", root, rel);
			xlog("bind %s -> %s", srcp, dst);
			if (mount(srcp, dst, NULL, MS_BIND, NULL) != 0)
				die("bind %s: %s", dst, strerror(errno));
		}
	}
	xlog("up complete");
	return 0;
}

static int do_down(void)
{
	for (int i = 0; MOUNTS[i]; i++) {
		char **subs; int m = collect_submounts(MOUNTS[i], &subs);
		for (int j = 0; j < m; j++) {
			if (umount2(subs[j], 0) != 0 &&
			    umount2(subs[j], MNT_DETACH) != 0)
				xlog("busy: %s", subs[j]);
			free(subs[j]);
		}
		free(subs);
	}
	if (is_mountpoint(WRITE_BACKING))
		if (umount2(WRITE_BACKING, 0) != 0) umount2(WRITE_BACKING, MNT_DETACH);
	if (STAGE_DIR && *STAGE_DIR) rm_rf(STAGE_DIR);
	xlog("down complete");
	return 0;
}

static int do_status(void)
{
	for (int i = 0; MOUNTS[i]; i++) {
		if (is_mountpoint(MOUNTS[i])) {
			printf("  %-22s mounted\n", MOUNTS[i]);
			char **subs; int m = collect_submounts(MOUNTS[i], &subs);
			for (int j = m - 1; j >= 0; j--) { printf("      %s\n", subs[j]); free(subs[j]); }
			free(subs);
		} else {
			printf("  %-22s not-mounted\n", MOUNTS[i]);
		}
	}
	fflush(stdout);
	return 0;
}

static int write_allowlist(void)
{
	if (!DEV_MODE) {                       /* production .ko: no list at all */
		unlink(AUTHZ_PATH); unlink(AUTHZ_SIG_PATH);
		return 0;
	}
	if (!GATE_ENFORCE) { xlog("gate off; skipping allow-list"); return 0; }
	if (GATE_REQUIRE_SIG) {
		if (access(AUTHZ_PATH, R_OK) == 0 && access(AUTHZ_SIG_PATH, R_OK) == 0)
			xlog("signed mode: using pre-signed %s (+ .p7s)", AUTHZ_PATH);
		else
			xlog("WARNING: signed mode but list/.p7s missing -> gate DENIES");
		return 0;
	}
	if (list_len(ALLOWL) == 0) {
		xlog("ALLOW empty -> per-exe/whitelist gating; removing stale %s", AUTHZ_PATH);
		unlink(AUTHZ_PATH); unlink(AUTHZ_SIG_PATH);
		return 0;
	}
	FILE *f = fopen(AUTHZ_PATH, "w");
	if (!f) die("cannot write %s: %s", AUTHZ_PATH, strerror(errno));
	for (int i = 0; ALLOWL[i]; i++) fprintf(f, "%s\n", ALLOWL[i]);
	fclose(f);
	chmod(AUTHZ_PATH, 0644);
	xlog("wrote %s", AUTHZ_PATH);
	return 0;
}

static int ensure_ctldev(void)
{
	if (!CTL_MM[0]) { xlog("no /sys/class/misc/vcachefs/dev; qemu gate unavailable"); return 0; }
	if (access("/dev/vcachefs", F_OK) == 0) return 0;
	unsigned maj, min;
	if (sscanf(CTL_MM, "%u:%u", &maj, &min) != 2) return 0;
	xlog("mknod /dev/vcachefs c %u %u", maj, min);
	if (mknod("/dev/vcachefs", S_IFCHR | 0666, makedev(maj, min)) != 0)
		xlog("WARNING: mknod /dev/vcachefs: %s", strerror(errno));
	else
		chmod("/dev/vcachefs", 0666);
	return 0;
}

/* readiness: every mount root exists + non-empty, and (if set) READY_MARKER. */
static int target_ready(void)
{
	for (int i = 0; MOUNTS[i]; i++) {
		if (!is_dir(MOUNTS[i])) return 0;
		DIR *d = opendir(MOUNTS[i]);
		if (!d) return 0;
		int has = 0; struct dirent *e;
		while ((e = readdir(d)))
			if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) { has = 1; break; }
		closedir(d);
		if (!has) return 0;
	}
	if (READY_MARKER && *READY_MARKER && access(READY_MARKER, F_OK) != 0)
		return 0;
	return 1;
}

/* full per-target "up" body (runs in target ns) */
static int target_up_body(void)
{
	write_allowlist();
	do_up();
	ensure_ctldev();
	do_status();
	return 0;
}

/* ---------------------------------------------------------- target executor */

/* Run fn() in the current target: host => directly; container => fork + setns
 * into the container's mount namespace, so the SAME routine's mount(2)/mkdir/…
 * land inside the container.  Returns fn()'s status (child exit code). */
static int run_in_target(int (*fn)(void))
{
	if (!IN_CONTAINER) return fn();
	char ns[64];
	snprintf(ns, sizeof ns, "/proc/%d/ns/mnt", (int)G_CPID);
	fflush(NULL);
	pid_t c = fork();
	if (c == 0) {
		int fd = open(ns, O_RDONLY);
		if (fd < 0) { fprintf(stderr, "open %s: %s\n", ns, strerror(errno)); _exit(3); }
		if (setns(fd, CLONE_NEWNS) != 0) { fprintf(stderr, "setns: %s\n", strerror(errno)); _exit(4); }
		close(fd);
		_exit(fn() & 0xff);
	}
	int st; waitpid(c, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* target present? host: always; container: only when running. */
static int target_present(void)
{ return !IN_CONTAINER || container_running(); }

/* Set the current target (updates G_CPID for the container). */
static void set_target(int container)
{
	IN_CONTAINER = container;
	if (container) G_CPID = container_pid();
}

/* --------------------------------------------------------------- dispatch */

/* Iterate the mode's targets: host always; +container in sim.  cb gets the
 * container flag (0/1). */
static void for_each_target(void (*cb)(int))
{
	cb(0);
	if (MODE_SIM) cb(1);
}

static void up_one(int container)
{
	set_target(container);
	if (!target_present()) {
		xlog("[%s] container '%s' not running -> skipped (start it, or use 'watch')",
		     container ? "ctr" : "host", CONTAINER);
		return;
	}
	if (run_in_target(target_ready) != 1) {
		xlog("[%s] ciphertext NOT ready (a mount root is empty%s) -> not mounting",
		     container ? "ctr" : "host",
		     (READY_MARKER && *READY_MARKER) ? " or marker missing" : "");
		return;
	}
	xlog("[%s] mounting", container ? "ctr" : "host");
	run_in_target(target_up_body);
}

static void down_one(int container)
{
	set_target(container);
	if (!target_present()) {
		xlog("[%s] not running; its mounts vanished with it", container ? "ctr" : "host");
		return;
	}
	xlog("[%s] tearing down", container ? "ctr" : "host");
	run_in_target(do_down);
}

static void down_pre(int container)  /* teardown pass before module (re)load */
{
	set_target(container);
	if (!target_present()) return;
	run_in_target(do_down);
}

static void status_one(int container)
{
	set_target(container);
	if (!target_present()) { xlog("[%s] not running", container ? "ctr" : "host"); return; }
	xlog("[%s] status:", container ? "ctr" : "host");
	run_in_target(do_status);
}

static void run_up_sequence(void)
{
	for_each_target(down_pre);       /* live mounts pin the module */
	IN_CONTAINER = 0; ensure_module(); read_ctl_mm();
	for_each_target(up_one);
	xlog("up complete. Watch for EROFS -> add paths to WRITE_DIRS/WRITE_FILES and re-run 'up'.");
}

static void do_watch(void)
{
	/* host first: mount immediately + load module.  target_up_body already
	 * runs write_allowlist in the correct ns, so we do not call it here. */
	set_target(0);
	run_in_target(do_down);
	ensure_module(); read_ctl_mm();
	run_in_target(target_up_body);

	if (!MODE_SIM) { xlog("real mode: no container to watch; done"); return; }

	xlog("watch: polling for '%s' every %ds (idle until it appears)",
	     CONTAINER, WATCH_INTERVAL);
	int prev = 0;   /* 0 down, 1 waiting, 2 up */
	for (;;) {
		set_target(1);
		if (container_running()) {
			if (run_in_target(target_ready) == 1) {
				if (prev != 2) {
					xlog("container up + ready -> mounting");
					run_in_target(do_down);
					run_in_target(target_up_body);
					prev = 2;
				}
			} else if (prev != 1) {
				xlog("container up but ciphertext NOT ready; waiting for install copy");
				prev = 1;
			}
		} else {
			prev = 0;
		}
		struct timespec ts = { WATCH_INTERVAL, 0 };
		nanosleep(&ts, NULL);
	}
}

/* --------------------------------------------------------------- bootstrap */

static void become_root(int argc, char **argv)
{
	if (geteuid() == 0) return;
	char self[4096];
	ssize_t r = readlink("/proc/self/exe", self, sizeof self - 1);
	if (r < 0) { perror("readlink"); exit(1); }
	self[r] = 0;
	char **na = calloc(argc + 3, sizeof *na);
	int i = 0;
	na[i++] = "sudo"; na[i++] = "-E"; na[i++] = self;
	for (int j = 1; j < argc; j++) na[i++] = argv[j];
	na[i] = NULL;
	execvp("sudo", na);
	perror("execvp sudo"); exit(1);
}

static const char *const DEF_MOUNTS[] = { CFG_MOUNTS NULL };
static const char *const DEF_ALLOW[]  = { CFG_ALLOW NULL };
static const char *const DEF_WDIRS[]  = { CFG_WRITE_DIRS NULL };
static const char *const DEF_WFILES[] = { CFG_WRITE_FILES NULL };

static void load_config(void)
{
	static char ko_buf[4096], sig_buf[4096];
	const char *kmod_dir = env_def("AREV_KMOD_DIR", CFG_KMOD_DIR);
	const char *ko = getenv("AREV_KO");
	if (!ko || !*ko) ko = CFG_KO;                 /* baked default (may be empty) */
	if (!ko || !*ko) { snprintf(ko_buf, sizeof ko_buf, "%s/vcachefs.ko", kmod_dir); ko = ko_buf; }
	KO = ko;

	CONTAINER       = env_def("AREV_CONTAINER", CFG_CONTAINER);
	WATCH_INTERVAL  = env_int("AREV_WATCH_INTERVAL", CFG_WATCH_SECS);
	READY_MARKER    = env_def("AREV_READY_MARKER", CFG_READY_MARKER);
	AUTHZ_PATH      = env_def("AREV_AUTHZ_PATH", CFG_AUTHZ_PATH);
	const char *sig = getenv("AREV_AUTHZ_SIG_PATH");
	if (!sig || !*sig) { snprintf(sig_buf, sizeof sig_buf, "%s.p7s", AUTHZ_PATH); sig = sig_buf; }
	AUTHZ_SIG_PATH  = sig;
	GATE_ENFORCE    = env_int("AREV_GATE_ENFORCE", CFG_GATE_ENFORCE);
	GATE_PASSTHROUGH= env_int("AREV_GATE_PASSTHROUGH", CFG_GATE_PASS);
	DEV_MODE        = env_int("AREV_DEV", CFG_DEV_MODE);
	GATE_REQUIRE_SIG= env_int("AREV_GATE_REQUIRE_SIG", CFG_REQUIRE_SIG);
	RELOAD_MODULE   = env_int("AREV_RELOAD_MODULE", CFG_RELOAD);
	VCACHEFS_OPTS   = env_def("AREV_VCACHEFS_OPTS", CFG_VCACHE_OPTS);
	STAGE_MODE      = env_def("AREV_STAGE_LOWER", CFG_STAGE_MODE);
	STAGE_DIR       = env_def("AREV_STAGE_DIR", CFG_STAGE_DIR);
	WRITE_BACKING   = env_def("AREV_WRITE_BACKING", CFG_WRITE_BACKING);
	TMPFS_OPTS      = env_def("AREV_TMPFS_OPTS", CFG_TMPFS_OPTS);

	MOUNTS      = list_from_env("AREV_MOUNTS", DEF_MOUNTS);
	ALLOWL      = list_from_env("AREV_ALLOW", DEF_ALLOW);
	WRITE_DIRS  = list_from_env("AREV_WRITE_DIRS", DEF_WDIRS);
	WRITE_FILES = list_from_env("AREV_WRITE_FILES", DEF_WFILES);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: vcache-mount-inplace [--mode real|sim] {up|down|status|watch}\n");
	exit(2);
}

int main(int argc, char **argv)
{
	become_root(argc, argv);

	const char *mode = env_def("AREV_MODE", "real");
	ACTION = NULL;
	for (int i = 1; i < argc; i++) {
		if      (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
		else if (!strncmp(argv[i], "--mode=", 7))            mode = argv[i] + 7;
		else if (!strcmp(argv[i], "up") || !strcmp(argv[i], "down") ||
			 !strcmp(argv[i], "status") || !strcmp(argv[i], "watch"))
			ACTION = argv[i];
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) usage();
		else { fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(); }
	}
	if (!ACTION) ACTION = "up";

	if      (!strcmp(mode, "real")) MODE_SIM = 0;
	else if (!strcmp(mode, "sim"))  MODE_SIM = 1;
	else die("unknown --mode '%s' (use real|sim)", mode);

	load_config();

	if (MODE_SIM && strcmp(ACTION, "watch") != 0) {
		char buf[16]; char *av[] = { "docker", "--version", NULL };
		if (run_capture(av, buf, sizeof buf) != 0) die("docker not found (sim mode)");
	}

	if      (!strcmp(ACTION, "up"))     run_up_sequence();
	else if (!strcmp(ACTION, "watch"))  do_watch();
	else if (!strcmp(ACTION, "down"))   { for_each_target(down_one);
					      xlog("down complete (module left loaded; 'rmmod vcachefs' to unload)"); }
	else if (!strcmp(ACTION, "status")) for_each_target(status_one);
	else usage();
	return 0;
}
