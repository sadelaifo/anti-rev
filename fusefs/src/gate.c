/*
 * gate.c — caller-identity authorization (whitelist + optional allow-list file).
 * See gate.h and ../DESIGN.md.  Per-exe PKCS#7 signature verification of the
 * caller is the next pass-type (future work, mirroring kmod2 gate step 2b).
 */
#include "gate.h"
#include "gate_whitelist.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static struct gate_config g_cfg;

void gate_init(const struct gate_config *cfg)
{
	g_cfg = *cfg;
}

/* Resolve /proc/<pid>/exe into `out` (full path).  Returns 0 / <0. */
static int resolve_exe(pid_t pid, char *out, size_t out_len)
{
	char link[64];
	ssize_t n;

	snprintf(link, sizeof(link), "/proc/%ld/exe", (long)pid);
	n = readlink(link, out, out_len - 1);
	if (n <= 0)
		return -1;
	out[n] = '\0';
	/* kernel appends " (deleted)" for unlinked exes; trim it so a
	 * memfd/deleted launcher still matches by basename. */
	{
		const char *del = " (deleted)";
		size_t dl = strlen(del);
		if ((size_t)n > dl && strcmp(out + n - dl, del) == 0)
			out[n - dl] = '\0';
	}
	return 0;
}

static const char *basename_of(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

static bool whitelisted(const char *base)
{
	const char *const *w;
	for (w = fusefs_whitelist; *w; w++)
		if (strcmp(*w, base) == 0)
			return true;
	return false;
}

/* Match the exe against an allow-list file: an entry containing '/' matches the
 * full path, otherwise it matches the basename.  '#' comments and blanks are
 * ignored.  Re-read per call so the list can be edited live (dev bring-up). */
static bool allowlist_file_matches(const char *path, const char *exe_path,
				   const char *exe_base)
{
	char line[PATH_MAX + 2];
	FILE *f = fopen(path, "re");
	bool hit = false;

	if (!f)
		return false;
	while (fgets(line, sizeof(line), f)) {
		char *s = line, *end;
		while (*s && isspace((unsigned char)*s))
			s++;
		if (*s == '#' || *s == '\0')
			continue;
		end = s + strlen(s);
		while (end > s && isspace((unsigned char)end[-1]))
			*--end = '\0';
		if (*s == '\0')
			continue;
		if (strchr(s, '/')) {
			if (strcmp(s, exe_path) == 0) { hit = true; break; }
		} else {
			if (strcmp(s, exe_base) == 0) { hit = true; break; }
		}
	}
	fclose(f);
	return hit;
}

bool gate_task_authorized(pid_t pid)
{
	char exe[PATH_MAX];
	const char *base;

	if (!g_cfg.enforce)
		return true;		/* bring-up / dev: allow all */

	if (resolve_exe(pid, exe, sizeof(exe)) < 0)
		return false;		/* fail-closed */
	base = basename_of(exe);

	if (whitelisted(base))
		return true;
	if (g_cfg.authz_path &&
	    allowlist_file_matches(g_cfg.authz_path, exe, base))
		return true;
	return false;
}
