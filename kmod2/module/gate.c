// SPDX-License-Identifier: GPL-2.0
/*
 * antirevfs decryption-authorization gate.
 *
 * This file is the ONE place that decides whether the *calling process* is
 * allowed to read decrypted (plaintext) content through an antirevfs mount.
 * antirevfs_file_open() calls antirevfs_task_authorized() for every open of an
 * encrypted file; an unauthorized process gets -EACCES and can therefore only
 * ever reach the lower .enc/ ciphertext (via the lower tree directly).
 *
 * Step 1 (this implementation): the predicate matches the calling process's
 * executable -- current->mm->exe_file, which the kernel updates at execve, so
 * fork() inherits authorization and execve() of an unlisted helper like /bin/cp
 * drops it with no bookkeeping on our side -- against a newline-separated
 * allow-list file (default /etc/authorized_apps.txt).
 *
 * This is a CORRECTNESS DEMONSTRATOR for the gating plumbing, NOT a security
 * boundary: anyone who can write the allow-list, or drop a binary at an allowed
 * path, passes.  Step 2 replaces ONLY the body of authz_exe_allowed() with a
 * signature check (verify the exe's detached signature against a public key in a
 * locked kernel keyring, anchored in measured boot).  The call site, the
 * -EACCES enforcement, the encrypted-only scoping, the fork/execve lifecycle,
 * and the shared-page-cache behaviour are all unchanged -- migration is a
 * one-function swap.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/limits.h>

#include "compat.h"
#include "antirevfs.h"

#define AUTHZ_MAX_BYTES		(64 * 1024)	/* sanity cap on the allow-list file */

static bool gate_enforce;
module_param(gate_enforce, bool, 0644);
MODULE_PARM_DESC(gate_enforce,
	"Enforce per-process decrypt authorization (0 = allow all, default)");

static char authz_path[256] = "/etc/authorized_apps.txt";
module_param_string(authz_path, authz_path, sizeof(authz_path), 0644);
MODULE_PARM_DESC(authz_path,
	"Allow-list file: newline-separated authorized exe paths or basenames");

/*
 * Read the whole allow-list file into a NUL-terminated kmalloc buffer.
 * Returns the buffer (caller kfree()s) or NULL on any error / empty / oversize.
 *
 * Opened with the caller's creds, so the file must be readable by the business
 * processes (e.g. mode 0644).  Re-read on every check so the test (and an admin)
 * can edit the list live; step 2 sheds the shared file entirely by reading a
 * signature off the exe itself.
 */
static char *authz_read_list(void)
{
	struct file *f;
	char *buf;
	loff_t size, pos = 0;
	ssize_t n;

	f = filp_open(authz_path, O_RDONLY, 0);
	if (IS_ERR(f))
		return NULL;

	size = i_size_read(file_inode(f));
	if (size <= 0 || size > AUTHZ_MAX_BYTES) {
		filp_close(f, NULL);
		return NULL;
	}

	buf = kmalloc(size + 1, GFP_KERNEL);
	if (!buf) {
		filp_close(f, NULL);
		return NULL;
	}

	n = arev_kernel_read(f, buf, size, &pos);
	filp_close(f, NULL);

	if (n != size) {
		kfree(buf);
		return NULL;
	}
	buf[size] = '\0';
	return buf;
}

/*
 * True if exe_path (the canonical absolute path of the caller's executable)
 * matches any allow-list entry.  An entry containing '/' is matched against the
 * full path; an entry with no '/' is matched against the basename only.  Blank
 * lines and '#' comments are ignored.  Mutates `list` in place (strsep/strim).
 */
static bool authz_list_matches(char *list, const char *exe_path)
{
	const char *base = kbasename(exe_path);
	char *line;

	while ((line = strsep(&list, "\n")) != NULL) {
		char *entry = strim(line);

		if (!*entry || *entry == '#')
			continue;
		if (strchr(entry, '/')) {
			if (!strcmp(entry, exe_path))
				return true;
		} else if (!strcmp(entry, base)) {
			return true;
		}
	}
	return false;
}

/* Resolve the calling process's executable path and test it against the list. */
static bool authz_exe_allowed(void)
{
	struct file *exe;
	char *pathbuf, *exe_path, *list;
	bool ok = false;

	if (!current->mm)			/* kernel thread: never authorized */
		return false;

	exe = get_mm_exe_file(current->mm);
	if (!exe)
		return false;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf) {
		fput(exe);
		return false;
	}

	exe_path = d_path(&exe->f_path, pathbuf, PATH_MAX);
	fput(exe);
	if (IS_ERR(exe_path))
		goto out;

	list = authz_read_list();
	if (!list)
		goto out;			/* enforce + no/unreadable list => deny */

	ok = authz_list_matches(list, exe_path);
	kfree(list);
out:
	kfree(pathbuf);
	return ok;
}

/*
 * The gate seam.  antirevfs_file_open() calls this for every open of an
 * encrypted file; returns true if the caller may read decrypted content.
 *
 * Step 2 replaces the authz_exe_allowed() body with a signature check; this
 * function's contract and every caller stay identical.
 */
bool antirevfs_task_authorized(void)
{
	if (!gate_enforce)
		return true;		/* gating off: behave exactly as before */
	return authz_exe_allowed();
}
