/*
 * fs.c — vcachefsd: a read-only FUSE filesystem that decrypts antirev
 * embedded-key containers on read, gated by caller identity.  High-level
 * libfuse3 API.  See ../DESIGN.md.
 *
 *   vcachefsd <lower-ciphertext-dir> <mountpoint> [options] [fuse opts]
 *
 * Options:
 *   --passdata                serve ANY non-magic file as plaintext passthrough
 *   --passthrough EXTS        colon-separated ext whitelist (e.g. json:txt:sh)
 *   --gate                    enforce the decrypt-authorization gate
 *   --authz FILE              dev allow-list file (basename or full path/line)
 *   --passthrough-cipher      unauthorized readers get the keyless container
 *                             (trailer stripped) instead of -EACCES
 *   --cache-mb N              plaintext LRU budget in MiB (default 512)
 */
#define FUSE_USE_VERSION 31

#include <fuse.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "container.h"
#include "crypto.h"
#include "gate.h"
#include "cache.h"

/* ---- daemon-wide config ---------------------------------------------------- */
static struct {
	char *lower;			/* absolute ciphertext root */
	int passdata;
	char *passthrough;		/* colon-separated extensions, or NULL */
	int gate;
	char *authz;
	int passthrough_cipher;
	int cache_mb;
} g = { .cache_mb = 512 };

/* per-open handle */
struct fh {
	int lfd;			/* lower fd, O_RDONLY */
	int encrypted;			/* 1 = antirev container */
	int authorized;		/* gate verdict for the opener */
	off_t container_len;		/* sig-stripped container length */
	off_t plain_len;		/* decrypted length (encrypted only) */
	off_t pt_limit;		/* unauthorized passthrough cap (key stripped) */
	struct stat lst;		/* lower stat at open (cache key) */
};

/* ---- helpers --------------------------------------------------------------- */
static int lower_path(const char *path, char *out, size_t out_len)
{
	int n;
	if (path[0] == '/' && path[1] == '\0')
		n = snprintf(out, out_len, "%s", g.lower);
	else
		n = snprintf(out, out_len, "%s%s", g.lower, path);
	if (n < 0 || (size_t)n >= out_len)
		return -ENAMETOOLONG;
	return 0;
}

static bool ext_whitelisted(const char *name)
{
	const char *dot, *p;
	size_t ext_len;

	if (!g.passthrough)
		return false;
	dot = strrchr(name, '.');
	if (!dot || !dot[1])
		return false;
	dot++;
	ext_len = strlen(dot);
	p = g.passthrough;
	while (*p) {
		const char *sep = strchr(p, ':');
		size_t tok = sep ? (size_t)(sep - p) : strlen(p);
		if (tok == ext_len && strncasecmp(p, dot, ext_len) == 0)
			return true;
		if (!sep)
			break;
		p = sep + 1;
	}
	return false;
}

/* Classify an open lower fd.
 *   1  = encrypted container (fills container_len, plain_len)
 *   0  = non-magic plaintext
 *   <0 = -errno (incl. -EIO for a magic file that is not a complete
 *        embedded-key container). */
static int classify(int fd, off_t file_size, off_t *container_len,
		    off_t *plain_len)
{
	int m = ar_has_magic(fd);
	off_t clen, plen;

	if (m < 0)
		return m;
	if (m == 0)
		return 0;			/* plaintext */

	if (ar_container_len(fd, file_size, &clen) < 0)
		return -EIO;
	if (ar_has_trailer(fd, clen) != 1)
		return -EIO;			/* magic but no key trailer */
	plen = ar_plain_len(clen);
	if (plen < 0)
		return -EIO;
	*container_len = clen;
	*plain_len = plen;
	return 1;
}

/* ---- fuse ops -------------------------------------------------------------- */
static void *fs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	(void)conn;
	/* We gate per-caller, so attributes must not be cached across callers
	 * while enforcing.  Also resolve paths ourselves (no kernel reval). */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = g.gate ? 0 : 1.0;
	cfg->negative_timeout = 0;
	return NULL;
}

static int fs_getattr(const char *path, struct stat *st,
		      struct fuse_file_info *fi)
{
	char lp[PATH_MAX];
	int fd, r, cls;
	off_t clen = 0, plen = 0;
	pid_t pid = fuse_get_context()->pid;

	(void)fi;
	if ((r = lower_path(path, lp, sizeof(lp))) < 0)
		return r;
	if (lstat(lp, st) < 0)
		return -errno;
	if (!S_ISREG(st->st_mode))
		return 0;			/* dirs/symlinks: report as-is */

	fd = open(lp, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;			/* unreadable: report raw stat */
	cls = classify(fd, st->st_size, &clen, &plen);
	close(fd);
	if (cls <= 0)
		return 0;			/* plaintext / strict: raw size */

	/* Encrypted: report the size the caller will actually be able to read. */
	if (!g.gate || gate_task_authorized(pid))
		st->st_size = plen;		/* authorized: plaintext size */
	else if (g.passthrough_cipher)
		st->st_size = clen - AR_TRAILER_LEN;	/* keyless container */
	else
		st->st_size = plen;		/* will -EACCES on read anyway */
	return 0;
}

static int fs_readlink(const char *path, char *buf, size_t size)
{
	char lp[PATH_MAX];
	ssize_t n;
	int r;

	if ((r = lower_path(path, lp, sizeof(lp))) < 0)
		return r;
	n = readlink(lp, buf, size - 1);
	if (n < 0)
		return -errno;
	buf[n] = '\0';
	return 0;
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		      off_t off, struct fuse_file_info *fi,
		      enum fuse_readdir_flags flags)
{
	char lp[PATH_MAX];
	DIR *d;
	struct dirent *de;
	int r;

	(void)off; (void)fi; (void)flags;
	if ((r = lower_path(path, lp, sizeof(lp))) < 0)
		return r;
	d = opendir(lp);
	if (!d)
		return -errno;
	while ((de = readdir(d))) {
		struct stat st = { .st_ino = de->d_ino,
				   .st_mode = DTTOIF(de->d_type) };
		if (filler(buf, de->d_name, &st, 0, 0))
			break;
	}
	closedir(d);
	return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
	char lp[PATH_MAX];
	struct fh *h;
	int fd, cls, r;
	off_t clen = 0, plen = 0;
	pid_t pid = fuse_get_context()->pid;

	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EROFS;		/* read-only filesystem */
	if ((r = lower_path(path, lp, sizeof(lp))) < 0)
		return r;
	fd = open(lp, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	h = calloc(1, sizeof(*h));
	if (!h) {
		close(fd);
		return -ENOMEM;
	}
	h->lfd = fd;
	if (fstat(fd, &h->lst) < 0) {
		r = -errno;
		goto fail;
	}
	cls = classify(fd, h->lst.st_size, &clen, &plen);
	if (cls < 0) {
		r = cls;			/* e.g. -EIO */
		goto fail;
	}
	if (cls == 0) {
		/* non-magic plaintext: only servable under passdata / ext list */
		if (!g.passdata && !ext_whitelisted(path)) {
			r = -EIO;		/* strict mode */
			goto fail;
		}
		h->encrypted = 0;
		fi->fh = (uintptr_t)h;
		fi->keep_cache = 1;	/* plaintext for everyone: cache freely */
		return 0;
	}

	/* encrypted container */
	h->encrypted = 1;
	h->container_len = clen;
	h->plain_len = plen;
	h->authorized = (!g.gate) || gate_task_authorized(pid);
	if (!h->authorized) {
		if (!g.passthrough_cipher) {
			r = -EACCES;
			goto fail;
		}
		h->pt_limit = clen - AR_TRAILER_LEN;	/* strip key trailer */
	}
	fi->fh = (uintptr_t)h;
	/* When the gate is enforced, DO NOT let the kernel share this inode's
	 * page cache across opens: an authorized reader would populate plaintext
	 * pages that a later UNAUTHORIZED opener of the same path could read
	 * without our handler ever running (gate bypass).  direct_io routes every
	 * read through fs_read so the caller is re-checked each time.  Cross-
	 * process sharing is still provided daemon-side by the plaintext LRU
	 * cache (decrypt-once).  With the gate off, everyone is authorized, so
	 * kernel caching is safe and faster. */
	if (g.gate) {
		fi->direct_io = 1;
		fi->keep_cache = 0;
	} else {
		fi->keep_cache = 1;
	}
	return 0;
fail:
	close(fd);
	free(h);
	return r;
}

/* serve a byte range from the lower fd, capped at `limit` */
static int serve_lower(struct fh *h, char *buf, size_t size, off_t off,
		       off_t limit)
{
	if (off >= limit)
		return 0;
	if (off + (off_t)size > limit)
		size = (size_t)(limit - off);
	{
		ssize_t n = pread(h->lfd, buf, size, off);
		return n < 0 ? -errno : (int)n;
	}
}

static int fs_read(const char *path, char *buf, size_t size, off_t off,
		   struct fuse_file_info *fi)
{
	struct fh *h = (struct fh *)(uintptr_t)fi->fh;
	struct cache_entry *e;
	unsigned char *plain;
	int r;

	(void)path;
	if (!h)
		return -EBADF;

	if (!h->encrypted)			/* plaintext passthrough */
		return serve_lower(h, buf, size, off, h->lst.st_size);

	if (!h->authorized)			/* keyless passthrough container */
		return serve_lower(h, buf, size, off, h->pt_limit);

	/* authorized decrypt: whole-file, cached */
	e = cache_lookup(&h->lst);
	if (!e) {
		plain = malloc(h->plain_len ? h->plain_len : 1);
		if (!plain)
			return -ENOMEM;
		r = ar_decrypt(h->lfd, h->container_len, plain, h->plain_len);
		if (r < 0) {
			free(plain);
			return r;		/* e.g. -EBADMSG on tag fail */
		}
		e = cache_insert(&h->lst, plain, h->plain_len);
		if (!e) {			/* insert failed: serve directly */
			size_t n = 0;
			if (off < (off_t)h->plain_len) {
				n = h->plain_len - off;
				if (n > size) n = size;
				memcpy(buf, plain + off, n);
			}
			free(plain);
			return (int)n;
		}
	}
	{
		size_t n = 0;
		const unsigned char *data = cache_data(e);
		size_t len = cache_len(e);
		if (off < (off_t)len) {
			n = len - off;
			if (n > size) n = size;
			memcpy(buf, data + off, n);
		}
		cache_release(e);
		return (int)n;
	}
}

static int fs_release(const char *path, struct fuse_file_info *fi)
{
	struct fh *h = (struct fh *)(uintptr_t)fi->fh;
	(void)path;
	if (h) {
		if (h->lfd >= 0)
			close(h->lfd);
		free(h);
	}
	return 0;
}

static const struct fuse_operations fs_ops = {
	.init		= fs_init,
	.getattr	= fs_getattr,
	.readlink	= fs_readlink,
	.readdir	= fs_readdir,
	.open		= fs_open,
	.read		= fs_read,
	.release	= fs_release,
};

/* ---- option parsing -------------------------------------------------------- */
#define OPT(t, m) { t, offsetof(typeof(g), m), 1 }
static const struct fuse_opt opt_spec[] = {
	OPT("--passdata",          passdata),
	OPT("--passthrough %s",    passthrough),
	OPT("--gate",              gate),
	OPT("--authz %s",          authz),
	OPT("--passthrough-cipher", passthrough_cipher),
	OPT("--cache-mb %d",       cache_mb),
	FUSE_OPT_END
};

/* grab the first non-option as the lower dir; keep the rest (mountpoint, fuse
 * opts) for fuse_main. */
static int opt_proc(void *data, const char *arg, int key,
		    struct fuse_args *outargs)
{
	(void)data; (void)outargs;
	if (key == FUSE_OPT_KEY_NONOPT && !g.lower) {
		g.lower = realpath(arg, NULL);
		if (!g.lower) {
			fprintf(stderr, "vcachefsd: bad lower dir '%s': %s\n",
				arg, strerror(errno));
			return -1;
		}
		return 0;		/* consume */
	}
	return 1;			/* keep (mountpoint / fuse opts) */
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct gate_config gc;
	int ret;

	if (fuse_opt_parse(&args, &g, opt_spec, opt_proc) < 0)
		return 1;
	if (!g.lower) {
		fprintf(stderr,
			"usage: vcachefsd <lower-dir> <mountpoint> [--passdata] "
			"[--passthrough e:e] [--gate [--authz FILE]] "
			"[--passthrough-cipher] [--cache-mb N] [fuse opts]\n");
		return 1;
	}

	cache_init((size_t)g.cache_mb * 1024 * 1024);
	gc.enforce = g.gate;
	gc.authz_path = g.authz;
	gate_init(&gc);

	ret = fuse_main(args.argc, args.argv, &fs_ops, NULL);
	fuse_opt_free_args(&args);
	free(g.lower);
	return ret;
}
