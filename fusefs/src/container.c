/*
 * container.c — container-format probing (magic / signature footer / trailer).
 * All reads are positioned pread()s so they are safe to call concurrently on a
 * shared lower fd.  See container.h and ../DESIGN.md.
 */
#include "container.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

static int pread_exact(int fd, void *buf, size_t len, off_t off)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = pread(fd, (char *)buf + done, len - done, off + done);
		if (n < 0)
			return -errno;
		if (n == 0)
			return -EIO;		/* short file */
		done += (size_t)n;
	}
	return 0;
}

int ar_has_magic(int fd)
{
	char buf[AR_MAGIC_LEN];
	int r = pread_exact(fd, buf, sizeof(buf), 0);
	if (r == -EIO)
		return 0;			/* too short to be a container */
	if (r < 0)
		return r;
	return memcmp(buf, AR_MAGIC, AR_MAGIC_LEN) == 0 ? 1 : 0;
}

int ar_container_len(int fd, off_t file_size, off_t *container_len)
{
	unsigned char magic[AR_SIG_MAGIC_LEN];
	unsigned char lenbuf[AR_SIG_LENFIELD];
	uint32_t slen;
	int r;

	*container_len = file_size;
	if (file_size < AR_SIG_FOOTER_LEN)
		return 0;			/* can't hold a sig footer */

	r = pread_exact(fd, magic, AR_SIG_MAGIC_LEN,
			file_size - AR_SIG_MAGIC_LEN);
	if (r < 0)
		return r;
	if (memcmp(magic, AR_SIG_MAGIC, AR_SIG_MAGIC_LEN) != 0)
		return 0;			/* no appended signature */

	r = pread_exact(fd, lenbuf, AR_SIG_LENFIELD,
			file_size - AR_SIG_FOOTER_LEN);
	if (r < 0)
		return r;
	slen = (uint32_t)lenbuf[0] | ((uint32_t)lenbuf[1] << 8) |
	       ((uint32_t)lenbuf[2] << 16) | ((uint32_t)lenbuf[3] << 24);
	if (slen == 0 || slen > AR_SIG_MAX ||
	    (off_t)slen + AR_SIG_FOOTER_LEN > file_size)
		return -EINVAL;			/* malformed footer */

	*container_len = file_size - AR_SIG_FOOTER_LEN - (off_t)slen;
	return 1;
}

int ar_has_trailer(int fd, off_t container_len)
{
	char buf[AR_MAGIC_LEN];
	int r;

	if (container_len < AR_HDR_LEN + AR_TRAILER_LEN)
		return 0;
	r = pread_exact(fd, buf, sizeof(buf), container_len - AR_MAGIC_LEN);
	if (r < 0)
		return r;
	return memcmp(buf, AR_MAGIC, AR_MAGIC_LEN) == 0 ? 1 : 0;
}
