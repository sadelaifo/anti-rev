/*
 * container.h — the antirev on-disk container format, shared byte-for-byte with
 * kmod2 (kmod2/module/vcachefs.h) and the packer (encryptor/protect.py,
 * kmod2/tools/vcache-pack.py).  See ../DESIGN.md.
 *
 * Embedded-key form (what vcache-pack.py emits):
 *   [ MAGIC:8 ][ IV:12 ][ TAG:16 ][ CT:n ][ KEY:32 ][ MAGIC:8 ]
 * Optional appended per-exe signature footer:
 *   [ container... ][ SIG:sig_len ][ sig_len:4 LE ][ SIG_MAGIC:8 ]
 */
#ifndef FUSEFS_CONTAINER_H
#define FUSEFS_CONTAINER_H

#include <stdint.h>
#include <sys/types.h>

/* Neutral "vcache" magic bytes — MUST match kmod2 ANTREV_MAGIC and the
 * packer's FS_MAGIC (a74c2e91d63b085f). */
#define AR_MAGIC       "\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f"
#define AR_MAGIC_LEN   8
#define AR_IV_LEN      12
#define AR_TAG_LEN     16
#define AR_KEY_LEN     32                               /* AES-256 */
#define AR_HDR_LEN     (AR_MAGIC_LEN + AR_IV_LEN + AR_TAG_LEN)   /* 36 */
#define AR_TRAILER_LEN (AR_KEY_LEN + AR_MAGIC_LEN)              /* 40 */

/* Appended per-exe signature section (FS_MAGIC/SIG_MAGIC = 3d6af0128c55b427). */
#define AR_SIG_MAGIC      "\x3d\x6a\xf0\x12\x8c\x55\xb4\x27"
#define AR_SIG_MAGIC_LEN  8
#define AR_SIG_LENFIELD   4                             /* u32 LE sig length */
#define AR_SIG_FOOTER_LEN (AR_SIG_LENFIELD + AR_SIG_MAGIC_LEN)  /* 12 */
#define AR_SIG_MAX        (16 * 1024)                   /* sanity cap */

/* Read the leading AR_MAGIC.  Returns 1 = present, 0 = absent, <0 = -errno. */
int ar_has_magic(int fd);

/*
 * Locate the container boundary, parsing past any appended signature footer.
 * On a signed file *container_len = start of the sig section; on an unsigned
 * file *container_len = file_size.  Returns 1 if a signature footer is present,
 * 0 if not, <0 = -errno (read error / malformed footer).
 */
int ar_container_len(int fd, off_t file_size, off_t *container_len);

/* Confirm the container ends in the embedded-key trailer magic (key trailer
 * present).  container_len is the sig-stripped length from ar_container_len().
 * Returns 1 / 0 / <0 = -errno. */
int ar_has_trailer(int fd, off_t container_len);

/* Plaintext length for a valid embedded-key container of container_len bytes.
 * Returns <0 = -EINVAL if the container is too small. */
static inline off_t ar_plain_len(off_t container_len)
{
	if (container_len < AR_HDR_LEN + AR_TRAILER_LEN)
		return -1;
	return container_len - AR_HDR_LEN - AR_TRAILER_LEN;
}

#endif /* FUSEFS_CONTAINER_H */
