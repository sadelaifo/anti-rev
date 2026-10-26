// SPDX-License-Identifier: GPL-2.0
/*
 * vcache-readout — capture EXACTLY the bytes a reader gets for a file through
 * an vcachefs mount, write a byte-faithful copy to an output path, and report
 * what came back.  A diagnostic for "what did the gate actually serve ME?".
 *
 * Why a dedicated tool and not `cp`/`cat`:
 *   - It reads with a plain sequential read(2) loop — NO mmap, NO seek.  The
 *     unauthorized passthrough path (gate_passthrough_cipher) refuses mmap with
 *     -ENODEV and serves via read_iter/splice, so this exercises the same path
 *     a size-honoring copier (cp/tar/rsync) hits, and never trips the mmap
 *     refusal.  `cp` sometimes mmaps; this never does.
 *   - It decodes the result for you: leading magic (decrypted ELF vs inert
 *     keyless container) and the trailing 8-byte signature footer — so you can
 *     tell plaintext-leak from ciphertext-served and signed from unsigned in
 *     one run, without a separate `tail -c8 | xxd`.
 *   - It reports the open/read errno plainly: EACCES == the read gate denied
 *     this process (you are not an authorized reader).
 *
 * The run's identity IS the test: run it AS the process you want to check
 * (your shell, or `setpriv`/`runuser` as another user, or exec it from a
 * whitelisted/signed context) — the gate keys on the CALLER's exe, so what
 * this tool gets back is what that identity is allowed to see.
 *
 * Magics (kmod2 / fs form; see shared/vcache-pack.py and module/crypto.c):
 *   container  a74c2e91d63b085f   (first 8 bytes)  -> you got CIPHERTEXT
 *   ELF        7f454c46           (first 4 bytes)  -> you got PLAINTEXT (decrypted)
 *   sig footer 3d6af0128c55b427   (last 8 bytes)   -> signature footer present
 *
 * Usage:
 *   vcache-readout <src> <dst>
 * Exit: 0 on a complete copy; 1 on a read error mid-stream; 2 on usage/open error.
 *
 * Build:  gcc -O2 -Wall -o vcache-readout vcache-readout.c   (or `make vcache-readout`)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#define CONTAINER_MAGIC "\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f"
#define SIG_MAGIC       "\x3d\x6a\xf0\x12\x8c\x55\xb4\x27"

static void hex8(const unsigned char *p, int n, char *out)
{
	static const char h[] = "0123456789abcdef";
	int i;
	for (i = 0; i < n; i++) {
		out[2 * i]     = h[p[i] >> 4];
		out[2 * i + 1] = h[p[i] & 0xf];
	}
	out[2 * n] = '\0';
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <src> <dst>\n", argv[0]);
		return 2;
	}
	const char *src = argv[1], *dst = argv[2];

	int in = open(src, O_RDONLY);
	if (in < 0) {
		fprintf(stderr, "open(%s): %s (errno=%d)\n", src, strerror(errno), errno);
		if (errno == EACCES)
			fprintf(stderr, "  -> read gate DENIED: this process is not an authorized reader.\n");
		return 2;
	}
	int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out < 0) {
		fprintf(stderr, "open(%s): %s (errno=%d)\n", dst, strerror(errno), errno);
		close(in);
		return 2;
	}

	unsigned char first[8] = {0};
	unsigned char tail[12]  = {0};	/* last up-to-12 bytes: [sig_len:4][SIG_MAGIC:8] */
	size_t first_n = 0, tail_n = 0;
	uint64_t total = 0;
	int read_err = 0, rc = 0;
	unsigned char buf[1 << 16];

	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0) {
			read_err = errno;
			rc = 1;
			break;
		}
		/* capture leading 8 */
		if (first_n < sizeof(first)) {
			size_t take = sizeof(first) - first_n;
			if ((size_t)n < take)
				take = n;
			memcpy(first + first_n, buf, take);
			first_n += take;
		}
		/* maintain trailing 12 as a sliding window */
		if ((size_t)n >= sizeof(tail)) {
			memcpy(tail, buf + n - sizeof(tail), sizeof(tail));
			tail_n = sizeof(tail);
		} else {
			size_t keep = sizeof(tail) - n;
			if (tail_n < keep) {		/* grow window */
				/* nothing to shift beyond what we have */
			}
			memmove(tail, tail + (tail_n >= keep ? tail_n - keep : 0),
				tail_n >= keep ? keep : tail_n);
			size_t base = (tail_n >= keep) ? keep : tail_n;
			memcpy(tail + base, buf, n);
			tail_n = base + n;
			if (tail_n > sizeof(tail))
				tail_n = sizeof(tail);
		}

		size_t off = 0;
		while (off < (size_t)n) {
			ssize_t w = write(out, buf + off, n - off);
			if (w < 0) {
				fprintf(stderr, "write(%s): %s\n", dst, strerror(errno));
				close(in);
				close(out);
				return 2;
			}
			off += w;
		}
		total += n;
	}
	close(in);
	if (close(out) < 0)
		fprintf(stderr, "close(%s): %s\n", dst, strerror(errno));

	/* ---- report ---- */
	char fh[17] = {0}, th[17] = {0};
	hex8(first, first_n < 8 ? first_n : 8, fh);
	if (tail_n >= 8)
		hex8(tail + tail_n - 8, 8, th);

	printf("src      : %s\n", src);
	printf("dst      : %s\n", dst);
	printf("bytes    : %llu\n", (unsigned long long)total);
	printf("first8   : %s", fh);
	if (first_n >= 4 && memcmp(first, "\x7f" "ELF", 4) == 0)
		printf("   -> ELF magic: DECRYPTED PLAINTEXT (you are an authorized reader)");
	else if (first_n >= 8 && memcmp(first, CONTAINER_MAGIC, 8) == 0)
		printf("   -> container magic: CIPHERTEXT served (unauthorized / passthrough)");
	printf("\n");

	if (tail_n >= 8) {
		printf("last8    : %s", th);
		if (memcmp(tail + tail_n - 8, SIG_MAGIC, 8) == 0) {
			printf("   -> SIGNATURE FOOTER present");
			if (tail_n >= 12) {
				uint32_t sl = tail[tail_n - 12] | (tail[tail_n - 11] << 8) |
					      (tail[tail_n - 10] << 16) | ((uint32_t)tail[tail_n - 9] << 24);
				printf(" (sig_len=%u)", sl);
			}
		} else {
			printf("   -> no signature footer");
		}
		printf("\n");
	}

	if (read_err) {
		fprintf(stderr, "READ ERROR after %llu bytes: %s (errno=%d)\n",
			(unsigned long long)total, strerror(read_err), read_err);
		if (read_err == EACCES)
			fprintf(stderr, "  -> gate denied mid-stream.\n");
	}
	return rc;
}
