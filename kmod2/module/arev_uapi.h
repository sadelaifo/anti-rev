/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arev_uapi.h — ioctl protocol between the vcachefs kernel module and the
 * qemu-user decrypt gate.  This file MUST stay byte-identical to
 * kmod2/module/arev_uapi.h (the kernel copy).
 *
 * Model (sim mode, ARM64-under-qemu on an x86 host):
 *   - The container holds the ciphertext in-place at the vcachefs mount
 *     (e.g. /root/SW/{bin,lib}); vcachefs decrypts it for the signed emulator.
 *   - Under qemu the kernel cannot tell which *guest* is running (every guest's
 *     exe_file is qemu), so qemu supplies the per-guest decision:
 *       * authorized guest (signed slave binary) -> opens the mount normally ->
 *         vcachefs decrypts into the SHARED page cache (cross-process sharing);
 *       * unauthorized guest (cp/objdump/...)     -> qemu asks the kernel for the
 *         KEYLESS ciphertext of the file and serves that instead.
 *   - The AES key never leaves the host kernel; qemu does no crypto.
 *
 * Both ioctls are gated in the kernel on the caller being the genuine, signed
 * emulator (its exe carries a valid vendor signature), so a rogue/modified qemu
 * cannot use them.
 */
#ifndef AREV_UAPI_H
#define AREV_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define AREV_DEV_NAME	"vcachefs"		/* control device: /dev/vcachefs */
#define AREV_DEV_PATH	"/dev/" AREV_DEV_NAME
#define AREV_IOC_MAGIC	0xAE

/*
 * AREV_IOC_AUTHORIZE_FD: verify that the file referenced by the fd passed as the
 * ioctl argument carries a valid vendor signature (an appended ANTREV_SIG
 * footer verifying against the module's embedded cert).  qemu calls this at
 * guest-ELF load to decide whether the guest is authorized.
 *   arg  = (unsigned long) fd
 *   ret  = 0  authorized
 *         <0  not authorized / error (-EACCES, -EBADF, ...)
 */
#define AREV_IOC_AUTHORIZE_FD	_IO(AREV_IOC_MAGIC, 1)

/*
 * AREV_IOC_OPEN_CIPHER: return the KEYLESS ciphertext of a vcachefs mount file
 * as a fresh, read-only fd, for the unauthorized-guest branch.  The kernel
 * resolves `path` (must live under a vcachefs mount), reads its lower container
 * with the key trailer stripped (an encrypted file) or the plaintext bytes (a
 * non-secret passthrough file), and installs a new fd in the caller.
 *   in : path      = userspace pointer to a NUL-terminated absolute path
 *        path_len  = strlen(path)+1 (sanity cap AREV_PATH_MAX)
 *   out: out_fd    = fd of the keyless-ciphertext file (caller owns/closes it)
 *   ret = 0 on success; <0 on error.
 */
#define AREV_PATH_MAX	4096
struct arev_cipher_arg {
	__u64	path;		/* __u64 so the struct is 32/64-bit identical */
	__u32	path_len;
	__s32	out_fd;		/* [out] */
};
#define AREV_IOC_OPEN_CIPHER	_IOWR(AREV_IOC_MAGIC, 2, struct arev_cipher_arg)

/*
 * AREV_IOC_LOWER_DIRFD: return a fresh fd for the LOWER (real, on-disk)
 * directory that backs a vcachefs DIRECTORY `path`.  With an in-place mount the
 * lower dir is shadowed by the read-only vcachefs mount and is unreachable by
 * path, so an authorized upgrade tool asks the kernel for a handle to it, then
 * creates a temp file + atomically renameat()s it over the target basename.
 * Only CIPHERTEXT is written through this fd — no plaintext and no key ever
 * cross the interface.  Reuses struct arev_cipher_arg:
 *   in : path/path_len = a vcachefs DIRECTORY (e.g. /root/proj/bin)
 *   out: out_fd        = O_DIRECTORY fd on the lower dir (caller owns/closes)
 *   ret = 0 on success; <0 on error.
 */
#define AREV_IOC_LOWER_DIRFD	_IOWR(AREV_IOC_MAGIC, 3, struct arev_cipher_arg)

/*
 * AREV_IOC_REFRESH_PATH: drop the cached vcachefs dentry for ONE regular file
 * `path` so the next access re-resolves the lower dentry and rebuilds a fresh
 * inode (classification + decrypt + gate verdict) from the just-replaced lower
 * file.  Lets a LIVE mount pick up new ciphertext for one file without a
 * remount — every other file/subsystem is untouched.  The replacement MUST be
 * an atomic rename in the lower dir (giving a NEW lower inode); an in-place
 * overwrite is not picked up (the cached inode would be reused).  out_fd unused.
 *   in : path/path_len = a vcachefs regular file (e.g. /root/proj/bin/FOO)
 *   ret = 0 on success; <0 on error.
 */
#define AREV_IOC_REFRESH_PATH	_IOW(AREV_IOC_MAGIC, 4, struct arev_cipher_arg)

#endif /* AREV_UAPI_H */
