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
 * AREV_IOC_INSTALL_CIPHER: write a CIPHERTEXT blob into the lower (.enc) store
 * of a vcachefs mount, so it is thereafter served DECRYPTED through the mount.
 * This is the "drop a hot-patch at runtime" primitive for the in-place layover
 * deployment (lower == mountpoint), where the real lower directory is shadowed
 * by the mount and so is unreachable from userspace — only the kernel, which
 * pinned the lower dir dentry at mount time, can write there.
 *
 *   in : path      = userspace ptr to a NUL-terminated absolute DESTINATION
 *                    path whose PARENT directory is under a vcachefs mount
 *                    (e.g. "/root/project/lib/patch_v3"); the leaf must not
 *                    already exist (installs never overwrite — a stale inode
 *                    classification would otherwise mask the new bytes).
 *        path_len  = strlen(path)+1 (sanity cap AREV_PATH_MAX)
 *        mode      = file mode for the new lower file (e.g. 0644; masked 0777)
 *        data      = userspace ptr to the ciphertext (a keyless FS_MAGIC
 *                    container, encrypted with the project key baked into the
 *                    .ko; the kernel verifies the leading magic and rejects
 *                    anything else, so this cannot plant arbitrary files)
 *        data_len  = ciphertext length (>= header, <= AREV_INSTALL_MAX)
 *   ret = 0 on success; <0 on error (-EACCES unauthorized caller, -EEXIST leaf
 *         present, -EINVAL not under a vcachefs mount / bad magic, -EROFS lower
 *         read-only, ...).  On any failure after create the partial file is
 *         unlinked.
 *
 * Gated (like the other ioctls) on vcf_ctl_caller_ok() — ship the installer as
 * a pinned/signed binary.  The installer still never holds the AES key: it
 * supplies ciphertext produced off-box with the project key.
 */
#define AREV_INSTALL_MAX	(64u * 1024 * 1024)	/* sanity cap on one blob */
struct arev_install_arg {
	__u64	path;		/* __u64 so the struct is 32/64-bit identical */
	__u32	path_len;
	__u32	mode;		/* new-file mode bits (masked to 0777) */
	__u64	data;		/* ciphertext bytes */
	__u64	data_len;
};
#define AREV_IOC_INSTALL_CIPHER	_IOW(AREV_IOC_MAGIC, 3, struct arev_install_arg)

#endif /* AREV_UAPI_H */
