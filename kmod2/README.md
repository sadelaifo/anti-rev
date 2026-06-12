# antirevfs — kmod2 implementation

Stacked read-only kernel filesystem that decrypts `ANTREV01` AES-256-GCM files
on page-fault, so glibc/`ld.so`/Python see plaintext while the on-disk bytes
(under a lower `.enc/` tree) stay ciphertext. The kernel page cache provides
cross-process page sharing for free — no daemon, no `LD_PRELOAD` shim, no
`memfd:` artifact. See [`DESIGN.md`](DESIGN.md) for the full rationale.

## Layout

```
kmod2/
├── DESIGN.md            architecture + locked decisions + open questions
├── module/              the kernel module (antirevfs.ko)
│   ├── antirevfs.h      shared types + on-disk format constants
│   ├── super.c          fs registration, mount, options, key acquisition, lifecycle
│   ├── inode.c          lookup proxied to lower tree, iget5 caching, getattr
│   ├── file.c           read_folio decrypt-on-fault, dir iterate, file ops
│   ├── crypto.c         ANTREV01 trailer detect + gcm(aes) whole-file decrypt
│   ├── Makefile         out-of-tree kbuild
│   └── dkms.conf        DKMS packaging (auto-rebuild on kernel upgrade)
├── tools/
│   ├── antirev-keyctl   install/clear the AES key in the kernel keyring
│   ├── antirev-mount    thin `mount -t antirevfs` wrapper (read-only view)
│   └── antirev-mount-rw writable view: overlayfs upper over the antirevfs lower
└── tests/
    └── test_antirevfs.sh end-to-end test (needs root)
```

## On-disk format

Reuses the existing `encryptor/protect.py encrypt-lib` container, unchanged:

```
[magic "ANTREV01" : 8][iv : 12][tag : 16][ciphertext ...]
```

The whole plaintext is one AES-256-GCM message (no chunking). `read_folio` does
a one-shot whole-file decrypt into a per-inode buffer on first fault (tag
verified once), then serves every page from it. The decrypt-the-whole-file
approach is required because GCM authenticates the entire message — per-page
random access cannot verify the tag in isolation.

## Kernel compatibility

The source carries `LINUX_VERSION_CODE` guards (`compat.h` + inline) so it
builds on a range of kernels. Verified build+runtime: **mainline 6.8**.
Backported (compile-tested on the target only): **SLES 12 / 4.12.14-default**.
The guards cover the APIs that moved between those: `read_folio`↔`readpage`,
the crypto async-wait trio (4.16), `getattr`/`generic_fillattr` signatures,
`alloc_inode_sb` (5.17), `free_inode`↔`destroy_inode` (5.2), `kernel_read`
signature (4.14), `SB_*`↔`MS_*` flags (4.15), and the `hex.h` split (5.18).

> Enterprise distro kernels (SUSE/RHEL) backport APIs while keeping an old
> `LINUX_VERSION_CODE`. If a guess is wrong for your kernel, override it, e.g.
> a 4.12 kernel that backported the new `kernel_read`:
> `make CC=<gcc> EXTRA_CFLAGS=-DAREV_NEW_KERNEL_READ`.

## Build

The module must be compiled with the **same compiler major version the running
kernel was built with** (check `cat /proc/version`) against that kernel's
headers.

### Mainline / Ubuntu 6.8 (this dev box)

```bash
cd kmod2/module
make CC=gcc-12          # gcc-12 = the compiler this kernel was built with
```

### SLES 12 (4.12.14-default) target

```bash
# 1. install build prerequisites (matching the *running* kernel)
sudo zypper install -y kernel-default-devel gcc make
uname -r                                  # e.g. 4.12.14-120-default
ls /usr/src/linux-$(uname -r | sed 's/-default//')-obj/  # headers present?

# 2. build (SLES 12's kernel was built with gcc; the distro gcc matches)
cd kmod2/module
make                                      # add CC=gcc-<n> if /proc/version differs
#   if it errors on kernel_read: make EXTRA_CFLAGS=-DAREV_NEW_KERNEL_READ

# 3. report back: if compilation fails, send the first few errors —
#    they pin which compat guard needs adjusting for your exact kernel.
```

Produces `antirevfs.ko`. Kernel headers (`/lib/modules/$(uname -r)/build`,
which on SLES points into `/usr/src/...`) must be installed.

## Usage

```bash
# 1. load the module
sudo insmod kmod2/module/antirevfs.ko        # or: modprobe antirevfs (after dkms install)

# 2. put the AES key in the kernel keyring (same key protect.py encrypted with)
sudo kmod2/tools/antirev-keyctl unlock --keyfile /path/to/key.hex

# 3. mount the ciphertext .enc/ tree as a decrypted view
sudo kmod2/tools/antirev-mount /root/proj/.enc/lib /root/proj/lib json:md
#   equivalently:
#   mount -t antirevfs -o ro,passthrough=json:md /root/proj/.enc/lib /root/proj/lib
```

- `passthrough=` (colon-separated extensions — `,` is the mount-option
  separator) serves matching files verbatim for mixed-content dirs. Any other
  file lacking the `ANTREV01` magic is rejected with `-EIO` (strict mode).
- `passdata` (`antirev-mount --passdata …`) serves **any** non-`ANTREV01` file
  as plaintext passthrough — for a complete mixed read-only `lib/`/`bin/` tree
  (encrypted ELFs + `.py`/`.sh`/`.txt`/`.json` data + third-party plaintext
  libs), produced by `antirev-fs-pack.py` with `mirror_plaintext` (default).
  The mount is read-only: redirect any runtime-written files to a writable path
  outside the mount (e.g. an overlayfs upper — see "Writable view" below).
- For ad-hoc testing without the keyring, pass `key=<64 hex chars>` in `-o`.

### Writable view (overlayfs upper) — `antirev-mount-rw`

A bare antirevfs mount is **read-only** (decrypt-on-read only; no write path), so
business software that writes lock/log/temp files *inside* `bin/` or `lib/` —
next to the protected executables — fails with `-EROFS`. `antirev-mount-rw`
fixes this by stacking a writable `overlayfs` upper on top of the decrypted
antirevfs lower:

```
overlayfs(upper = writable ext4)   ← what the app sees (read-write)
    │
antirevfs(ro, decrypt-on-read)     ← lower (ciphertext under .enc/)
```

Reads of encrypted `.so`/`.elf` fall through to the antirevfs lower and decrypt;
anything the app writes lands in the overlay's writable upper and **never
touches the ciphertext tree**.

```bash
# mount: writable decrypted view of .enc/bin at bin/
sudo kmod2/tools/antirev-mount-rw --passdata /root/proj/.enc/bin /root/proj/bin

# tear down (unmounts overlay then antirevfs, preserves the upper)
sudo kmod2/tools/antirev-mount-rw --down /root/proj/bin

# where do the app's writes (logs/locks/temp) live? — works mounted or not
sudo kmod2/tools/antirev-mount-rw --status /root/proj/bin
```

**Where written files persist / retrieving logs after unmount.** While mounted,
the app reads/writes them at the natural path (`/root/proj/bin/run.log`), exactly
as in plaintext mode. After `--down`, `bin/` is just the bare mountpoint again,
but the files are **not lost** — they stay on disk in the upper at
`/root/proj/.antirev-rw/bin/upper/` (the default upper is disk-backed ext4,
matching plaintext write semantics; `--down` never deletes it). Use
`antirev-mount-rw --status <mountpoint>` to print the upper path and list what
the app has written, or just re-mount to expose them at `bin/` again. In
production the overlay normally stays mounted (fstab/systemd), so `bin/run.log`
is always live; teardown is a maintenance action.

By default the three overlay layers (`dec/` decrypted lower, `upper/` writable,
`work/`) live under `<dirname mountpoint>/.antirev-rw/<basename mountpoint>`;
override with `--state <dir>` (point it at a tmpfs path to wipe writes on
reboot). `--passthrough <exts>` and `ANTIREV_MOUNT_OPTS` (e.g. `key=<64hex>`)
work the same as for `antirev-mount`. Covered by `tests/test_antirevfs_overlay_rw.sh`.

> **Copy-up caveat.** overlayfs copies a file *up* into the writable upper on
> first modification — and the copy is the **decrypted plaintext**. This only
> triggers if the app *rewrites an existing encrypted `.so`/`.elf`*, which
> business code does not do at runtime; new lock/log/temp files never copy up.
> If an app does rewrite a protected file, that one file becomes plaintext in
> the upper, so keep the upper on an access-controlled / reboot-wiped path.

### Key custody / keyring caveat

The module looks up a `user`-type key named `antirevfs:default` via
`request_key()` from the mount path, which searches the mounting task's
**session keyring**. So the `antirev-keyctl unlock` and the `mount` must run in
the **same session** (same shell / same systemd unit). A key added to the
per-UID `@u` keyring is *not* reliably found, because `sudo`/login
(`pam_keyinit`) installs a fresh session keyring that does not link `@u`. For an
unlock-now / mount-later-in-another-session flow, use the `key=` mount option in
`/etc/fstab`, or link `@u` into the unit's session keyring. Production
TPM/PKCS#11/dongle unseal wires into `antirev-keyctl unlock-from-tpm`.

## Test

```bash
make -C kmod2/module          # add CC=gcc-12 on the Ubuntu 6.8 dev box
sudo bash kmod2/tests/test_antirevfs.sh
```

Needs `python3` + the `cryptography` package (for `protect.py encrypt-lib`),
`gcc` (builds the test helpers), and root (insmod/mount). Runs on any kernel
where the module builds and loads. Verifies: decrypt correctness vs original
plaintext, ciphertext-on-disk,
`dlopen`+`dlsym`+call through the mount, real path (no `memfd:`) in
`/proc/maps`, strict-mode reject, passthrough whitelist, and cross-process page
sharing (identical PFN via `/proc/<pid>/pagemap`).

## Status

This is the PoC + first working implementation that resolves DESIGN.md open
question #8 (stacked FS validates: pre-encrypted `.so` loads, pages shared,
real path in maps), built and runtime-tested on mainline 6.8 and source-ported
to SLES 12 / 4.12 behind version guards (build-tested on the target). Not yet
addressed from DESIGN.md: module signing for Secure Boot, key rotation, and the
DKMS `.deb`/`.rpm` packaging around `dkms.conf`.
