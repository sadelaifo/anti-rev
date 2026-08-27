# qemu-user decrypt gate (sim mode)

Per-guest decrypt gating for the ARM64-under-`qemu-aarch64-static` container. The
host kernel (vcachefs) still holds the key and decrypts; qemu supplies the one
bit the kernel can't see — **which guest is running** — so `cp`/`objdump` inside
the container get **keyless ciphertext** while the signed slave app gets
plaintext from the shared page cache.

## Why this exists

Under qemu-user every guest's `current->mm->exe_file` is `qemu-aarch64-static`,
so the kernel can't tell the slave app from an ARM64 `objdump`. Whitelisting the
emulator therefore trusts the *whole* container. This gate closes that: qemu
authorizes each guest (by its vendor signature, checked in the kernel) and, for
an unauthorized guest reading a protected file, hands it the keyless container
instead of plaintext.

## Pieces

- **Kernel** (`kmod2/module/`): a `/dev/vcachefs` control device (`ctldev.c`)
  with two ioctls, both gated on the caller being the genuine emulator
  (whitelisted basename or a signed exe):
  - `AUTHORIZE_FD(fd)` — verify a guest binary's vendor signature.
  - `OPEN_CIPHER(path)` — return the keyless ciphertext of a mount file.
- **qemu** (`linux-user/`): `arev_gate.c` + hooks in `elfload.c` (authorize the
  guest at load) and `syscall.c` (`do_guest_openat`/`do_openat2` — serve
  ciphertext to unauthorized guests, passthrough for authorized).
- **Shared protocol**: `arev_uapi.h` (this dir == `kmod2/module/arev_uapi.h`;
  keep the two byte-identical).

## Apply to a qemu tree

```bash
python3 apply-gate.py /path/to/qemu-src      # idempotent; qemu 11.0.0 anchors
cd /path/to/qemu-src
./configure --target-list=aarch64-linux-user # + your usual flags
make
```

## Build the kernel side

The control device is part of the normal module build (`ctldev.o` is in the
Makefile):

```bash
make -C kmod2/module CC=gcc-4.8        # or gcc matching your kernel
# needs CONFIG_SYSTEM_DATA_VERIFICATION (PKCS#7) for signature checks
```

## Runtime

1. Load the module and mount the ciphertext in-place as usual — the mount stays
   the plaintext (shared-cache) path.
2. Sign the guest **executables** (option 1 — exes ship as plaintext ELF +
   signature; their `.so` libs stay encrypted):
   ```bash
   python3 ../tools/authz-sign-exe.py priv.pem cert.pem /root/SW/bin/slave_app ...
   ```
3. Run qemu with:
   ```bash
   AREV_PROTECT_ROOTS=/root/SW        # dirs whose files are gated
   # AREV_GATE=off                    # disable the gate (debug)
   # AREV_GATE_LOG=/tmp/arev.log      # per-decision log
   ```
   `qemu-aarch64-static` must be authorized to drive `/dev/vcachefs` — either
   whitelist its basename in `module/gate_whitelist.h`, or sign the qemu binary.

## Test

- **Kernel device, standalone (no qemu build):**
  `sudo bash ../tests/test_qemu_ctldev.sh` — builds a throwaway module, drives
  the ioctls from a C helper, checks AUTHORIZE (signed vs unsigned), OPEN_CIPHER
  (keyless container = enc−40, no key trailer), and the caller gate.
- **End-to-end** (needs the qemu build + a cross/emulation stack): run
  `cp`/`objdump` on an encrypted lib inside the container → keyless container;
  run the signed slave app → decrypts and shares the page cache.

## Status

Written and reviewed against qemu 11.0.0 / the vcachefs module APIs, **not yet
compiled** (no toolchain in the authoring env). Expect a build-fix pass on the
target kernel/qemu — the version-sensitive kernel spots are `shmem_file_setup`,
`fget`/`fd_install`, and `kernel_write` (via the compat wrapper).
