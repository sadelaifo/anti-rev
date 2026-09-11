# fusefs — userspace decrypt-on-read FUSE daemon (antirev design 3)

A userspace alternative to the kmod2 kernel module, built for shipping products
as **Docker images to unknown client hosts**: `fuse` is stock on every kernel
(no vermagic), and each container runs its own daemon in its own mount
namespace (no shared global module). It decrypts the **same** `ANTREV01`
embedded-key containers that `kmod2/tools/vcache-pack.py` already produces — no
new packer.

See [`DESIGN.md`](DESIGN.md) for the full rationale, threat-model fit, and the
honest divergences from the kernel module (keys in user memory, racy gate,
no exec-load split, performance).

## Build

```sh
# deps:  Debian/Ubuntu: libfuse3-dev libssl-dev
#        SLES/openSUSE:  fuse3-devel libopenssl-devel
make                 # dynamic
make static          # static binary for shipping in an image
```

## Run

```sh
# decrypt a ciphertext tree at <lower> onto <mnt>, full mixed-content mode:
./vcachefsd <lower> <mnt> --passdata

# with the gate (only whitelisted/allow-listed callers decrypt), unauthorized
# readers get a keyless container instead of EACCES:
./vcachefsd <lower> <mnt> --passdata --gate --passthrough-cipher

unmount:  fusermount3 -u <mnt>
```

Options: `--passdata`, `--passthrough e:e`, `--gate`, `--authz FILE` (dev
allow-list), `--passthrough-cipher`, `--cache-mb N`. The compiled-in caller
whitelist is `src/gate_whitelist.h` (edit + rebuild).

Runtime requirements in a container: `--device /dev/fuse --cap-add SYS_ADMIN`
(some hosts also `--security-opt apparmor:unconfined`).

## Test

```sh
make && bash tests/test_fusefs.sh
```

Needs `fusermount3`, `/dev/fuse`, and `python3` with `cryptography` (to build
containers exactly like the packer). No kernel module, usually no root.

## Status

v1: decrypt-on-read, strict/passthrough/passdata modes, caller-identity gate
(whitelist + dev allow-list), keyless passthrough-cipher deny posture, LRU
plaintext cache. **Not yet:** per-exe signature verification of the caller,
exec-load vs data-read split, overlay-rw writable view, key obfuscation/TPM,
Docker entrypoint templates. Authored on a Windows box — **build and run the
tests on Linux.**
