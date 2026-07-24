# Layover (Self-)Mount: Eliminating the `.enc/` Tree

Companion to [`DESIGN.md`](DESIGN.md). Status: **proposal — analysis complete, PoC pending**.

> 中文摘要：本文论证把 antirevfs 直接挂载在密文所在目录自身之上（layover/self-mount），
> 从而彻底去掉 `.enc/` 并行树，使加密前后用户所见的路径、视图、操作结果完全一致。
> 结论：机制上可行（eCryptfs layover mount 有十几年先例，逐条对照本仓库代码无阻断性问题），
> 五项代价中三项可彻底解决、两项是加密方案的共同前提可管理到最优，并附带一个安全红利：
> 嵌密钥的密文容器不再暴露在可直接读取的路径上。

## Problem statement

The current design stages ciphertext in a parallel `.enc/` tree and mounts decrypted
views over `bin/` and `lib/`:

```
/root/proj/
├── .enc/bin/module_a/foo.exe    ciphertext (readable by anyone — incl. key trailer!)
├── bin/                          ← antirevfs mount, backed by .enc/bin
└── .enc/lib/ ... lib/ ...
```

This violates the transparency ideal: *the strongest encryption is the one where the
user's view, operations, and results are identical before and after protection — only
the on-disk bytes change.* The `.enc/` tree is not a requirement of the crypto format;
it is a structural by-product of the stacked-FS implementation choice. This document
proposes removing it via a **layover mount**: mount antirevfs over the very directory
that holds the ciphertext.

```
# ciphertext lives AT the original paths; antirevfs mounted over the same path
mount -t antirevfs -o ro,passdata /root/proj/bin /root/proj/bin
```

## Prior art: eCryptfs layover mount

Self-mount is not novel. eCryptfs — the stacked cryptographic filesystem this design
is modeled on — documents mounting a directory over itself, recommended by its author
Michael Halcrow (Linux Journal, *"eCryptfs: a Stacked Cryptographic Filesystem"*):

```
mount -t ecryptfs /secret /secret
```

> "Note that the lower directory and the mountpoint have the same path in this
> example... I recommend doing a layover mount **in order to help ensure that only
> eCryptfs has access to the files in the lower filesystem.** When you unmount
> eCryptfs and look in /secret, you will see the encrypted lower files."

The VFS never forbids `lowerdir == mountpoint`; `mount(2)` does not check for it.
Self-mount has a decade-plus of production precedent.

## Why this was not in DESIGN.md

The recorded May 26/28 design sessions never evaluated self-mount — it is unexplored
design space, not a rejected option. Inferable reasons the parallel tree became the
default:

1. **The shipment model locked the mental model.** Locked decision #4 (pre-encrypted
   shipping artifacts) plus the tarball layout and migration runbook
   (`mv bin .enc/bin`, `tar -xf ... -C .enc/`) all assume two trees.
2. **Mainstream eCryptfs usage is misleading.** Tutorials and the Ubuntu tooling
   (hard-coded `~/.Private` → `~/Private`) always show separate lower/upper dirs.
3. **The parallel tree has genuine migration value** (original untouched, instant
   A/B cutover, `rm -rf .enc` rollback) — a real advantage the layover design must
   buy back by other means (see Costs).

## Mechanism validation against this codebase

| Mechanism | Code | Holds under layover? |
|---|---|---|
| Mount ordering | `super.c::antirevfs_fill_super` — `kern_path(lowerdir)` | ✅ Runs before the new mount attaches; pins the underlying fs's dentry+vfsmount via `path_get`. Covering the path afterwards is irrelevant. |
| No lookup recursion | `inode.c::antirevfs_lookup` — `lookup_one_len_unlocked(name, lower_dir)` | ✅ Operates on the dcache, never crosses mount points (crossing happens only in path-walk `follow_managed`). This is the standard stacked-FS proxy mechanism; no re-entry into antirevfs. |
| Ciphertext reads | `dentry_open(&ii->lower_path, ...)` | ✅ Uses the pinned lower vfsmount, independent of mountpoint coverage. |
| Gate path matching | `gate.c` — `d_path` on exe | ✅ **Better than `.enc` mode**: exe paths are the real deployment paths (`/root/proj/bin/foo.exe`); allow-list entries match deployment docs exactly, no lower/upper path divergence. |
| `/proc/<pid>/maps` | mount-point paths shown | ✅ Byte-identical to plaintext era. |
| `stat` size | `antirevfs_getattr` reports plaintext logical size | ✅ `ls -l` indistinguishable; true on-disk size (+76 B/file: 36 B header + 40 B trailer) is shielded by the mount with no unprivileged way to observe it. |
| strict mode / `passdata` / cipher-passthrough | trailer sniffing, path-independent | ✅ Unaffected. |
| `antirev-mount-rw` (overlay upper) | overlayfs over antirevfs | ⚠️ Becomes a three-layer stack (ext4 → antirevfs → overlay). overlayfs does not care whether its lowerdir is a layover mount; expected to work, must be verified by test. |

No blocking issue found at the mechanism level.

## Security bonus: the key-embedded containers get shielded

The top weakness of the `.enc/` layout: ciphertext files — each embedding its AES key
in a trailer — sit at a directly readable path. `cp /root/proj/.enc/lib/foo.so ~/`
walks off with key+iv+tag+ct; the gate's trailer-stripping only protects reads *through*
the mount.

A layover mount closes exactly this hole: every ordinary path to the ciphertext is
covered by the mount, so all reads hit the gate. This is the original rationale for
eCryptfs's layover recommendation. Residual bypasses (a bind mount made before the
layover, another mount namespace, raw block access) still exist — but the bar rises
from *"any user, one cp command"* to *"root + namespace surgery"*.

## Costs — and their resolutions

### 1. Loss of parallel-tree migration safety — ✅ fully solvable

- **File-level parallelism replaces tree-level**: the in-place packer encrypts
  `foo.exe` → writes `foo.exe.arevtmp` → renames onto `foo.exe`, keeping the original
  as `foo.exe.bak` (or a mirrored tree under `/var/backups/`). After mount
  verification and customer sign-off, `shred -u` the backups — same semantics as
  runbook step 10, refined to file granularity.
- **Rollback**: any failure before sign-off = restore `.bak` files. Under a minute.
  Peak disk usage identical to the parallel tree (one plaintext + one ciphertext
  copy), just distributed per file.
- **Reverse tool**: encryption is reversible (key in trailer, keyfile held by the
  packer); add `--decrypt-in-place` for a backup-independent rollback path.

### 2. In-place encryption atomicity / hard links / xattrs — ✅ fully solvable

- **Atomicity**: temp file + `fsync` + `rename` — after a power cut a file is either
  old plaintext or new ciphertext, never half-written. A manifest tracks per-file
  state; reruns skip files already carrying `ANTREV01` magic and clean stray
  `.arevtmp` files — idempotent and re-entrant.
- **Hard links**: pre-scan an `inode → [paths]` map. For `st_nlink > 1` ELFs, encrypt
  once, `rename` onto the first path, then `link()`/`unlink()` the rest — link
  topology preserved.
- **xattrs/ACLs**: rename creates a new inode, so explicitly copy
  `listxattr/getxattr/setxattr` plus `chmod`/`chown` (extends the existing chmod
  logic in `copy_verbatim`).

### 3. Unmounted-window inconsistency — ⚠️ manageable to optimum, not eliminable

With no decryptor present there can be no plaintext view — a premise of any
encryption scheme (true of the `.enc/` design and of dm-crypt alike), not a new cost
introduced by layover. Manage the window:

- **systemd ordering**: mount unit with `Before=business-*.service`; business units
  with `RequiresMountsFor=/root/proj/bin`. If the mount fails, business services
  never start — no half-alive process reading ciphertext.
- **Boot-time module smoke test**: a oneshot unit running `modprobe antirevfs` that
  alarms and blocks business startup on DKMS rebuild failure (moves the existing
  runbook smoke test from install-time to every boot).
- Failure direction is fail-safe: a program reading ciphertext crashes loudly.

Residual: the DKMS-rebuild-failure downtime risk of the kernel-module route itself
(already a locked-in cost in DESIGN.md, unrelated to layover).

### 4. Double self-mount — ✅ eliminable at the root

- **Userspace**: `antirev-mount` refuses if the target is already an antirevfs
  mountpoint (`/proc/self/mounts` check).
- **Kernel-side root fix** (one line in `antirevfs_fill_super`):
  reject when the lower path already resolves onto an antirevfs superblock:
  `if (d_inode(sbi->lower_root.dentry)->i_sb->s_magic == ANTIREVFS_MAGIC) return -EINVAL;`
  Nesting antirevfs over itself becomes impossible regardless of tooling.

### 5. `/proc/mounts` visibility — ⚠️ mitigable, eradication not advised

- **Low-cost mitigation**: register the fs under an inconspicuous name (e.g. `fsdrv`
  instead of `antirevfs`); keep `show_options` free of sensitive parameters. Defeats
  casual `cat /proc/mounts` inspection.
- **Not advised**: rootkit-style mount-table hiding — unstable, trips kernel
  integrity auditing, and clashes with the DKMS legitimate-distribution story.
- The true mountless route (DESIGN.md approach B, per-inode aops hook) stays
  rejected for the original reasons.

Residual: a determined reverser can still see a non-standard fs mounted. Consistent
with the threat model — keys ship with the artifact; the goal is raising the reverse
-engineering bar, not hiding that protection exists.

### Summary

| Cost | Verdict | Means |
|---|---|---|
| Migration safety | ✅ solved | per-file `.bak` + sign-off-then-shred + `--decrypt-in-place` |
| Atomicity / hard links / xattrs | ✅ solved | temp+fsync+rename, nlink map, xattr copy, idempotent reruns |
| Unmounted window | ⚠️ managed | systemd Requires/Before ordering; fail-safe direction |
| Double self-mount | ✅ eliminated | kernel `s_magic` check (one line) |
| `/proc/mounts` line | ⚠️ mitigated | fs rename; eradication rejected |

Three of five costs have complete engineering exits; the other two are premises
shared by all encryption schemes, not new costs of the layover design.

## Implementation plan

1. **Packer**: `antirev-fs-pack.py --in-place` — temp+fsync+rename atomic writes,
   hard-link inode map, xattr/ACL copying, per-file `.bak` retention, manifest with
   idempotent re-entry, and `--decrypt-in-place` rollback.
2. **Kernel module**: nested-mount guard in `antirevfs_fill_super` (one-line
   `s_magic` check). No other module changes required by the layover design.
3. **Tools**: `antirev-mount` accepts `lowerdir == mountpoint`; refuses targets that
   are already antirevfs mountpoints. Consider a neutral `ANTIREVFS_NAME`.
4. **Deployment**: systemd mount units + `RequiresMountsFor=` on business units;
   boot-time `modprobe` smoke unit; rewritten migration runbook.
5. **Tests**: `tests/test_antirevfs_layover.sh` — rerun the full existing matrix
   (decrypt correctness, `dlopen`+`dlsym`+call, real path in maps, strict `-EIO`,
   passthrough whitelist, cipher-passthrough gate, cross-process PFN sharing) under
   layover layout, plus layover-specific checks: umount reveals ciphertext at the
   same paths, double-mount rejection, overlay-rw three-layer stack, interrupted-
   pack recovery. Extend `test_antirevfs_qemu.sh` for the aarch64 target; verify on
   both kernel 6.8 (mainline dev box) and 4.12 (SLES 12 target).

## Open questions

1. Layover behavior on the 4.12 (SLES 12) target — expected fine (same VFS
   mechanics), but the PoC must confirm before this ships.
2. overlayfs-over-layover (three-layer) for the RW view, incl. the existing copy-up
   plaintext caveat — needs the `test_antirevfs_overlay_rw.sh` matrix rerun under
   layover.
3. Whether to ship `--in-place` as the default pack mode or keep both layouts
   (`.enc/` for staged rollouts, layover for transparency-first installs).
