# kmod2: Kernel-Module Filesystem (`antirevfs`) Design

Alternative architecture to `stub2/` (patched ld.so). Encryption protection moves from the dynamic linker into a custom kernel filesystem. Decryption happens during page-fault servicing in kernel space, with the kernel's page cache providing automatic cross-process page sharing without a daemon.

## Locked decisions

These are settled from prior discussion. Open questions further down.

1. **Architecture**: custom stacked filesystem (`antirevfs`) registered as a kernel module. eCryptfs-pattern overlay: ciphertext lives in a lower directory, plaintext view appears via the antirevfs mount.
2. **Distribution**: loadable kernel module via DKMS. No OS reinstall, no kernel replacement, no reboot to install. Module rebuilds automatically against kernel updates via DKMS post-install hooks.
3. **No daemon, no shim, no patched ld.so, no `antirev_client.py`.** All eliminated — see "What this replaces" below.
4. **Pre-encrypted shipping artifacts.** Existing `ANTREV01` trailer format preserved; packing pipeline reused. Encryption never happens on the customer machine.
5. **Per-subdirectory mounts**: encrypt `bin/` and `lib/` separately, leave `config/` on the underlying filesystem untouched.
6. **Strict-mode default**: files under an antirevfs mount must carry `ANTREV01` magic; missing-magic files return `-EIO`. Mixed-content directories (e.g., `lib/module_xx/data.json` alongside `lib/module_xx/foo.so`) handled via an explicit extension passthrough whitelist at mount time.
7. **Key custody**: kernel keyring. Boot-time service unseals from TPM / USB dongle / PKCS#11, adds to keyring. Key never enters userspace memory.

## Problem this solves

### Pain points in current architecture

1. **Implicit cross-lib symbol dependencies** — `libFoo.so` references symbols defined in `libBar.so` with no `DT_NEEDED` edge. `dlopen_shim`'s closure walk misses the edge; lazy binding fails. `ANTIREV_NO_PRELOAD=1` is the existing escape hatch but is opt-in per-app.
2. **ODR violations** — same `.c` compiled into two libs, or two libs exporting the same symbol with different impls. Tested-pass in plaintext, breaks under encryption because preload-order ≠ DT_NEEDED-order and `/proc/self/fd/N` paths break glibc's link-map dedup.
3. **Daemon as architectural overhead** — fd-based protocol, closure graph, symlink-dir lifecycle, lifecycle reaper. ~1500 LOC of moving parts to provide cross-process page sharing.
4. **`memfd: (deleted)` artifact in `/proc/<pid>/maps`** — visible signal that something is decrypting in memory.
5. **`antirev_client.py` complexity** — Python integration requires `sys.meta_path` patching, `ctypes.CDLL` interception, daemon protocol speaker.
6. **Per-arch shim complexity** — `aarch64_extend_shim` for `ANTI_LoadProcess` and `popen`/`pclose` workarounds; LD_PRELOAD scrubbing differences between arches.

### What the kernel-module approach gives

The kernel's page cache is keyed on `(struct address_space*, page_index)`. If two processes mmap the same inode, they share physical pages automatically — no SCM_RIGHTS, no fd-passing, no daemon. If your decryption populates the page cache with plaintext, every process reading the file sees plaintext, sharing for free.

The architecture: ciphertext on disk → kernel `read_folio` callback decrypts on page fault → page cache holds plaintext → all processes share.

**Side effects that follow**:

- Glibc sees encrypted libs as plaintext. All symbol resolution (DT_NEEDED, dlopen, ctor ordering, ODR dedup) works natively. Implicit-dep and ODR pain disappears with no per-app workarounds.
- No `memfd:` artifact — `/proc/<pid>/maps` shows real file paths.
- Python integration is automatic — `open()` returns plaintext, no `antirev_client.py` needed.
- Cross-process page sharing happens by kernel design, no daemon required.

## Approaches considered and rejected

| Approach | Why rejected |
|---|---|
| **Status quo (daemon + shims)** | Doesn't fix symbol resolution. Memfd artifact. Per-arch complexity. |
| **stub2: patched ld.so + slimmed daemon** | Requires glibc fork (LGPL distribution burden, per-glibc-version maintenance — SLES 12 glibc 2.22 + aarch64 glibc ~2.31 spread). Daemon still required for page sharing. Replaces a system file with high blast radius. |
| **fscrypt** (kernel-native file encryption) | Requires plaintext at install time (fscrypt encrypts on write). Cannot ingest pre-encrypted artifacts. Hard constraint violation. |
| **FUSE filesystem** | Userspace-side decryption requires a long-lived FUSE daemon process — that's still a daemon, just renamed. Plus FUSE has historically had quirks around `MAP_PRIVATE` and page cache lifetime. |
| **dm-crypt / LUKS on lib partition** | Whole-partition granularity. Once mounted, every byte is plaintext. No per-file policy. |

## Architecture

### Module structure

```
antirevfs.ko
├── filesystem registration (register_filesystem)
├── superblock setup (antirevfs_mount)
├── inode lookup (proxies to lower file under .enc/)
├── address_space_operations:
│   ├── decrypt_aops.read_folio    — AES-GCM decrypt on page fault
│   └── passthrough_aops.read_folio — plain copy for whitelisted extensions
├── file operations:
│   └── antirevfs_open — trailer-magic check, picks aops
└── key access (kernel keyring lookup)
```

Estimated total: ~500-800 LOC. Comparable to a minimal eCryptfs-like overlay.

### Dispatch flow

For `open("/root/proj/lib/module_xx/foo.so")`:

1. VFS path walk reaches `/root/proj/lib` — antirevfs mount point.
2. From there, dispatch uses antirevfs's operation tables.
3. `antirevfs_iops->lookup` resolves to inode backed by lower file `/root/proj/.enc/lib/module_xx/foo.so` (raw ext4).
4. `antirevfs_open` reads the trailer; on `ANTREV01` match, assigns `decrypt_aops` to the inode's `address_space`.
5. `mmap()` creates a VMA backed by the antirevfs inode.
6. First page access faults. Kernel calls `antirevfs_read_folio(folio)`.
7. Callback: reads corresponding ciphertext page from lower file, decrypts with keyring-held key, writes plaintext into folio, marks uptodate.
8. Page cache now holds plaintext for `(antirevfs_inode, offset)`.
9. Any other process mmapping the same inode shares those physical pages via the page cache.

Outside antirevfs mounts, the kernel routes through whichever filesystem owns the path. No interaction.

### Trailer-magic per-file dispatch

Each inode picks its aops at open time:

```c
static int antirevfs_open(struct inode *inode, struct file *file) {
    if (has_antrev_trailer(ANTIREV_I(inode)->lower_file))
        inode->i_mapping->a_ops = &antirevfs_decrypt_aops;
    else if (extension_in_passthrough_whitelist(file))
        inode->i_mapping->a_ops = &antirevfs_passthrough_aops;
    else
        return -EIO;   // strict mode
    return 0;
}
```

This makes mixed `bin/` and `lib/` contents work cleanly while keeping strict-mode safety: a file that *should* have been encrypted but slipped through the packer is loud, not silent.

### Read-only by design

The module exposes `read_folio` only. No `write_folio`, no `writepage`. Mounts are `ro` (or RW for non-encrypted files only — TBD). Business code does not write `.so` or `.elf` files at runtime, so this is fine. Config writes go to the unprotected `config/` tree.

### Why stacked overlay (not custom-aops-on-existing-FS)

Two designs considered:

- **A. Stacked filesystem** (chosen): new mount, lower files on existing ext4, upper view via antirevfs. eCryptfs / overlayfs pattern. Stable kernel interfaces, isolation-friendly.
- **B. Hook into ext4's aops per-inode**: at file open, sniff trailer, swap in custom aops. No new mount needed. More elegant but trickier inode-lifetime handling, fragile against kernel-internal changes.

Picked A for maintenance reasons — multi-year codebase needs to survive kernel upgrades.

## What this replaces

Components deleted or dramatically shrunk:

| Component | Status under kmod2 |
|---|---|
| `stub` launcher | Deleted. Protected exes are regular ELFs at real paths. No `fexecve`, no memfd. |
| `antirev_shim` (entire DSO) | Deleted. `LD_PRELOAD` no longer needed. |
| `exe_shim.c` | Deleted. No identity hiding needed — `/proc/self/exe` shows real path naturally. |
| `dlopen_shim.c` | Deleted. glibc reads encrypted libs as plaintext via antirevfs. |
| `aarch64_extend_shim` (ANTI_LoadProcess hook) | Deleted. `.elf` files read as plaintext, business API works unmodified. |
| `aarch64_extend_shim` (popen/pclose) | **Kept** — independent aarch64 glibc bug unrelated to encryption. May move to a tiny `libantirev-aarch64-popen.so` LD_PRELOAD-only DSO. |
| `daemon_client.c` | Deleted. |
| `.antirev-libd` daemon | Deleted. |
| `antirev_client.py` | Deleted. Python imports work natively. |
| Symlink dir lifecycle (atexit, daemon reaper) | Deleted. No symlink dir. |
| `ANTIREV_*` env vars (FD_MAP, LIBD_SOCK, ENC_LIBS, SYMLINK_DIR, CLOSE_FDS, NO_PRELOAD) | All deleted. |
| `antirev-pack.py` | Mostly preserved — still encrypts files with `ANTREV01` trailer. New: encrypts `.py` files too. Output layout change: ciphertext goes under `.enc/` subtree. |
| Encryption format (AES-256-GCM + `ANTREV01` trailer) | Preserved. |
| Key custody (TPM / USB / PKCS#11) | Preserved, moved to kernel keyring. |

`stub2/` plan (patched ld.so) becomes unnecessary if kmod2 ships — they target the same problem.

## Installation model

### What ships

| Artifact | Purpose |
|---|---|
| `antirev-kmod-dkms_X.Y_all.deb` (or `.rpm`) | Module source + DKMS wrapper. DKMS builds the `.ko` against the customer's running kernel. |
| `antirev-tools_X.Y.deb` | Userspace utilities: `antirev-keyctl`, `antirev-mount`, install helpers. |
| `business-software-encrypted_X.Y.tar.zst` | Pre-encrypted business tree. Layout matches the target install layout under `.enc/`. |
| Key material | TPM-sealed blob / USB dongle / PKCS#11 device, depending on chosen custody mode. |

### Filesystem layout

**Before** (plaintext install):
```
/root/proj/                              ← ext4
├── bin/module_a/foo.exe                  plaintext
├── lib/module_a/libfoo.so                plaintext
├── lib/module_a/foo.py                   plaintext
└── config/module_a/foo.conf              plaintext
```

**After** (encrypted install):
```
/root/proj/                              ← ext4, unchanged
├── .enc/bin/module_a/foo.exe             ciphertext
├── .enc/lib/module_a/libfoo.so           ciphertext
├── .enc/lib/module_a/foo.py              ciphertext
├── bin/                                  ← antirevfs mount, backed by .enc/bin
│   └── module_a/foo.exe                  decrypted-on-read view
├── lib/                                  ← antirevfs mount, backed by .enc/lib
│   ├── module_a/libfoo.so                decrypted-on-read view
│   └── module_a/foo.py                   decrypted-on-read view
└── config/module_a/foo.conf              plaintext, untouched
```

Two mount points, one per encrypted subtree. `config/` never crosses an antirevfs mount.

### Persistent mount via fstab

```
/root/proj/.enc/bin   /root/proj/bin   antirevfs   defaults                     0 0
/root/proj/.enc/lib   /root/proj/lib   antirevfs   defaults,passthrough=json,md 0 0
```

The `passthrough=` mount option whitelists extensions for plaintext passthrough — `lib/` may contain `README.md` / `data.json` alongside encrypted `.so` and `.py` files.

### Boot-time key unlock

systemd unit ordered before mount target:

```ini
[Unit]
Description=Unlock antirev keys
DefaultDependencies=no
Before=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/antirev-keyctl unlock-from-tpm
RemainAfterExit=yes

[Install]
WantedBy=local-fs.target
```

Key resident in kernel keyring before any antirevfs mount is attempted.

## Migration runbook (plaintext → encrypted)

For a customer machine currently running plaintext business software, technician on-site:

```bash
# 0. Pre-flight (non-destructive)
uname -r
modinfo loop || abort  # confirm CONFIG_MODULES
ls /lib/modules/$(uname -r)/build/ || abort  # kernel headers present
df -h /root/proj  # need room for parallel .enc tree during migration

# 1. Snapshot
tar -cf /var/backups/business-plaintext-$(date +%F).tar -C /root/proj bin lib

# 2. Install module + tools (still non-destructive, no behavior change)
dpkg -i antirev-kmod-dkms_X.Y_all.deb
modprobe antirevfs                  # smoke test — if this fails, abort cleanly
lsmod | grep antirevfs
dpkg -i antirev-tools_X.Y.deb

# 3. Quiesce business (start of downtime window)
systemctl stop business-*
lsof +D /root/proj | head           # verify nothing still open

# 4. Restage
mkdir -p /root/proj/.enc
mv /root/proj/bin /root/proj/.enc/bin
mv /root/proj/lib /root/proj/.enc/lib
mkdir /root/proj/bin /root/proj/lib

# 5. Encrypt in place (one-time cost during migration)
antirev-encrypt /root/proj/.enc/bin
antirev-encrypt /root/proj/.enc/lib

# 6. Deliver key
antirev-keyctl unlock               # technician inserts dongle / unseals TPM

# 7. Mount
mount -t antirevfs /root/proj/.enc/bin /root/proj/bin
mount -t antirevfs /root/proj/.enc/lib /root/proj/lib

# 8. Verify
file /root/proj/bin/module_a/foo.exe        # ELF
file /root/proj/.enc/bin/module_a/foo.exe   # data
ls -la /root/proj/config/                   # untouched

# 9. Resume (end of downtime window)
systemctl start business-*

# 10. After customer sign-off, destroy plaintext backup
shred -u /var/backups/business-plaintext-$(date +%F).tar
rm -rf /var/backups/business-plaintext-$(date +%F).tar
```

**Downtime window**: step 3 → step 9, dominated by step 5 (proportional to total `bin + lib` size). For a fresh install where step 5 is skipped (artifact already encrypted), the window is <30 seconds.

**Rollback**: any time before step 10, restore from the `bak` directory and remove the antirevfs mounts. Box returns to plaintext, working, in under a minute.

### Pre-staged install variant

Maximum pre-staging shrinks the onsite window:

- Ship `antirev-kmod-dkms` and `antirev-tools` via routine maintenance update before technician visit. Module already built and ready to load.
- Ship encrypted tarball via normal software distribution. Already on disk at `/var/cache/antirev/`.
- Pre-configure `/etc/fstab` and `antirev-keyctl.service`.

Onsite work compresses to:

```bash
systemctl stop business-*
mv /root/proj/{bin,lib} /root/proj/.enc/
mkdir /root/proj/{bin,lib}
antirev-keyctl unlock-from-tpm
systemctl daemon-reload && mount -a
tar -xf /var/cache/antirev/business-encrypted.tar.zst -C /root/proj/.enc/
systemctl start business-*
```

~5 minutes downtime.

## Tradeoffs

### Wins (vs current architecture)

- Implicit-dep and ODR problems disappear (glibc native semantics).
- ~3000 LOC deleted across stub, shims, daemon, Python client.
- No `memfd:` artifact in `/proc/<pid>/maps`.
- No symlink dirs, no env-var bookkeeping, no closure walks.
- Per-arch differences shrink — only `aarch64_extend_shim::popen` survives, in a much smaller DSO.
- Python integration is automatic.

### Wins (vs stub2 patched-ld.so)

- No glibc fork — no LGPL distribution burden, no per-glibc-version pinning.
- Cross-process page sharing without a daemon.
- Doesn't replace any system file — purely additive kernel module.

### New costs

- **Kernel module maintenance per kernel version.** DKMS automates the rebuild but each kernel that changes VFS internals enough to break the module requires a source-level fix. Realistically: 1 engineer-day per major kernel upgrade if the kernel is moving.
- **GPL constraints.** Module needs `MODULE_LICENSE("GPL")` to use VFS exports. Decryption logic ships as GPL source. Mitigation: keep the module thin (AES-GCM + trailer parse only), ship key custody and policy logic in obfuscated userspace.
- **Bugs panic the box.** Kernel module work needs tighter QA than userspace. Test plan must include: corrupted trailers, missing keys, key rotation mid-mount, oversized files, unaligned access, concurrent open/close storms.
- **Key in kernel memory exposes new attack surface.** Lock down via OS image hardening:
  - `CONFIG_STRICT_DEVMEM=y`, `CONFIG_DEVMEM=n` if possible
  - `/proc/kcore` permissions or disable via `CONFIG_PROC_KCORE=n`
  - `kernel.kexec_load_disabled=1` post-boot via sysctl
  - `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`
  - No `kgdb`, no kmemleak in production builds
- **Reverse-engineering attack surface shifts to `.ko` file.** Layer 1-3 hardening (visibility, strings, key-out-of-binary) applies to the module. Module is small enough to be carefully obfuscated.

## Open questions

1. **Kernel version support range.** Need confirmed kernel versions for both customer arches. VFS interfaces have changed across releases (e.g., `read_folio` is new, older kernels have `readpage`). Decision: do we maintain one module per major kernel series, or a single source with compat shims?
2. **Stacked FS vs direct aops hook** — chosen stacked FS, but worth a PoC to confirm no glibc-side surprises (path-identity in link-map dedup, dlopen path resolution under stacked-mount).
3. **Read-write or read-only mounts?** Business code presumably doesn't write `.so` files at runtime. Confirm with team. If yes, ro is simpler and safer.
4. **Module signing.** Enforced module signing (Secure Boot / lockdown mode) requires shipping a signed `.ko` or installing the customer's signing key. Add to install pre-flight.
5. **Key rotation.** How to add a new key to the keyring and re-encrypt artifacts without taking the mount offline. Probably: dual-key support, mount accepts either key, packer rotates on next build.
6. **fsck / disk-integrity tooling.** Customers running periodic fsck or backup tools will see ciphertext under `.enc/` — confirm no operational surprise (e.g., antivirus alerting on high-entropy files).
7. **Resource accounting.** Page cache occupancy attributed to antirevfs mount. Memory pressure / OOM behavior under load. Test under realistic concurrent-process counts.
8. **PoC validation step** before committing to full design:
   - 50-line module registering stacked FS with no-op (XOR) `read_folio`.
   - Confirm: pre-XOR'd `.so` loads successfully via `dlopen`.
   - Confirm: two processes mmapping share physical pages (verify via `/proc/<pid>/pagemap`).
   - Confirm: `/proc/<pid>/maps` shows real file path.
   - If all three hold, the rest is engineering.

## Discussion history

This design captures the May 28 follow-up discussion to the May 26 `stub2/DESIGN.md` session. Key decision points:

- Eliminated daemon (originally a stub2 component) by recognizing kernel page cache provides automatic cross-process sharing when decryption populates the page cache directly.
- Rejected fscrypt due to "shipped artifacts must be pre-encrypted" constraint (fscrypt encrypts on write, can't ingest pre-encrypted files).
- Rejected FUSE (still requires long-lived daemon process).
- Settled on stacked-FS kernel module as the design that satisfies: pre-encrypted shipment + cross-process page sharing + no daemon + symbol-resolution-by-natural-glibc + minimal artifacts in `/proc`.
- Established that installation requires neither OS reinstall nor kernel replacement — DKMS-packaged module, no reboot needed for the module itself, no reboot needed for the mounts.
- Resolved per-subdirectory mount strategy after recognizing `config/` should stay on the underlying filesystem at full performance.
- Resolved mixed-content (`.so` + `.py` + `.json` in same dir) handling: strict-mode + extension passthrough whitelist + encrypt `.py` files alongside `.so`.
