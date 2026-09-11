# fusefs — userspace (FUSE) decrypt-on-read filesystem (design 3)

`fusefs/` is the **third** antirev architecture, a sibling to:

1. **stub + shim + daemon** (`stub/`, `encryptor/`, `lrxd`) — memfd + `LD_PRELOAD`.
2. **kmod2 / vcachefs** (`kmod2/`) — an in-kernel stacked filesystem.
3. **fusefs** (this dir) — a **userspace FUSE daemon** that does the same
   decrypt-on-read as kmod2, but entirely in user space.

It exists for one deployment shape that the kernel module cannot serve well:

> Products shipped as **Docker images** that a client runs on a machine whose
> **OS / kernel we do not know or control**, with **several of our products**
> (several containers) running on one host.

A kernel module is vermagic-pinned to the exact host kernel and is a single
global object shared by every container — so an unknown host can't load our
`.ko`, and multiple independently-versioned products would fight over one
module. A FUSE daemon has neither problem: `fuse` is stock on essentially every
Linux kernel (no vermagic), and **each container runs its own daemon in its own
mount namespace** — N products = N independent daemons, zero cross-coupling.

## On-disk format — IDENTICAL to kmod2 (byte-for-byte)

fusefs reads exactly what `kmod2/tools/vcache-pack.py` (and
`encryptor/protect.py make_container(..., embed_key=True, magic=FS_MAGIC)`)
already produce. No new packer. The container is the **embedded-key trailer**
form:

```
[ MAGIC:8 ][ IV:12 ][ TAG:16 ][ CIPHERTEXT:n ][ KEY:32 ][ MAGIC:8 ]
  \__________ header (36) __________/            \___ trailer (40) ___/
```

- `MAGIC` = `a7 4c 2e 91 d6 3b 08 5f` (the kmod2 neutral bytes, `ANTREV_MAGIC`).
- AES-256-GCM: the whole plaintext is one GCM message. `CIPHERTEXT` length ==
  plaintext length; `TAG` is the 16-byte GCM tag, stored **before** the
  ciphertext in the file (the Python encryptor emits `ct||tag`; we reassemble
  `ct||tag` for the AEAD, pass IV separately, no AAD).
- `plaintext_len = file_size - HDR(36) - TRAILER(40)`.
- **The AES key is embedded per file, in the trailer.** There is no mount-time
  key, no keyring — same as kmod2's embedded-key scheme.

Executables may carry an appended per-exe signature footer (identical to
kmod2), which we parse past to find the true container length:

```
[ container... ][ SIG:sig_len ][ sig_len:4 LE ][ SIG_MAGIC:8 ]
```

`SIG_MAGIC` = `3d 6a f0 12 8c 55 b4 27`. `container_len` = everything before the
sig section; all size math (plaintext length, trailer detection, unauthorized
size) uses `container_len`, not raw file size — same as kmod2.

## How it works

```
   client process  ──read()──▶  /mnt (fusefs)  ──▶  vcachefsd (daemon)
                                                        │  decrypt-on-read
                                                        ▼
                                              lower .enc tree (ciphertext)
```

- The **lower tree** is the ciphertext produced by `vcache-pack.py`.
- `vcachefsd` mounts a FUSE filesystem over a mountpoint; lookups proxy to the
  lower tree, `getattr` reports plaintext sizes, and `read` decrypts.
- glibc/`ld.so`/python/qemu see **plaintext at real paths** — so the implicit
  DT_NEEDED / ODR pain (`ANTIREV_NO_PRELOAD`) is gone, exactly as with kmod2.
- First read of an encrypted file triggers a **whole-file one-shot decrypt**
  (GCM authenticates the whole message) into an LRU plaintext cache; later
  reads are served from the cache. `FOPEN_KEEP_CACHE` lets the kernel page
  cache hold the plaintext too, so repeat reads across processes don't
  re-cross into the daemon.

## Modes (mirror kmod2)

- **strict** (default): a file under the mount lacking `MAGIC` returns `-EIO`
  unless its extension is in `--passthrough` (colon-separated) or `--passdata`
  is set.
- **`--passthrough ext:ext`**: non-magic files with a whitelisted extension are
  served verbatim (plaintext passthrough).
- **`--passdata`**: *any* non-magic file is served verbatim — the mode for a
  complete mixed-content tree (encrypted ELFs + plaintext `.py`/`.sh`/data +
  third-party plaintext ELFs). Encrypted files are still decrypted + gated.
- Read-only: the mount hosts shipped content only; runtime writes must go to a
  writable path outside the mount (same posture as kmod2 bare mount). An
  overlay-rw equivalent can be layered the same way if needed.

## The gate (decrypt-authorization)

Only an *authorized* process reaches plaintext; `cp`/backup/file-manager get the
ciphertext (trailer-stripped) or `-EACCES`.

- FUSE hands us the caller's `pid` via `fuse_get_context()`. We resolve
  identity with `readlink(/proc/<pid>/exe)` and match the **basename** against
  a **compiled-in whitelist** (`src/gate_whitelist.h`, edit + rebuild — e.g.
  `python3`, `qemu-aarch64-static`, your launcher). A dev build also honors an
  allow-list file for bring-up.
- **Deny posture — `--passthrough-cipher`**: when on, an unauthorized reader is
  served the lower ciphertext **capped at `container_len - TRAILER(40)`** so the
  embedded key is never exposed — a valid-looking but keyless, undecryptable
  container (`cp`/`objdump` "succeed" but get useless bytes). When off → hard
  `-EACCES`. Mirrors kmod2 `gate_passthrough_cipher`.
- **Kernel page-cache safety under gating:** when the gate is enforced,
  encrypted files are opened `direct_io` (no `keep_cache`), so every read is
  re-routed to the daemon and re-checked against the live caller. Otherwise the
  kernel would share one inode's cached plaintext pages across opens, and a
  later *unauthorized* opener could read plaintext an authorized opener cached
  without our handler running. Cross-process sharing is still provided
  daemon-side by the plaintext LRU cache (decrypt-once). With the gate off,
  `keep_cache` is used (everyone is authorized → safe and faster).

### Honest divergences from kmod2 (documented, not hidden)

These are the costs of moving to user space; they are acceptable under the
project threat model (at-box adversary = non-technical rookie; capable
competitor never touches the live box) but must be named:

1. **Keys live in the daemon's user memory**, not kernel memory — easier for
   root to `gcore`/`ptrace`. We `mlock` + zero key buffers, but root wins.
2. **The gate is racy (TOCTOU).** kmod2 gates atomically inside `open()` on
   `current->mm->exe_file`. We resolve `/proc/<pid>/exe` *after* the call
   arrives — a caller could `exec` between the syscall and our check, and PIDs
   can be reused. Unspoofable atomic gating is a kernel-only property.
3. **No clean exec-load vs data-read split.** kmod2 distinguishes an execve
   open (gated on the program's own path) from a data read (gated on the
   caller's exe). FUSE `open` does not carry `FMODE_EXEC` reliably, so fusefs
   gates **every** open on the caller's identity. Consequence: *directly*
   exec'ing an encrypted binary from the mount requires the launching process
   to be whitelisted. The primary target case — an interpreter/emulator
   (`python3`, `qemu-aarch64-static`) loading encrypted libs/modules — works,
   because the interpreter is the caller and is whitelisted. Direct-exec of
   encrypted native binaries is future work (see below).
4. **Performance:** cold start of a many-lib product pays a userspace
   round-trip per first fault. `FOPEN_KEEP_CACHE` + the LRU plaintext cache
   mitigate steady state; benchmark cold start on the target CPU.

## Deployment (the motivating case)

- Ship the ciphertext tree + `vcachefsd` (a static binary) + an entrypoint
  inside the Docker image. Nothing touches the host kernel beyond stock `fuse`.
- Run requirements: `--device /dev/fuse --cap-add SYS_ADMIN` (some hosts also
  `--security-opt apparmor:unconfined`). Far less than the kernel module's
  `--privileged` / `CAP_SYS_MODULE`.
- Entrypoint: mount `vcachefsd` over the product tree inside the container, drop
  privileges, exec the product. Plaintext exists only inside the container's
  mount namespace — the intended isolation posture.

### Key provenance on an unknown, root-ful host (the hard open problem)

Because the client has host root and the image ships the ciphertext, a
`docker save` captures the `.enc` tree **with the embedded keys inside it** →
decryptable offline. TPM sealing is unreliable on an unknown host. So the
load-bearing future work is the same deferred item as the other designs:
**obfuscate / derive the key inside the daemon binary** instead of shipping it
in-the-clear in each file trailer — see the repo's `project_key_in_ko` /
`project_key_obfuscation` notes (here it becomes "key in the `vcachefsd`
binary"). This design does not solve that; it inherits it.

## Not yet done

- Per-exe PKCS#7 signature verification of the *caller* exe (whitelist +
  optional allow-list file are implemented; signature is the next pass-type,
  mirroring kmod2's step 2b).
- Exec-load vs data-read split (see divergence #3).
- Overlay-rw writable-view helper (layer stock overlayfs over the fusefs lower,
  same as kmod2's `vcache-mount-rw`).
- Key obfuscation / TPM (shared with the other designs).
- Docker entrypoint + systemd/compose templates.
