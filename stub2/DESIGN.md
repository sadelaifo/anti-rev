# stub2 — antirev built into a custom glibc ld.so

## Status

Design draft. No code yet. Sibling to `stub/`.

## Why this exists

The current `stub/` + `daemon` + `antirev_shim` architecture works, but introduces seams between encrypted-lib loading and plaintext loading. Those seams cause real, recurring failures in the protected business stack:

1. **Implicit symbol dependencies**: `libFoo` undefined-references a symbol defined in `libBar`, with no `DT_NEEDED` edge declared either direction. Production exes have many of these. `dlopen_shim`'s per-dep preload doesn't reach them.
2. **Implicit circular dependencies**: `libFoo`↔`libBar` reference each other's undefined symbols, neither declares the edge. Glibc handles cyclic DT_NEEDED natively at exe-init time, but the affected libs are reached via `dlopen`, where the per-dep preload loop loads them one-at-a-time with ctors running between — breaking the cycle.
3. **ODR violations baked into the build**: same `.c` file compiled into two libs both linked by one exe; or two libs exporting the same symbol with different bodies. Plaintext "happened to work" because glibc's natural load order made one definition win consistently. Under encryption, preload reordering and memfd path identity flip the outcome, dev-team test pass becomes runtime crash.

These are dev-team mistakes. They are also not going away. Owning the dynamic linker reduces them from "every new instance is a firefight" to "implemented once as policy."

Stealth (no `memfd:` in `/proc/self/exe`, no `LD_PRELOAD` leak, no second exec) is a real secondary benefit but not the driver.

## Goal (one line)

**Encrypted libs should produce bit-identical load semantics to plaintext libs, from glibc's perspective.**

Once that holds, every "works plaintext, fails encrypted" bug class disappears because there is no plaintext-vs-encrypted distinction at the loader level.

## Locked decisions

The four shape-defining decisions, with the reasoning that got us here:

1. **Approach 1 — patched glibc, not appended payload.** We need control over link-map dedup, symbol resolution order, and the "map-everything-then-init" dlopen funnel. None of those hooks are exposed via `LD_PRELOAD`; all of them are internal to ld.so. Approach 2 (binary patching stock ld.so) can't reach them.

2. **Replace the system ld.so.** We own the OS image. ld-antirev is shipped at `/lib64/ld-linux-x86-64.so.2` (and equivalents per-arch), so stock `PT_INTERP` already points at it. No `patchelf --set-interpreter` step on business exes. **Hard requirement that falls out**: ld-antirev must be a strict drop-in for stock ld.so for all non-antirev workloads (every binary on the box goes through it, including `bash`, `sshd`, `systemd`).

3. **No `memfd_create` inside ld-antirev for loading.** memfd was a workaround for `fexecve`'s "give me a fd" interface in the old stub. Since ld-antirev maps ELF segments directly via internal glibc APIs, there is no exec involved and no fd needed for decrypted content. ELF segments are mapped with `mmap(MAP_PRIVATE | MAP_ANONYMOUS, ...)` and the decrypted bytes are `memcpy`d in. Kills the `ANTIREV_CLOSE_FDS` workaround, the symlink dir, the `/proc/self/fd/N` paths, the `memfd: (deleted)` artifact in `/proc/self/maps`. (The daemon still uses memfd internally — see below.)

4. **Daemon stays, but in a much slimmer role.** Cross-process page sharing of decrypted libs requires a long-lived process to hold the canonical memfd. Without it, 100 long-running exes × ~500 MB working set = ~50 GB peak resident memory; KSM eventually folds duplicates but takes minutes and costs CPU. With daemon: ~500 MB total via SCM_RIGHTS'd shared memfds. The complexity is worth it at this scale.

## Out of scope

- Hardware-key / Layer 3 work. Independent track. The daemon's "key custody" role makes adopting it easier later, but stub2 doesn't depend on it.
- aarch64 `ANTI_LoadProcess` hijack and aarch64 `popen` workaround. Live in `antirev_shim`, unaffected by stub2.
- `antirev-pack.py`'s per-lib encryption pipeline. Reused unchanged — same trailer format (`ANTREV01` magic + AES-GCM payload) on encrypted libs and exes.

## Architecture

### Runtime flow

1. Kernel `execve`s a protected business exe. `PT_INTERP` = standard `/lib64/ld-linux-x86-64.so.2`. Kernel loads ld-antirev as the interpreter, jumps to its entry.
2. ld-antirev's modified `dl_main()` runs:
   a. Detect whether the main exe is encrypted by checking trailer magic at file end.
   b. If encrypted: connect to the daemon (Unix socket at a fixed path, e.g. `/run/antirev/libd.sock`). Send `OP_GET_LIB` for the main exe. Receive a memfd via SCM_RIGHTS. Override glibc's "main-exe link-map" to use this memfd as the source of bytes.
   c. If not encrypted: skip — plaintext load proceeds exactly as stock glibc would.
3. Continue normal `dl_main()`:
   - Walk main exe's DT_NEEDED.
   - For each requested SONAME, ld-antirev's modified `_dl_map_object` opens the on-disk file, checks for trailer magic.
     - Encrypted: ask daemon for memfd of this lib, mmap it as file-backed (`MAP_PRIVATE`, fd from daemon). Pages shared across all processes that asked the daemon for the same lib.
     - Plaintext: stock path, file-backed mmap of the on-disk `.so`.
   - **Bulk map + relocate** — every lib in the closure is mapped and relocated before any of their ctors run. Glibc already does this for exe-init DT_NEEDED; stub2 ensures dlopen path uses the same code path.
   - Run all ctors at the end of the closure (DT_INIT_ARRAY, deps-before-dependents).
4. Jump to main exe's `_start`.

### Loader policy changes (the heart of stub2)

Surgical modifications to glibc's `elf/` subdirectory, kept as patches against pinned glibc:

- **`dl-load.c` — encrypted-magic detection in `_dl_map_object_from_fd`**: before the normal mmap dance, read the trailer. If it's ours, decrypt-via-daemon path (file-backed mmap of daemon-served memfd). Otherwise, untouched.
- **`dl-load.c` — link-map dedup by SONAME**: when comparing existing link-map entries against a new load request, prefer SONAME equality over `l_name` path equality. Fixes "memfd path A ≠ memfd path B even if same lib." Gate behind a flag set only on our daemon-served entries, so plaintext semantics for non-antirev workloads are unchanged.
- **`dl-open.c` — funnel dlopen through bulk-load path**: when a dlopen target is encrypted, expand to its full encrypted-lib closure, map+relocate all of them, then run ctors as one batch. Eliminates the per-dep ctor-during-load failure mode that today's `dlopen_shim` preload loop hits on circular implicit deps.
- **`dl-deps.c` — augmented DT_NEEDED**: at dependency-walk time, daemon hands us an "extra deps" list per lib (the implicit edges discovered at pack time via `.dynsym` scanning). Splice them into the dependency list as if they were declared `DT_NEEDED`. Glibc's existing cycle handling then resolves circular implicit deps correctly.
- **`dl-init.c` — ctor order policy**: unchanged from stock semantically (deps before dependents). Only difference: dlopen-time ctors batch at end of closure load, not per-lib.
- **`rtld.c` — main-exe magic detection + daemon connect**: new early code in `dl_main()` before any glibc init that depends on main exe contents. Magic check, daemon socket connect on hit, OP_GET_LIB for the main exe.

Everything else in glibc is unchanged.

### Strict plaintext compatibility

Since ld-antirev replaces the system ld.so, every binary on the box uses it. Non-antirev workloads must behave **bit-identically** to stock. Concretely:

- Trailer magic detection happens before any structural decisions. If absent, ld-antirev takes the stock code path with zero observable difference.
- All antirev-specific link-map flags and dedup overrides are gated on per-entry markers set only when daemon-served. A link-map entry for `/usr/lib/libcrypto.so.3` (plaintext) is identical to what stock glibc would produce.
- Daemon connection is attempted only when an encrypted ELF is seen. A box running ld-antirev with no encrypted binaries never opens the daemon socket. (Daemon may not even be running — fine.)
- Test plan: run the full OS test suite under ld-antirev. Boot, package install, common services. Anything that fails identifies a compat regression.

### Daemon (slimmed)

Role in stub2:

- Key custody (now: embedded key; future: TPM/PKCS#11 unwrap at daemon start).
- Decrypt encrypted on-disk files to memfds. Lazy — on first request per lib. Cached for daemon lifetime.
- Serve memfds via SCM_RIGHTS over a Unix socket at a fixed path.

What's removed vs today's daemon:

- No closure graph maintenance (`build_deps_graph`). ld-antirev does its own DT_NEEDED walk via stock glibc machinery.
- No `OP_GET_CLOSURE`. Just `OP_GET_LIB` (single lib by basename or full path).
- No symlink dir management. No `sweep_dead_symlink_dirs` reaper.
- No `OP_LIST` / `OP_NAMES` proactive publishing. Linker discovers encryption per-file via magic check.

Protocol shrinks from ~5 opcodes to 1-2. The daemon code base should shrink from ~1500 LOC to ~200-300 LOC.

### What stub/shim become

Sliced down dramatically:

- `stub/exe_shim.c` — identity hide via readlink/realpath/getauxval: **deletable**. `/proc/self/exe` shows the on-disk wrapper path (or the encrypted business exe path directly), not a memfd artifact. Nothing to hide.
- `stub/dlopen_shim.c` — dlopen interception: **deletable**. Linker handles dlopen of encrypted libs natively.
- `stub/daemon_client.c` — daemon protocol: **moved into ld-antirev**.
- `stub/aarch64_extend_shim.c` — `ANTI_LoadProcess` hijack and aarch64 `popen` workaround: **stays as antirev_shim.so for aarch64 only**. These are libc-level concerns, unrelated to load semantics. ld-antirev doesn't replace them.
- Old `stub/stub.c` standalone launcher: **deletable** once stub2 is the only path.

`antirev_shim` shrinks from "intercept everything" to "aarch64-specific business-API hijack." Cleaner separation of concerns.

## Build strategy

- Pin to one glibc version (e.g. 2.35 — based on oldest customer-supported distro, though OS-ownership relaxes this).
- Build in a hermetic container. The build artifact is `ld-antirev-<arch>.so.2`. Per-arch: x86_64, aarch64.
- CMake integration: `ExternalProject` that builds glibc and extracts only the dynamic linker. Cache aggressively — glibc build is 5-20 minutes.
- Source modifications kept as patches in `stub2/patches/` applied to a pinned glibc tarball. Easier to maintain across glibc upgrades than a full fork.

### LGPL

Modified glibc is LGPL. Since we ship in our own OS image:

- Distribute the source patches and a build recipe alongside the OS. Satisfies the "corresponds to source" clause.
- Business code is unaffected; only ld-antirev's patches need to be public.
- Practical artifact: `stub2/patches/*.patch` + `stub2/BUILDING.md`.

## Migration

- stub2 lives alongside stub/. Per-deployment opt-in via packing config.
- Same daemon code (with slimmed protocol) serves both architectures during transition.
- Mixed deployments work: a stub-based exe and a stub2-based exe in the same install dir both talk to the same daemon for the same encrypted libs.

## Open questions

1. **glibc version pin**: which version? Bounds the syscall/ABI floor. Pick one once we know the target OS base.
2. **Daemon socket path**: hardcoded (`/run/antirev/libd.sock`) or env-configurable? Hardcoded is simpler and matches the "we own the OS" assumption. Env override useful for tests only.
3. **Daemon autostart**: launched by systemd at boot, or on first connect by ld-antirev? Lean: systemd unit, started before any business exe. Eliminates startup races.
4. **Trailer format**: reuse current `ANTREV01` magic + AES-GCM, or define a new one (and as a side effect, drop the obvious magic string)? Reuse is simpler; new format combines naturally with Layer 2 string obfuscation.
5. **Python interpreters**: do we also rewrite `antirev_client.py` flow now that ld-antirev handles `ctypes.CDLL → dlopen → encrypted lib` natively? Likely yes — antirev_client becomes a thin compat layer or goes away entirely.
6. **Fail-open mode for dev**: env var to force ld-antirev to skip encryption checks (`ANTIREV_LDSO_BYPASS=1`)? Dangerous in prod, valuable in dev. Probably yes, with a loud log message.
7. **Crash diagnostics**: ld-antirev failures are catastrophic (process never reaches ctors). Need a clear `ANTIREV_LDSO_LOG=/path` env var with line-buffered structured output.
8. **Daemon protocol**: stick with current binary frame format, or simplify? Probably simplify since the opcode count drops to 1-2.
9. **Test infrastructure**: existing test suite uses stub-based exes. Need a parallel stub2 fixture path, or a build flag that flips test fixtures to stub2. The latter once stub2 reaches feature parity.

## What we need before writing code

- Decision on glibc version pin (question 1).
- Decision on Python interpreter handling (question 5).
- A glibc source tree pinned and building cleanly in a hermetic container.
- A minimum-viable test case: one encrypted exe + one encrypted lib + the smallest possible patched ld.so that loads and runs it. From there, add policy.
