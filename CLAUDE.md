# antirev

Binary protection system that encrypts executables and shared libraries, then runs them from memory (memfd) to prevent reverse engineering. Key components:

- **stub**: C launcher that decrypts bundled binaries into memfds and executes via `fexecve`
- **exe_shim**: LD_PRELOAD shim that intercepts `readlink`, `realpath`, `getauxval` to hide memfd paths from the protected process
- **dlopen_shim**: LD_PRELOAD shim that redirects `dlopen()` calls to decrypted memfd-backed libraries via `ANTIREV_FD_MAP`
- **aarch64_extend_shim** (aarch64-only): LD_PRELOAD shim that (a) intercepts `ANTI_LoadProcess(struct ANTI_ProcessInfo *)` to rewrite `info->ltrBin` from an on-disk `.elf` path to a `/proc/self/fd/N` memfd populated from the daemon; (b) hosts the aarch64 `popen`/`pclose` workaround moved out of `exe_shim.c` (glibc's vfork-based popen corrupts memfd-heavy parent processes on this arch).
- **encryptor** (`protect.py`, `antirev-pack.py`): Python tools that encrypt and bundle binaries with AES-256-GCM
- **daemon mode** (`.antirev-libd`): a lightweight lib-server process that scans its directory for encrypted `.so` files, decrypts them into memfds, and serves the fds to client processes via SCM_RIGHTS
- **antirev_client.py**: Python client that connects to the daemon, receives decrypted lib memfds via SCM_RIGHTS, and patches `import` + `ctypes.CDLL` to transparently load encrypted libs. Handles dependency ordering via `_ensure_loaded()` which recursively preloads transitive DT_NEEDED deps with `RTLD_GLOBAL`.
- **build.py**: compiles/obfuscates Python source files via Cython, Nuitka, or PyArmor

## Target environment

This project protects a business software suite consisting of:
- 100+ executables
- 550+ shared libraries
- 1000+ Python scripts (some of which dlopen encrypted .so files)

The business software also uses third-party libraries (e.g. `libdopra.so`, `libprotobuf.so`, open62541, Boost) which are NOT encrypted but coexist in the same processes.

## Build

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

## Testing

Always run the full test suite after adding features or making changes:

```bash
cmake -DBUILD_DIR=build -DSRC_DIR=. -P cmake/run_all_tests.cmake
```

New features must include a corresponding test case that verifies correctness and demonstrates the failure mode without the fix.

When adding or changing features, update this CLAUDE.md file to reflect the new behavior or architecture changes.

## Architecture notes

- Protected binaries run from memfd via `fexecve`. `/proc/self/exe` points to `memfd:name (deleted)`.
- The exe_shim constructor may run after C++ global static initializers in DT_NEEDED libraries. On x86_64, `is_owner_process()` handles this via lazy detection — the first interceptor call re-probes `/proc/self/exe` for `memfd:` and sets `g_owner_pid` on its own. On aarch64 the lazy path is compiled out; ownership is decided only inside the constructor (matching master's field-tested ARM behavior).
- Child processes inherit `LD_PRELOAD` but the shims detect non-owner processes (by checking `/proc/self/exe` for memfd) and pass through to real libc functions.
- **Owner-side env scrub (aarch64 only)**: on ARM the constructor also strips `/proc/self/fd/*` out of `LD_PRELOAD`, `/tmp/antirev_*` out of `LD_LIBRARY_PATH`, and unsets `ANTIREV_FD_MAP` even inside the owner process. The shims are already mapped, so env entries are only load-bearing for children spawned via `popen`/`system`/`fork+exec`; on ARM the business stack closes random fds and those children fail to start if they inherit `/proc/self/fd/N` preloads. x86_64 deliberately skips this scrub — its test matrix includes a protected parent forking a plain child that dlopens an encrypted lib through the daemon (see `test_fork_same_lib`), which requires the child to inherit `ANTIREV_FD_MAP` + the shim `LD_PRELOAD`.
- The daemon mode splits libs into DT_NEEDED (resolved via symlink dir on `LD_LIBRARY_PATH`) and dlopen'd (lazy, fetched on demand). DT_NEEDED libs are NOT on `LD_PRELOAD` — glibc's normal BFS resolves them through the symlink dir, preserving the original symbol lookup order. `LD_PRELOAD` contains only exe_shim + dlopen_shim.
- `antirev-pack.py` computes per-exe transitive DT_NEEDED using topological sort (Kahn's algorithm) to embed the needed-libs section. The stub uses this to create symlinks for the correct set of libs.
- **DT_NEEDED fd cleanup**: after glibc's dynamic linker has mapped the DT_NEEDED libs, their backing memfds are pure bookkeeping — the mappings keep the memfds alive. The stub passes the fd list via `ANTIREV_CLOSE_FDS=n,m,...` and `exe_shim`'s constructor closes each one, freeing fd-table slots so that later `socket()`/`open()` land at low fd numbers. Matters for any code that still uses `select()` (FD_SETSIZE=1024).
- **Lazy dlopen fetch (Mode C daemon path)**: the stub only eagerly fetches the exe's encrypted DT_NEEDED set (filtered through `all_enc_names` from `OP_LIST`). The Unix socket to the daemon is kept open across `fexecve` and passed to the child via `ANTIREV_LIBD_SOCK=<fd>`. `dlopen_shim` inherits `ANTIREV_ENC_LIBS` (comma-separated) and `ANTIREV_SYMLINK_DIR`; on each `dlopen()` of an encrypted basename it sends `OP_GET_CLOSURE` to fetch the lib plus its transitive encrypted DT_NEEDED closure in one round trip, materializes symlinks in the shared dir, then calls `real_dlopen` (glibc resolves via `LD_LIBRARY_PATH`). Returned fds are cached for the process lifetime to pin `/proc/self/fd/N` paths — closing and reusing them would make glibc collapse different libs into one link-map entry. The daemon parses each lib's `.dynamic`/`DT_NEEDED` at startup via `build_deps_graph()` so `OP_GET_CLOSURE` is a graph lookup. New opcodes: `OP_LIST`/`OP_NAMES`, `OP_GET_CLOSURE` (replies reuse `OP_BATCH`/`OP_END`).
- **Preload-closure-deps on lazy fetch**: after receiving the closure, `dlopen_shim::fetch_closure` iterates it in topological (DFS post-order) order and calls `real_dlopen(symlink_path, RTLD_LAZY | RTLD_GLOBAL)` on every *non-root* entry before the caller's own `real_dlopen` of the root. `RTLD_GLOBAL` is mandatory — generated `.pb.cc` code exports `descriptor_table_<file>_2eproto` with default visibility, and duplicate definitions across plugins (common ODR-ish build pattern for protobuf) dedup via symbol interposition only when both DSOs are in the global scope. The root lib is explicitly skipped so the caller's own dlclose can actually unload it, which matters for plugin systems that cycle plugins carrying overlapping static state (see `test_dlopen_reload`, `test_dlopen_interpose`, `test_python_reload`).

### aarch64_extend_shim (aarch64-only)

Houses two unrelated aarch64-specific interceptors:

- **`ANTI_LoadProcess(struct ANTI_ProcessInfo *)` hijack**: business API that loads a program-binary `.elf` from the path in `info->ltrBin`. aarch64_extend_shim computes `basename(info->ltrBin)`, checks it against the shared `ANTIREV_ENC_LIBS` set (same env var `dlopen_shim` uses — `.elf` and `.so` basenames coexist), and on match fetches the decrypted memfd from the daemon via **`OP_GET_LIB` (reused, no new opcode)**, rewrites `info->ltrBin = "/proc/self/fd/N"`, then calls the real `ANTI_LoadProcess` via `dlsym(RTLD_NEXT, ...)`. The original pointer is restored in the caller's struct after the call returns. `ANTI_UnLoadProcess(pgId)` is **not** intercepted — it keys on a pgId handle, not the path, and the kernel mapping created by the real `ANTI_LoadProcess` pins the memfd regardless of whether our fd cache stays open. The memfd fd is cached per pgName for the process lifetime.
- **`popen` / `pclose`**: moved verbatim from `exe_shim.c`. Rationale unchanged — glibc's vfork'd popen child corrupts the memfd-heavy parent; we override with plain fork+exec and maintain our own FILE*→pid table so `pclose` reaps the right child.

aarch64_extend_shim shares the daemon socket (`ANTIREV_LIBD_SOCK`) with `dlopen_shim`. Both shims have their own mutex, so cross-shim requests hitting the socket concurrently from different threads could interleave responses — not an issue today because `ANTI_LoadProcess` is called at process init (single-threaded) while `dlopen` happens later, but worth noting if that timing ever changes.

Packing:

- **CLI path** (`protect-daemon --libs`): `.elf` files can be passed alongside `.so` files — daemon indexes them by basename, no separate flag.
- **YAML/`antirev-pack.py` path**: `classify_elf` treats any file whose basename ends in `.elf` as `kind='lib'` (regardless of ET_EXEC vs ET_DYN), so `.elf` PG binaries flow through the same encrypt/skip + `encrypt_libs` / `plaintext_libs` filters as `.so` libs. Without this, ET_EXEC `.elf` files would fall into the exe pipeline and get wrapped as standalone `.protected` stubs — wrong semantics for ANTI_LoadProcess targets. `_encrypt_lib_worker` skips the patchelf SONAME-patching step for `.elf` files (ANTI_LoadProcess targets are looked up by basename via `OP_GET_LIB`, never via DT_NEEDED, so no SONAME is needed).
- **Stub side**: `scan_encrypted_libs` in `stub.c` accepts both `.so` and `.elf` extensions as its fast-path filename filter — the authoritative check remains the `ANTREV01` magic header.
- **Unsupported-arch fallback**: when the YAML `stubs:` map omits an arch present in the install tree (e.g. only `aarch64` configured but x86_64 binaries appear), `antirev-pack.py` no longer hard-errors. The unmatched ELFs are copied to `output_dir` as plaintext with a per-arch `[pack] WARNING` summary listing each affected file. This keeps the install tree complete while flagging the omission so a typo in `stubs:` is still visible.

### aarch64_extend_shim env vars (runtime)

- `ANTIREV_AARCH64_EXTEND_LOG=<path>` — line-buffered log of every `ANTI_LoadProcess` call, path-rewrite decision, and daemon fetch outcome. Use this to diagnose "daemon returned no fd" or "basename not in enc list" issues in the field.

### dlopen_shim env vars (runtime)

- `ANTIREV_DLOPEN_LOG=<path>` — when set, `dlopen_shim` writes every `dlopen` decision, closure fetch, preload, and failure to `<path>` with line-buffered IO. Required for diagnosing any closure / preload issue in the field.
- `ANTIREV_NO_PRELOAD=1` — escape hatch that disables the per-dep preload loop entirely. `fetch_closure` still fetches the closure and materializes symlinks, but the caller's `real_dlopen(root)` then triggers glibc's normal recursive DT_NEEDED walk, which maps every dep first and runs all ctors together at the end — matching plaintext semantics exactly. Use this for apps with **implicit inter-lib symbol dependencies**, where one business lib references a symbol provided by a sibling lib without an explicit `DT_NEEDED` edge (e.g. `_ZN3BBBC1EPN6google8protobuf5ArenaE` — `BBB::BBB(google::protobuf::Arena*)` — needed by libccc but provided by libbbb with no edge between them). The per-dep preload loop loads ctors in isolation and can trip lazy-binding failures across the implicit boundary; natural load sidesteps it. Tradeoff: without preload, any lib whose `DT_RPATH` points at the encrypted on-disk dir will have its own DT_NEEDED search hit ciphertext before `LD_LIBRARY_PATH` catches it — so `ANTIREV_NO_PRELOAD` is opt-in per-app, set in the start script, not the default. The correct long-term fix is to add the missing `DT_NEEDED` edge to the business build (`target_link_libraries(CCC PRIVATE BBB)` in libccc's CMakeLists), which makes the dependency explicit and works for every loader.

### Python integration

Python scripts load encrypted libs via `antirev_client.py` — called from within Python (`from antirev_client import activate`). Connects to the daemon, patches `ctypes.CDLL` and `sys.meta_path` to redirect to memfd-backed libs. Loads encrypted libs with `RTLD_GLOBAL` and creates soname symlinks in a temp dir prepended to `LD_LIBRARY_PATH`. Speaks daemon protocol v2 — sends `OP_INIT` on connect and collects `OP_BATCH`/`OP_END` framed replies. Covered by `test_python_client_daemon`.

### Known issues with memfd loading

- Each decrypted lib holds an open memfd, consuming file descriptors. Large deployments (550+ libs) may require raising `ulimit -n`.
- The dynamic linker's path-based deduplication uses `l_name` from the load path. The same library accessed via memfd path (`/proc/self/fd/N`) vs disk path may be treated as different libraries.
- **Duplicate-symbol detection**: `tools/missing_syms.py` runs a per-target duplicate-symbol scan by default. For every project ELF it walks the transitive DT_NEEDED closure (plus the ELF itself) and reports symbols defined by more than one DSO in that load image. STRONG-vs-STRONG duplicates are errors (real interposition / ODR risk); WEAK-vs-WEAK and STRONG-vs-WEAK are warnings (common C++ vague linkage; usually benign but worth surfacing). C++ vague-linkage prefixes (`_ZTV`, `_ZTI`, `_ZTS`, `_ZTC`, `_ZTT`) are filtered by default — pass `--all-cxx` to include them. System-lib-only duplicates (e.g. libc vs ld-linux) are filtered unless `--system-dups` is given. Use `--no-duplicates` to skip this pass.
- Legacy binaries without the needed-section (backward compat) still use LD_PRELOAD for encrypted libs, which changes symbol lookup order. Re-pack with `antirev-pack.py` to get the symlink-dir-only approach.
- **Debug symbol files (.debug) affect runtime behavior**: exe_shim spoofs `readlink("/proc/self/exe")` to point to the encrypted stub on disk. Business software that scans for `.debug` files relative to the exe path (e.g., signal handlers, crash recovery) will find or miss them depending on deployment. Two encrypted processes (Foo, Bar) crash in open62541 `ua_client()` init when `.debug` files are absent, but work fine when present. A standalone demo (tests/opcua_enc/) confirmed encryption itself does NOT cause the crash — the issue is the business software's debug-file-dependent infrastructure. **Workaround**: always deploy `.debug` files alongside encrypted binaries. **Investigation pending**: strace to identify which library reads `.debug` at runtime.
