# antirev

Binary protection system that encrypts executables and shared libraries, then runs them from memory (memfd) to prevent reverse engineering. Key components:

- **stub**: C launcher that decrypts bundled binaries into memfds and executes via `fexecve`
- **exe_shim**: LD_PRELOAD shim that intercepts `readlink`, `realpath`, `getauxval` to hide memfd paths from the protected process
- **dlopen_shim**: LD_PRELOAD shim that redirects `dlopen()` calls to decrypted memfd-backed libraries via `ANTIREV_FD_MAP`
- **encryptor** (`protect.py`, `antirev-pack.py`): Python tools that encrypt and bundle binaries with AES-256-GCM
- **daemon mode** (`.antirev-libd`): a lib-server process decrypts shared libraries once and serves them to client processes via SCM_RIGHTS
- **wrapper mode** (`.antirev-wrap`): connects to daemon, receives lib fds, sets up `LD_PRELOAD` with dlopen_shim + `ANTIREV_FD_MAP`, then execs an arbitrary command (e.g. `python3`). Used for non-encrypted binaries that need to dlopen encrypted libs.
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
- The exe_shim constructor may run after C++ global static initializers in DT_NEEDED libraries. The `is_owner_process()` function handles this via lazy detection.
- Child processes inherit `LD_PRELOAD` but the shims detect non-owner processes (by checking `/proc/self/exe` for memfd) and pass through to real libc functions.
- The daemon mode splits libs into DT_NEEDED (resolved via symlink dir on `LD_LIBRARY_PATH`) and dlopen'd (lazy, fetched on demand). DT_NEEDED libs are NOT on `LD_PRELOAD` — glibc's normal BFS resolves them through the symlink dir, preserving the original symbol lookup order. `LD_PRELOAD` contains only exe_shim + dlopen_shim.
- `antirev-pack.py` computes per-exe transitive DT_NEEDED using topological sort (Kahn's algorithm) to embed the needed-libs section. The stub uses this to create symlinks for the correct set of libs.
- **DT_NEEDED fd cleanup**: after glibc's dynamic linker has mapped the DT_NEEDED libs, their backing memfds are pure bookkeeping — the mappings keep the memfds alive. The stub passes the fd list via `ANTIREV_CLOSE_FDS=n,m,...` and `exe_shim`'s constructor closes each one, freeing fd-table slots so that later `socket()`/`open()` land at low fd numbers. Matters for any code that still uses `select()` (FD_SETSIZE=1024).
- **Lazy dlopen fetch (Mode C daemon path)**: the stub only eagerly fetches the exe's encrypted DT_NEEDED set (filtered through `all_enc_names` from `OP_LIST`). The Unix socket to the daemon is kept open across `fexecve` and passed to the child via `ANTIREV_LIBD_SOCK=<fd>`. `dlopen_shim` inherits `ANTIREV_ENC_LIBS` (comma-separated) and `ANTIREV_SYMLINK_DIR`; on each `dlopen()` of an encrypted basename it sends `OP_GET_CLOSURE` to fetch the lib plus its transitive encrypted DT_NEEDED closure in one round trip, materializes symlinks in the shared dir, then calls `real_dlopen` (glibc resolves via `LD_LIBRARY_PATH`). Returned fds are cached for the process lifetime to pin `/proc/self/fd/N` paths — closing and reusing them would make glibc collapse different libs into one link-map entry. The daemon parses each lib's `.dynamic`/`DT_NEEDED` at startup via `build_deps_graph()` so `OP_GET_CLOSURE` is a graph lookup. New opcodes: `OP_LIST`/`OP_NAMES`, `OP_GET_CLOSURE` (replies reuse `OP_BATCH`/`OP_END`).
- **Preload-closure-deps on lazy fetch**: after receiving the closure, `dlopen_shim::fetch_closure` iterates it in topological (DFS post-order) order and calls `real_dlopen(symlink_path, RTLD_LAZY | RTLD_GLOBAL)` on every *non-root* entry before the caller's own `real_dlopen` of the root. `RTLD_GLOBAL` is mandatory — generated `.pb.cc` code exports `descriptor_table_<file>_2eproto` with default visibility, and duplicate definitions across plugins (common ODR-ish build pattern for protobuf) dedup via symbol interposition only when both DSOs are in the global scope. The root lib is explicitly skipped so the caller's own dlclose can actually unload it, which matters for plugin systems that cycle plugins carrying overlapping static state (see `test_dlopen_reload`, `test_dlopen_interpose`, `test_python_reload`).

### dlopen_shim env vars (runtime)

- `ANTIREV_DLOPEN_LOG=<path>` — when set, `dlopen_shim` writes every `dlopen` decision, closure fetch, preload, and failure to `<path>` with line-buffered IO. Required for diagnosing any closure / preload issue in the field.
- `ANTIREV_NO_PRELOAD=1` — escape hatch that disables the per-dep preload loop entirely. `fetch_closure` still fetches the closure and materializes symlinks, but the caller's `real_dlopen(root)` then triggers glibc's normal recursive DT_NEEDED walk, which maps every dep first and runs all ctors together at the end — matching plaintext semantics exactly. Use this for apps with **implicit inter-lib symbol dependencies**, where one business lib references a symbol provided by a sibling lib without an explicit `DT_NEEDED` edge (e.g. `_ZN3BBBC1EPN6google8protobuf5ArenaE` — `BBB::BBB(google::protobuf::Arena*)` — needed by libccc but provided by libbbb with no edge between them). The per-dep preload loop loads ctors in isolation and can trip lazy-binding failures across the implicit boundary; natural load sidesteps it. Tradeoff: without preload, any lib whose `DT_RPATH` points at the encrypted on-disk dir will have its own DT_NEEDED search hit ciphertext before `LD_LIBRARY_PATH` catches it — so `ANTIREV_NO_PRELOAD` is opt-in per-app, set in the start script, not the default. The correct long-term fix is to add the missing `DT_NEEDED` edge to the business build (`target_link_libraries(CCC PRIVATE BBB)` in libccc's CMakeLists), which makes the dependency explicit and works for every loader.

### Python integration

Python scripts load encrypted libs via two mechanisms:
1. **Wrapper mode**: `.antirev-wrap python3 script.py` — the wrapper connects to the daemon, sets up dlopen_shim via LD_PRELOAD, then execs Python. The dlopen_shim intercepts C-level dlopen calls.
2. **antirev_client.py**: called from within Python (`from antirev_client import activate`). Connects to the daemon, patches `ctypes.CDLL` and `sys.meta_path` to redirect to memfd-backed libs. Loads encrypted libs with `RTLD_GLOBAL` and creates soname symlinks in a temp dir prepended to `LD_LIBRARY_PATH`. Speaks daemon protocol v2 — sends `OP_INIT` on connect and collects `OP_BATCH`/`OP_END` framed replies. Covered by `test_python_client_daemon`.

### Known issues with memfd loading

- Each decrypted lib holds an open memfd, consuming file descriptors. Large deployments (550+ libs) may require raising `ulimit -n`.
- The dynamic linker's path-based deduplication uses `l_name` from the load path. The same library accessed via memfd path (`/proc/self/fd/N`) vs disk path may be treated as different libraries.
- **Duplicate-symbol detection**: `tools/missing_syms.py` runs a per-target duplicate-symbol scan by default. For every project ELF it walks the transitive DT_NEEDED closure (plus the ELF itself) and reports symbols defined by more than one DSO in that load image. STRONG-vs-STRONG duplicates are errors (real interposition / ODR risk); WEAK-vs-WEAK and STRONG-vs-WEAK are warnings (common C++ vague linkage; usually benign but worth surfacing). C++ vague-linkage prefixes (`_ZTV`, `_ZTI`, `_ZTS`, `_ZTC`, `_ZTT`) are filtered by default — pass `--all-cxx` to include them. System-lib-only duplicates (e.g. libc vs ld-linux) are filtered unless `--system-dups` is given. Use `--no-duplicates` to skip this pass.
- Legacy binaries without the needed-section (backward compat) still use LD_PRELOAD for encrypted libs, which changes symbol lookup order. Re-pack with `antirev-pack.py` to get the symlink-dir-only approach.
- **Debug symbol files (.debug) affect runtime behavior**: exe_shim spoofs `readlink("/proc/self/exe")` to point to the encrypted stub on disk. Business software that scans for `.debug` files relative to the exe path (e.g., signal handlers, crash recovery) will find or miss them depending on deployment. Two encrypted processes (Foo, Bar) crash in open62541 `ua_client()` init when `.debug` files are absent, but work fine when present. A standalone demo (tests/opcua_enc/) confirmed encryption itself does NOT cause the crash — the issue is the business software's debug-file-dependent infrastructure. **Workaround**: always deploy `.debug` files alongside encrypted binaries. **Investigation pending**: strace to identify which library reads `.debug` at runtime.
