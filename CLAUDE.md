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
- The daemon mode splits libs into DT_NEEDED (resolved via symlink dir on `LD_LIBRARY_PATH`) and dlopen'd (on `ANTIREV_FD_MAP`). DT_NEEDED libs are NOT on `LD_PRELOAD` — glibc's normal BFS resolves them through the symlink dir, preserving the original symbol lookup order. `LD_PRELOAD` contains only exe_shim + dlopen_shim.
- `antirev-pack.py` computes per-exe transitive DT_NEEDED using topological sort (Kahn's algorithm) to embed the needed-libs section. The stub uses this to create symlinks for the correct set of libs.
- **DT_NEEDED fd cleanup**: after glibc's dynamic linker has mapped the DT_NEEDED libs, their backing memfds are pure bookkeeping — the mappings keep the memfds alive. The stub passes the fd list via `ANTIREV_CLOSE_FDS=n,m,...` and `exe_shim`'s constructor closes each one, freeing fd-table slots so that later `socket()`/`open()` land at low fd numbers. Matters for any code that still uses `select()` (FD_SETSIZE=1024).

### Python integration

Python scripts load encrypted libs via two mechanisms:
1. **Wrapper mode**: `.antirev-wrap python3 script.py` — the wrapper connects to the daemon, sets up dlopen_shim via LD_PRELOAD, then execs Python. The dlopen_shim intercepts C-level dlopen calls.
2. **antirev_client.py**: called from within Python (`from antirev_client import activate`). Connects to the daemon, patches `ctypes.CDLL` and `sys.meta_path` to redirect to memfd-backed libs. Loads encrypted libs with `RTLD_GLOBAL` and creates soname symlinks in a temp dir prepended to `LD_LIBRARY_PATH`.

### Known issues with memfd loading

- Each decrypted lib holds an open memfd, consuming file descriptors. Large deployments (550+ libs) may require raising `ulimit -n`.
- The dynamic linker's path-based deduplication uses `l_name` from the load path. The same library accessed via memfd path (`/proc/self/fd/N`) vs disk path may be treated as different libraries.
- **Symbol collision detection**: `tools/symbol_collision.py` checks for LD_PRELOAD symbol interposition risks. Run it against plaintext originals before deployment to catch collisions between encrypted and unencrypted libs.
- Legacy binaries without the needed-section (backward compat) still use LD_PRELOAD for encrypted libs, which changes symbol lookup order. Re-pack with `antirev-pack.py` to get the symlink-dir-only approach.
- **Debug symbol files (.debug) affect runtime behavior**: exe_shim spoofs `readlink("/proc/self/exe")` to point to the encrypted stub on disk. Business software that scans for `.debug` files relative to the exe path (e.g., signal handlers, crash recovery) will find or miss them depending on deployment. Two encrypted processes (Foo, Bar) crash in open62541 `ua_client()` init when `.debug` files are absent, but work fine when present. A standalone demo (tests/opcua_enc/) confirmed encryption itself does NOT cause the crash — the issue is the business software's debug-file-dependent infrastructure. **Workaround**: always deploy `.debug` files alongside encrypted binaries. **Investigation pending**: strace to identify which library reads `.debug` at runtime.
