                                                                                                 
● ╔══════════════════════════════════════════════════════════════╗                                                                  
  ║                    OFFLINE: protect.py                       ║
  ╚══════════════════════════════════════════════════════════════╝                                                                  
                                                                                                                                    
    your_binary + libfoo.so + libbar.so                                                                                             
            │                                               
            ▼
    ┌─────────────────────────────────────────────────────┐
    │ 1. Generate random AES-256 key (32 bytes)           │
    │ 2. For each file:                                   │
    │      encrypt with AES-256-GCM → {iv, tag, ct}      │
    │ 3. Pack bundle:                                     │
    │      [num_files][name+flags+iv+tag+ct_size+ct] ...  │
    │ 4. Append to stub ELF:                              │
    │      stub_elf | bundle | bundle_offset | key | MAGIC│
    └─────────────────────────────────────────────────────┘
            │
            ▼
    protected_binary  (single self-contained file)


  ╔══════════════════════════════════════════════════════════════╗
  ║                 RUNTIME: user runs protected_binary          ║
  ╚══════════════════════════════════════════════════════════════╝

    $ ./protected_binary [args]
            │
            ▼
    kernel loads stub ELF → ld.so → stub main()
            │
            │   /proc/self/exe = protected_binary itself
            ▼
    ┌─────────────────────────────────────────────────────┐
    │ PHASE 1: read trailer (last 48 bytes)               │
    │   [bundle_offset : 8B]                              │
    │   [key           : 32B]  ← embedded at protect time │
    │   [magic         : 8B]   "ANTREV01" sanity check    │
    └─────────────────────────────────────────────────────┘
            │
            ▼
    ┌─────────────────────────────────────────────────────┐
    │ PHASE 2: scan bundle headers (tiny pread calls)     │
    │   read num_files                                    │
    │   for each file:                                    │
    │     read name, flags, iv, tag, ct_size              │
    │     record ct_offset (skip ciphertext bytes)        │
    │   → file_entry_t entries[]  (no ciphertext in RAM)  │
    └─────────────────────────────────────────────────────┘
            │
            ▼
    ┌─────────────────────────────────────────────────────┐
    │ PHASE 3: decrypt each file  (4MB chunk buffer)      │
    │                                                     │
    │   for each file:                                    │
    │     ┌──────────────────────────────────────────┐   │
    │     │ Pass A — GHASH (tag verification)        │   │
    │     │   init AES-GCM ctx                       │   │
    │     │   stream ciphertext in 4MB chunks        │   │
    │     │   accumulate GHASH                       │   │
    │     │   verify tag → abort if mismatch         │   │
    │     └──────────────────────────────────────────┘   │
    │     ┌──────────────────────────────────────────┐   │
    │     │ Pass B — CTR decrypt                     │   │
    │     │   reset ctx (same key+iv)                │   │
    │     │   stream ciphertext in 4MB chunks        │   │
    │     │   decrypt in-place                       │   │
    │     │   write plaintext → memfd  (RAM only)    │   │
    │     └──────────────────────────────────────────┘   │
    │     seek memfd back to 0                            │
    │     if is_main  → main_fd                           │
    │     if is_lib   → lib_fds[i], lib_names[i]         │
    └─────────────────────────────────────────────────────┘
            │
            ▼
    ┌─────────────────────────────────────────────────────┐
    │ PHASE 4: write embedded shims to memfds             │
    │   dlopen_shim_blob → dlopen_shim_fd  (memfd)        │
    │   audit_shim_blob  → audit_shim_fd   (memfd)        │
    │   (blobs baked into stub at compile time)           │
    └─────────────────────────────────────────────────────┘
            │
            ▼
    ┌─────────────────────────────────────────────────────┐
    │ PHASE 5: build envp for child                       │
    │   ANTIREV_FD_MAP=libfoo.so=6,libbar.so=7            │
    │   LD_PRELOAD=/proc/self/fd/<dlopen_shim_fd>         │
    │   LD_AUDIT=/proc/self/fd/<audit_shim_fd>            │
    │   (strip any existing LD_PRELOAD/LD_AUDIT/FD_MAP)   │
    │   wipe key from memory (explicit_bzero)             │
    └─────────────────────────────────────────────────────┘
            │
            ▼
    fexecve(main_fd, argv, new_envp)
    ← replaces stub process image, same PID, no fork


  ╔══════════════════════════════════════════════════════════════╗
  ║              TARGET BINARY STARTS (same PID)                 ║
  ╚══════════════════════════════════════════════════════════════╝

    kernel hands control to ld.so (of target binary)
            │
            ├─── reads LD_AUDIT  → loads audit_shim.so from memfd
            │         │
            │         └─ la_version() handshake
            │
            ├─── reads LD_PRELOAD → loads dlopen_shim.so from memfd
            │
            ├─── processes DT_NEEDED entries:
            │     for each "libfoo.so":
            │       → la_objsearch("libfoo.so", LA_SER_ORIG)
            │           basename match in ANTIREV_FD_MAP?
            │           YES → return "/proc/self/fd/6"
            │           NO  → return name (normal search)
            │       → ld.so opens /proc/self/fd/6 (memfd, RAM)
            │
            └─── target main() runs
                      │
                      └─ dlopen("/abs/path/to/libbar.so")
                            → la_objsearch("/abs/.../libbar.so", LA_SER_ORIG)
                                basename("libbar.so") → fd 7
                                return "/proc/self/fd/7"
                            → ld.so opens memfd (RAM)

  Key properties visible in the flow:
  - No disk writes — all plaintext lives in memfds
  - No fork — fexecve replaces the process image
  - Tag verified before any plaintext released — Pass A before Pass B
  - Peak RAM = ~4MB — one chunk buffer regardless of binary size
  - Key wiped before fexecve — not present in target process memory

