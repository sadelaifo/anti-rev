# Prebuilt stub binaries

Shippable, ready-to-pack stub launchers for targets without a matching
build toolchain. Pack them exactly like a freshly built `stub`:

```bash
python3 shared/protect.py protect-exe \
    --stub daemon-shim/prebuilt/stub-x86_64-static \
    --main ./myapp --key ./cluster.key --output ./myapp.protected
```

## `stub-x86_64-static`

Fully **static** x86-64 stub — **no runtime libc dependency**, no
`ld-linux` interpreter. Runs on any x86-64 Linux regardless of the box's
glibc version (`file` → `statically linked`; `ldd` → `not a dynamic
executable`; no `PT_INTERP`, no `DT_NEEDED`). Minimum kernel 3.2.0.

Build (reproduce with):

```bash
cmake -S daemon-shim -B build/static -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXE_LINKER_FLAGS="-static -no-pie"
cmake --build build/static --target stub -j
```

Notes:
- `-no-pie` keeps it loadable on old targets (SLES 12 / CentOS 7); a
  default static-PIE needs newer-kernel self-relocation support.
- Only the **stub** is static. The `antirev_shim_<arch>.so` it embeds is
  built dynamic as usual — it is `LD_PRELOAD`'d into the business app's
  process and must match that process's (glibc) ABI.
- The exact bytes vary per build: `daemon-shim/CMakeLists.txt` rotates a
  random `/tmp` prefix and the obfstr string layout on every configure,
  so two builds of the same source are equivalent but not identical.
- Built with glibc 2.35 / gcc 11.4 (Ubuntu 22.04).
