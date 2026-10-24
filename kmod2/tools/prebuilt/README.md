# prebuilt vcache-mount (static, x86-64)

Statically-linked build of `../vcache-mount.c` — the shippable mount helper that
replaces the readable `vcache-mount-{ro,rw}` shell scripts on client media. A
`cat` of a shell script hands a rookie the whole architecture; this binary carries
no commentary, and `-static` makes it run on any x86-64 box (SLES 12 SP5, Docker,
…) regardless of the host glibc version. Stripped of its symbol table.

Verify:
    file vcache-mount-x86_64        # ELF x86-64, statically linked, stripped
    ldd  vcache-mount-x86_64        # "not a dynamic executable"
    sha256sum vcache-mount-x86_64   # 78eb6ed84d5d96d4356316a6103a051515018c8c670600feebaa69d0e4be99fd

Usage (run as root — it calls mount(2) directly, no /bin/mount, no shell):
    vcache-mount-x86_64 up [--ro|--rw] [--passdata] [--passthrough <exts>] \
                        [--state <dir>] [--insmod <module.ko>] <encdir> <mountpoint>
    vcache-mount-x86_64 down [--state <dir>] <mountpoint>

  up --rw (default)  vcachefs(ro[,passdata]) lower under <state>/dec  +  overlayfs(rw)
                     upper on <mountpoint>; app runtime writes land in <state>/upper,
                     never the ciphertext tree (state = <dir mp>/.vcache-rw/<base mp>).
  up --ro            single vcachefs mount directly on <mountpoint>.
  down               umount overlay then the vcachefs lower.
  --insmod <ko>      load the module first (finit_module) with the production
                     parameter gate_passthrough_cipher=1.

Rebuild:  make -C ..            # or: gcc -O2 -static -o vcache-mount ../vcache-mount.c
Rebuild + re-commit this artifact whenever ../vcache-mount.c changes.

---

# prebuilt vdb (static, multiarch, x86-64 host)

Fully-static, multiarch (`--enable-targets=all`) gdb 14.2 built by
`../build-gdb-static.sh` — the company-only "vdb" a technician brings to a
client box to debug coredumps of protected (encrypted-binary) processes. The OS
core is plaintext, but the ENCRYPTED binaries/.debug gdb must symbolize are gated
by the vcachefs `.ko`; this `vdb-x86_64` build is authorized by the gate's
**name + SHA-256 pin** (`module/gate_trusted_hashes.h`), while a client's stock
gdb is denied. Reads BOTH x86_64 and aarch64 cores/binaries. `-all-static`
(libtool's fully-static flag — plain `-static` is swallowed by libtool) +
`-no-pie` make it run on any x86-64 box regardless of host glibc. NOT shipped to
the client. Stripped.

A random 128-bit marker is baked into the version string via `--with-pkgversion`,
so this binary's SHA-256 cannot match any public gdb and `gdb --version`
identifies it — and that unique SHA-256 is exactly what the gate pins.

Verify:
    file vdb-x86_64        # ELF x86-64, statically linked, stripped
    ldd  vdb-x86_64        # "not a dynamic executable"
    ./vdb-x86_64 --version # GNU gdb (vcachefs-coredbg 2ac81e6b014e8e3e55d2c74d0051a2a2) 14.2
    sha256sum vdb-x86_64   # e94429f48a5e2a8626e1bc491c9cb9780c3686ff79eef2160e6a1eefd080bcce

AUTHORIZED BY HASH PIN (already embedded): `module/gate_trusted_hashes.h` pins
`{ "vdb-x86_64", <the SHA-256 above> }`. Rebuild the `.ko` after any change to
that header, and run the binary under the basename `vdb-x86_64` so the gate's
basename pre-filter matches. To re-pin after rebuilding the binary:
    ../authz-embed-qemu-hash.sh vdb-x86_64 vdb-x86_64 ../../module/gate_trusted_hashes.h

Do NOT also vendor-sign it: `sign-exe.sh` appends a footer that changes the file
bytes and would break the hash pin. Signing is the mutually-exclusive alternative
(it would need the cert in `gate_authz_pubkey.h` instead of the hash pin).
