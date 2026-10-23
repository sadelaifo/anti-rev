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

# prebuilt vcache-coredbg (static, multiarch, x86-64 host)

Fully-static, multiarch (`--enable-targets=all`) gdb 14.2 built by
`../build-gdb-static.sh` — the company-only "vcache-coredbg" a technician brings to a
client box to debug coredumps of protected (encrypted-binary) processes. The OS
core is plaintext, but the ENCRYPTED binaries/.debug gdb must symbolize are gated
by the vcachefs `.ko`; a VENDOR-SIGNED vcache-coredbg is authorized by the gate's per-exe
signature path, a client's stock gdb is denied. Reads BOTH x86_64 and aarch64
cores/binaries. `-all-static` (libtool's fully-static flag — plain `-static` is
swallowed by libtool) + `-no-pie` make it run on any x86-64 box regardless of
host glibc. NOT shipped to the client. Stripped.

A random 128-bit marker is baked into the version string via `--with-pkgversion`,
so this binary's SHA-256 cannot match any public gdb and `gdb --version`
identifies it — the clean alternative to trailing garbage (which would collide
with the signature footer the gate reads from the file's end).

Verify:
    file vcache-coredbg-x86_64        # ELF x86-64, statically linked, stripped
    ldd  vcache-coredbg-x86_64        # "not a dynamic executable"
    ./vcache-coredbg-x86_64 --version # GNU gdb (vcachefs-coredbg 2ac81e6b014e8e3e55d2c74d0051a2a2) 14.2
    sha256sum vcache-coredbg-x86_64   # e94429f48a5e2a8626e1bc491c9cb9780c3686ff79eef2160e6a1eefd080bcce

NOT YET SIGNED. Before use, vendor-sign it so the gate trusts it (the matching
vendor cert must be embedded in gate_authz_pubkey.h and the .ko rebuilt):
    ../sign-exe.sh <vendor.key> <vendor.crt> vcache-coredbg-x86_64
