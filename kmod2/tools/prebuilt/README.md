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
