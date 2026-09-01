# prebuilt qemu-aarch64-static (gate-enabled)

Static `qemu-aarch64` **11.0.0** for x86-64 hosts, with the vcachefs decrypt gate
compiled in. Built on WSL Ubuntu 22.04 (static-pie: glibc + glib linked
statically → no runtime deps; runs on SLES 12 SP5 and inside Docker).

Verify:
    file qemu-aarch64-static      # ELF x86-64, static-pie linked
    ./qemu-aarch64-static --version   # qemu-aarch64 version 11.0.0
    strings qemu-aarch64-static | grep -i 'AREV_PROTECT_ROOTS|/dev/vcachefs'

Deploy as the binfmt interpreter (keep the basename the gate whitelists):
    cp qemu-aarch64-static  <container-rootfs>/usr/bin/qemu-aarch64-static
    # at qemu launch:  export AREV_PROTECT_ROOTS=/root/SW

Rebuild from source: kmod2/qemu-gate/apply-gate.py + a static glib (see the
qemu-gate README). Source of the gate: kmod2/qemu-gate/arev_gate.{c,h}, arev_uapi.h.
