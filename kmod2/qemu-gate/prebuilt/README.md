# prebuilt qemu-aarch64-static (gate-enabled)

Static `qemu-aarch64` **11.0.0** for x86-64 hosts, with the vcachefs decrypt gate
compiled in. Built on WSL Ubuntu 22.04 (static-pie: glibc + glib linked
statically → no runtime deps; runs on SLES 12 SP5 and inside Docker).

Verify:
    file qemu-aarch64-static      # ELF x86-64, static-pie linked
    ./qemu-aarch64-static --version   # qemu-aarch64 version 11.0.0
    strings qemu-aarch64-static | grep -i 'AREV_PROTECT_ROOTS|/dev/vcachefs'

Deploy as the binfmt interpreter (keep the basename the gate whitelists). Use the
helper so transparent aarch64 execution goes through THIS qemu — it installs the
binary and registers binfmt escape-safe with the F (fix-binary) flag so it works
inside containers:
    sudo kmod2/qemu-gate/register-binfmt.sh register    # install + register on the HOST
    sudo kmod2/qemu-gate/register-binfmt.sh status       # verify (enabled, interpreter, magic)
    sudo kmod2/qemu-gate/register-binfmt.sh unregister   # revert
    # then at qemu launch:  export AREV_PROTECT_ROOTS=/root/SW
Do NOT register with a bare `echo` — sh/dash mangles the \x.. magic and the
trailing newline, giving "Exec format error". The script uses printf '%s'.

Rebuild from source: kmod2/qemu-gate/apply-gate.py + a static glib (see the
qemu-gate README). Source of the gate: kmod2/qemu-gate/arev_gate.{c,h}, arev_uapi.h.
