# kmod2 build dependencies

Vendored build-time dependencies for compiling `vcachefs.ko` on deployment
targets that cannot reach a package repo (air-gapped appliances).

## kernel-devel-5.10.0-60.18.0.50.oe2203.aarch64.rpm

Kernel build tree (headers + config + Makefiles) for building the module on the
**native ARM64 EulerOS v2 SP11 slave** (kernel `5.10.0-60.18.0.50.h509.eulerosv2r11.aarch64`).

- **Provenance:** openEuler 22.03 LTS, `repo.openeuler.org/openEuler-22.03-LTS/OS/aarch64/Packages/`.
- **SHA-256:** `9c6d6f912f681986b1f675c2a6ca775c368b114c09545680b2757f86fd0aca89`
- **Why openEuler, not EulerOS:** the exact EulerOS SP11 devel RPM
  (`...h509.eulerosv2r11.aarch64`) is only in Huawei's subscription repo / on the
  EulerOS install media — not publicly downloadable. openEuler 22.03 LTS ships the
  **same kernel source base** (`5.10.0-60.18.0.50`); only the distro tag differs
  (`oe2203` vs `h509.eulerosv2r11`). Prefer the real EulerOS RPM if you can get it.

### vermagic caveat — a plain `insmod` will be REFUSED without this

A module built against this tree defaults to vermagic `...50.oe2203.aarch64`; the
running EulerOS kernel expects `...50.h509.eulerosv2r11.aarch64`. Build procedure:

```bash
mkdir -p ~/kdevel && cd ~/kdevel
rpm2cpio /path/to/kernel-devel-5.10.0-60.18.0.50.oe2203.aarch64.rpm | cpio -idmv
KT=$PWD/usr/src/kernels/5.10.0-60.18.0.50.oe2203.aarch64

# use the RUNNING kernel's real config to remove config drift (if available)
zcat /proc/config.gz > "$KT/.config" 2>/dev/null || cp /boot/config-$(uname -r) "$KT/.config"
make -C "$KT" ARCH=arm64 modules_prepare

# force vermagic to match the EulerOS kernel (AFTER modules_prepare)
echo '#define UTS_RELEASE "5.10.0-60.18.0.50.h509.eulerosv2r11.aarch64"' > "$KT/include/generated/utsrelease.h"
echo '5.10.0-60.18.0.50.h509.eulerosv2r11.aarch64' > "$KT/include/config/kernel.release"

# build the module against this tree
cd <repo>/kmod2/module
make clean && make KDIR="$KT" AREV_DEV_MODE=1 CC=gcc
modinfo vcachefs.ko | grep vermagic   # must read ...h509.eulerosv2r11.aarch64
sudo insmod vcachefs.ko
```

**Residual risk:** the config-swap above removes config drift, but if EulerOS
carried out-of-tree *source* patches that changed the layout of structs the module
touches (`inode`, `super_block`, `file`, crypto/AEAD, `mm->exe_file`), a
forced-vermagic load could misbehave. Those structures are very stable, so the risk
for this VFS/crypto module is low — but it is why the real EulerOS devel RPM is
preferred.
