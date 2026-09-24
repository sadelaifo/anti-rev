cmake_minimum_required(VERSION 3.13)
# NONE: no compiler probe — the kernel module is built by the kernel's kbuild,
# which is a Makefile CMake cannot replace, so this design wraps `make`.
project(kmod2 NONE)

# Configure-time knobs (pass with -D... to cmake):
#   -DKMOD2_KDIR=/lib/modules/<ver>/build   override the kernel build tree
#   -DKMOD2_CC=gcc-12  (or the strip wrapper) override the module compiler
#   -DKMOD2_DEV=ON     AREV_DEV_MODE=1 dev build (gate toggle + allow-list)
set(KMOD2_KDIR "" CACHE STRING "kernel build tree (default: Makefile's /lib/modules/$(uname -r)/build)")
set(KMOD2_CC   "" CACHE STRING "compiler for the module (e.g. gcc-12 or tools/gcc-strip-unknown-flags.sh)")
option(KMOD2_DEV "AREV_DEV_MODE=1 dev build" OFF)

set(_margs "")
if(KMOD2_KDIR)
    list(APPEND _margs "KDIR=${KMOD2_KDIR}")
endif()
if(KMOD2_CC)
    list(APPEND _margs "CC=${KMOD2_CC}")
endif()
if(KMOD2_DEV)
    list(APPEND _margs "AREV_DEV_MODE=1")
endif()

add_custom_target(kmod2_module ALL
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}/module" ${_margs}
    COMMENT "Building vcachefs.ko via kbuild"
    VERBATIM USES_TERMINAL)

add_custom_target(kmod2_tools ALL
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}/tools"
    COMMENT "Building kmod2 userspace tools (vcache-mount*)"
    VERBATIM USES_TERMINAL)

add_custom_target(kmod2_clean
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}/module" clean
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}/tools"  clean
    COMMENT "Cleaning kmod2 build outputs"
    VERBATIM)
