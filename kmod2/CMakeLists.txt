cmake_minimum_required(VERSION 3.13)
# NONE: no compiler probe — the kernel module is built by the kernel's kbuild,
# which is a Makefile CMake cannot replace, so this design wraps `make`.
project(kmod2 NONE)

# Configure-time knobs (pass with -D... to cmake):
#   -DKMOD2_KDIR=/lib/modules/<ver>/build   override the kernel build tree
#   -DKMOD2_CC=gcc-12  (or the strip wrapper) override the module compiler
#   -DKMOD2_DEV=ON     AREV_DEV_MODE=1 dev build (gate toggle + allow-list)
#   -DKMOD2_KEYFILE=/path/key.hex  bake this AES-256 key into the .ko (see below)
set(KMOD2_KDIR    "" CACHE STRING "kernel build tree (default: Makefile's /lib/modules/$(uname -r)/build)")
set(KMOD2_CC      "" CACHE STRING "compiler for the module (e.g. gcc-12 or tools/gcc-strip-unknown-flags.sh)")
set(KMOD2_KEYFILE "" CACHE STRING "hex keyfile whose AES-256 key is baked into the .ko (blank = keep the checked-in placeholder key_blob.c)")
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

# key-in-.ko: with -DKMOD2_KEYFILE set, regenerate module/key_blob.c (the
# obfuscated master key, its own TU) from that keyfile before the kbuild step.
# Only key_blob.o then recompiles + relinks — the rest of the module is cached,
# so swapping keys is a fast rebuild.  Blank keeps the checked-in placeholder
# (module builds but decrypt returns -ENOKEY: fail-safe).
if(KMOD2_KEYFILE)
    add_custom_target(kmod2_key
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/../shared/gen_key_blob.py"
                "${KMOD2_KEYFILE}" "${CMAKE_CURRENT_SOURCE_DIR}/module/key_blob.c"
        COMMENT "Embedding master key from ${KMOD2_KEYFILE} into module/key_blob.c"
        VERBATIM)
    add_dependencies(kmod2_module kmod2_key)
endif()

add_custom_target(kmod2_tools ALL
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}/tools"
    COMMENT "Building kmod2 userspace tools (vcache-mount*)"
    VERBATIM USES_TERMINAL)

add_custom_target(kmod2_clean
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}/module" clean
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}/tools"  clean
    COMMENT "Cleaning kmod2 build outputs"
    VERBATIM)
