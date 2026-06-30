cmake_minimum_required(VERSION 3.16)
project(antirev C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Emit compile_commands.json so CLion (and other clangd-based IDEs) can
# index every translation unit with the real compile flags + include
# paths.  Previously stub.c / exe_shim.c / dlopen_shim.c / crypto.c were
# compiled through add_custom_command, which is opaque to CLion — code
# inspection, goto-definition, and completion didn't work on them.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Native-only build ────────────────────────────────────────────────
# Build only for the host architecture: aarch64 host → aarch64, x86_64
# host → x86_64.  Cross-compilation is not supported.
if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(TARGET_ARCH   "aarch64")
    set(ARCH_SUFFIX   "_aarch64")
    set(STUB_NAME     "stub_aarch64")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(TARGET_ARCH   "x86_64")
    set(ARCH_SUFFIX   "_x86_64")
    set(STUB_NAME     "stub")
else()
    message(FATAL_ERROR
        "Unsupported host arch: ${CMAKE_HOST_SYSTEM_PROCESSOR}. "
        "Supported: x86_64, aarch64.")
endif()
message(STATUS "${TARGET_ARCH} host: native build with ${CMAKE_C_COMPILER}")

# Convenience flag aliases so the test blocks below (gated on
# X86_GCC / AARCH64_GCC) keep their existing shape without duplication.
set(X86_GCC     "")
set(AARCH64_GCC "")
if(TARGET_ARCH STREQUAL "x86_64")
    set(X86_GCC "${CMAKE_C_COMPILER}")
else()
    set(AARCH64_GCC "${CMAKE_C_COMPILER}")
endif()

# ── Helper: generate C blob header from a binary file ─────────────────
# One legitimate add_custom_command — turning a built .so into a C
# header is a file-gen step, not a translation unit.  Used by each
# shim target below.
function(make_blob_header OUTPUT INPUT VARNAME DEP)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/cmake/bin2h.py"
                        "${INPUT}" "${OUTPUT}" "${VARNAME}"
        DEPENDS "${DEP}"
        COMMENT "Generating blob header: ${OUTPUT}"
    )
endfunction()

# ── Helper: route a list of stub/* sources through tools/obfstr_gen.py ─
# Compile-time string-literal obfuscation pass: takes paths relative to
# the source tree (e.g. "stub/stub.c"), writes the rewritten copies to
# ${BUILD}/obf/<basename>, and yields the rewritten paths into OUT_VAR.
# The caller passes OUT to add_executable / add_library so the actual
# compile happens against the obfuscated source — every fprintf /
# snprintf / dlsym / getenv / strncmp literal in the original ends up as
# encrypted bytes in the binary's .rodata.
#
# Codegen for each unique basename is declared exactly once (guarded via
# a global property) so multiple targets can share the same source file
# without CMake complaining about duplicate add_custom_command outputs.
function(obfstr_codegen_sources OUT_VAR)
    set(_obfd "")
    foreach(_src ${ARGN})
        # Source paths can be either source-tree-relative (e.g.
        # "stub/stub.c") or absolute (e.g. ${CMAKE_CURRENT_BINARY_DIR}/runtime_paths.c
        # for configure-generated files).  Normalise to a full path.
        if(IS_ABSOLUTE "${_src}")
            set(_full "${_src}")
        else()
            set(_full "${CMAKE_CURRENT_SOURCE_DIR}/${_src}")
        endif()
        get_filename_component(_name "${_full}" NAME)
        set(_out "${CMAKE_CURRENT_BINARY_DIR}/obf/${_name}")
        get_property(_already GLOBAL PROPERTY _OBFSTR_DONE_${_name})
        if(NOT _already)
            add_custom_command(
                OUTPUT  "${_out}"
                COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/obf"
                COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tools/obfstr_gen.py"
                        --out-dir "${CMAKE_CURRENT_BINARY_DIR}/obf"
                        "${_full}"
                DEPENDS "${_full}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tools/obfstr_gen.py"
                        "${CMAKE_CURRENT_SOURCE_DIR}/stub/obfstr.h"
                COMMENT "obfstr-codegen ${_name}"
            )
            set_property(GLOBAL PROPERTY _OBFSTR_DONE_${_name} TRUE)
        endif()
        list(APPEND _obfd "${_out}")
    endforeach()
    set(${OUT_VAR} "${_obfd}" PARENT_SCOPE)
endfunction()

# ── Per-build random /tmp prefix ──────────────────────────────────────
# Replaces the old hard-coded "antirev_" prefix that was trivially
# fingerprintable from `ls /tmp/`.  Every fresh `cmake ..` rotates the
# value, so a dump of one build's runtime fingerprint doesn't carry
# over to the next release.  Set ANTIREV_TMP_PREFIX externally for a
# repeatable build (e.g. -DANTIREV_TMP_PREFIX=.foo_).
if(NOT DEFINED ANTIREV_TMP_PREFIX OR ANTIREV_TMP_PREFIX STREQUAL "")
    string(RANDOM LENGTH 8 ALPHABET "0123456789abcdef" _antirev_rand_hex)
    set(ANTIREV_TMP_PREFIX ".${_antirev_rand_hex}_" CACHE STRING
        "Per-build random prefix for /tmp dirs antirev creates at runtime"
        FORCE)
endif()
message(STATUS "antirev runtime tmp prefix: ${ANTIREV_TMP_PREFIX}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/runtime_paths.c.in"
    "${CMAKE_CURRENT_BINARY_DIR}/runtime_paths.c"
    @ONLY
)

# ═══════════════════════════════════════════════════════════════════════
#  antirev_shim.so — single shipping shim DSO
# ═══════════════════════════════════════════════════════════════════════
# All LD_PRELOAD-able interceptors live in one DSO:
#
#   exe_shim.c             — readlink / realpath / getauxval identity hide
#   dlopen_shim.c          — dlopen redirect to /proc/self/fd/N
#   patch_fetch.c          — shared .pat suffix + OP_GET_PATCH fetch
#   patch_redirect.c       — fopen/fopen64 .pat redirect (all arches) +
#                             open/openat .pat redirect (x86 only, via
#                             #ifndef __aarch64__)
#   aarch64_extend_shim.c  — ANTI_LoadProcess hijack + popen/pclose +
#                             open/openat .pat redirect (aarch64 only —
#                             empty TU on x86)
#   daemon_client.c        — shared daemon-protocol client (socket fd,
#                             __r_FM / __r_EL state,
#                             send/recv helpers used by both shims)
#
# One .so = one memfd, one LD_PRELOAD entry, regardless of arch.  Hot
# patches go through antirev_shim itself (reusing the daemon connection) —
# no separate lrxd.so.  The business opens .pat via BOTH fopen64 (ifstream)
# and open(), so both are hooked: fopen* on all arches (patch_redirect),
# open/openat on x86 (patch_redirect) and aarch64 (aarch64_extend_shim).
set(ANTIREV_SHIM_SOURCES
    stub/exe_shim.c
    stub/dlopen_shim.c
    stub/daemon_client.c
    stub/patch_fetch.c
    stub/patch_redirect.c
)
if(TARGET_ARCH STREQUAL "aarch64")
    list(APPEND ANTIREV_SHIM_SOURCES stub/aarch64_extend_shim.c)
endif()
# Configure-generated runtime_paths.c lives in BUILD dir; pass an
# absolute path so obfstr_codegen_sources's source-tree-relative
# fallback isn't tried.
list(APPEND ANTIREV_SHIM_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/runtime_paths.c")
obfstr_codegen_sources(ANTIREV_SHIM_SOURCES_OBF ${ANTIREV_SHIM_SOURCES})
add_library(antirev_shim SHARED ${ANTIREV_SHIM_SOURCES_OBF})
set_target_properties(antirev_shim PROPERTIES
    OUTPUT_NAME "antirev_shim${ARCH_SUFFIX}"
    PREFIX ""                             # no "lib" prefix
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
    # Suppress DT_SONAME — the shim is embedded into stub.c as a byte
    # blob and loaded via fexecve-inherited memfd, never resolved
    # through the dynamic linker's SONAME machinery.  Letting the
    # linker write `antirev_shim_<arch>.so` as DT_SONAME means
    # `strings stub` finds the literal string in the embedded blob,
    # leaking the LD_PRELOAD shim's name.  NO_SONAME=TRUE drops the
    # DT_SONAME entry entirely.
    NO_SONAME TRUE
)
target_compile_options(antirev_shim PRIVATE -O2)
target_include_directories(antirev_shim PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/stub")
if(TARGET_ARCH STREQUAL "aarch64")
    target_compile_options(antirev_shim PRIVATE -march=armv8-a+crypto)
endif()
target_link_libraries(antirev_shim PRIVATE dl pthread)

# stub.c #includes this file — aarch64 looks for the suffixed name,
# x86 looks for the plain one.  Keep both conventions.
if(TARGET_ARCH STREQUAL "aarch64")
    set(ANTIREV_SHIM_BLOB_H "${CMAKE_CURRENT_BINARY_DIR}/antirev_shim_blob_aarch64.h")
else()
    set(ANTIREV_SHIM_BLOB_H "${CMAKE_CURRENT_BINARY_DIR}/antirev_shim_blob.h")
endif()
make_blob_header("${ANTIREV_SHIM_BLOB_H}" "$<TARGET_FILE:antirev_shim>"
                 "antirev_shim_blob" antirev_shim)
add_custom_target(antirev_shim_blob_h DEPENDS "${ANTIREV_SHIM_BLOB_H}")

# ═══════════════════════════════════════════════════════════════════════
#  stub executable
# ═══════════════════════════════════════════════════════════════════════
obfstr_codegen_sources(STUB_SOURCES_OBF
    stub/stub.c
    stub/crypto.c
    "${CMAKE_CURRENT_BINARY_DIR}/runtime_paths.c"   # configure-generated
)
add_executable(${STUB_NAME} ${STUB_SOURCES_OBF})
target_include_directories(${STUB_NAME} PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"        # generated blob headers
    "${CMAKE_CURRENT_SOURCE_DIR}/stub"   # crypto.h, obfstr.h
)
target_compile_options(${STUB_NAME} PRIVATE -O2 -Wall -Wextra)
target_link_libraries(${STUB_NAME} PRIVATE pthread)

if(TARGET_ARCH STREQUAL "aarch64")
    # aarch64: enable ARM Crypto Extensions for AES hardware accel.
    target_compile_options(${STUB_NAME} PRIVATE -march=armv8-a+crypto)
    # openEuler / CentOS / SUSE / 麒麟 aarch64 only ship
    # /lib64/ld-linux-aarch64.so.1 (Debian defaults to /lib/...).
    # Force INTERP so the stub launches on either rootfs layout.
    target_link_options(${STUB_NAME} PRIVATE
        "-Wl,--dynamic-linker=/lib64/ld-linux-aarch64.so.1")
endif()

# stub.c #includes the generated blob headers — the object file can't
# compile until they exist.  Declare both as OBJECT_DEPENDS and wire a
# phony target dependency so parallel builds stay correct.  After the
# obfstr codegen pass, the actual file fed to gcc is the rewritten copy
# under ${BUILD}/obf/, so the property has to attach there.
set(STUB_BLOB_HEADERS "${ANTIREV_SHIM_BLOB_H}")
add_custom_target(stub_blob_headers DEPENDS ${STUB_BLOB_HEADERS})
add_dependencies(${STUB_NAME} stub_blob_headers)
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/obf/stub.c" PROPERTIES
    OBJECT_DEPENDS "${STUB_BLOB_HEADERS}"
)

# Match the old pipeline's artefact size — strip after link.
add_custom_command(TARGET ${STUB_NAME} POST_BUILD
    COMMAND ${CMAKE_STRIP} -s $<TARGET_FILE:${STUB_NAME}>
    COMMENT "Stripping $<TARGET_FILE_NAME:${STUB_NAME}>"
)

# ═══════════════════════════════════════════════════════════════════════
#  Tests
# ═══════════════════════════════════════════════════════════════════════
# All test binaries, helper functions, and end-to-end test targets live
# in cmake/tests.cmake — included here so the top-level file stays focused
# on the shipping artifacts (antirev_shim + stub).  include() (not
# add_subdirectory) keeps the same directory scope, so CMAKE_CURRENT_*,
# X86_GCC/AARCH64_GCC, and the obfstr/blob helpers remain in scope.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/tests.cmake")
