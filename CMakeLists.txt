cmake_minimum_required(VERSION 3.16)
project(antirev C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Cross-compiler detection ──────────────────────────────────────────
find_program(AARCH64_GCC aarch64-linux-gnu-gcc)
if(AARCH64_GCC)
    message(STATUS "aarch64 cross-compiler: ${AARCH64_GCC}")
else()
    message(STATUS "aarch64-linux-gnu-gcc not found — skipping ARM64 targets")
endif()

# ── Helper: compile a shared library with a given compiler ────────────
# Usage: compile_shim(<output.so> <compiler> <source.c>)
function(compile_shim OUTPUT COMPILER SOURCE)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2 -fvisibility=hidden
                -o "${OUTPUT}" "${SOURCE}" -ldl
        DEPENDS "${SOURCE}"
        COMMENT "Building dlopen shim: ${OUTPUT}"
    )
endfunction()

# ── Helper: generate C blob header from a binary file ─────────────────
# Usage: make_blob_header(<output.h> <input.so> <varname> <dep_target>)
function(make_blob_header OUTPUT INPUT VARNAME DEP)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND python3 "${CMAKE_SOURCE_DIR}/cmake/bin2h.py"
                        "${INPUT}" "${OUTPUT}" "${VARNAME}"
        DEPENDS "${DEP}"
        COMMENT "Generating blob header: ${OUTPUT}"
    )
endfunction()

# ── Helper: build a stub binary with a given compiler ─────────────────
# Usage: build_stub(<output> <compiler> <blob_header_dep>)
function(build_stub OUTPUT COMPILER STRIPPER BLOB_DEP)
    # Extra flags: pass -static for cross-compiled (non-native) stubs so they run
    # on QEMU user-mode (no ARM64 dynamic linker on the host) and on embedded targets.
    # Native x86-64 stub stays dynamically linked (faster startup, smaller binary).
    if("${COMPILER}" STREQUAL "gcc")
        set(EXTRA_FLAGS "")
    else()
        set(EXTRA_FLAGS "-static")
    endif()
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -O2 -Wall -Wextra ${EXTRA_FLAGS}
                -I "${CMAKE_BINARY_DIR}"
                -I "${CMAKE_SOURCE_DIR}/stub"
                -o "${OUTPUT}"
                "${CMAKE_SOURCE_DIR}/stub/stub.c"
                "${CMAKE_SOURCE_DIR}/stub/crypto.c"
        COMMAND "${STRIPPER}" -s "${OUTPUT}"
        DEPENDS
            "${CMAKE_SOURCE_DIR}/stub/stub.c"
            "${CMAKE_SOURCE_DIR}/stub/crypto.c"
            "${CMAKE_SOURCE_DIR}/stub/crypto.h"
            "${BLOB_DEP}"
        COMMENT "Building and stripping stub: ${OUTPUT}"
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  x86-64 targets
# ═══════════════════════════════════════════════════════════════════════

set(SHIM_X86    "${CMAKE_BINARY_DIR}/dlopen_shim_x86_64.so")
set(SHIM_BLOB_X86_H "${CMAKE_BINARY_DIR}/dlopen_shim_blob.h")
set(STUB_X86    "${CMAKE_BINARY_DIR}/stub")

compile_shim("${SHIM_X86}" gcc "${CMAKE_SOURCE_DIR}/stub/dlopen_shim.c")
add_custom_target(dlopen_shim_x86 DEPENDS "${SHIM_X86}")

make_blob_header("${SHIM_BLOB_X86_H}" "${SHIM_X86}" "dlopen_shim_blob" "${SHIM_X86}")
add_custom_target(dlopen_shim_blob_h DEPENDS "${SHIM_BLOB_X86_H}")

build_stub("${STUB_X86}" gcc strip "${SHIM_BLOB_X86_H}")
add_custom_target(stub ALL DEPENDS "${STUB_X86}")

# ═══════════════════════════════════════════════════════════════════════
#  ARM64 targets (only when cross-compiler is present)
# ═══════════════════════════════════════════════════════════════════════

if(AARCH64_GCC)
    set(SHIM_ARM64       "${CMAKE_BINARY_DIR}/dlopen_shim_aarch64.so")
    set(SHIM_BLOB_ARM64_H "${CMAKE_BINARY_DIR}/dlopen_shim_blob_aarch64.h")
    set(STUB_ARM64       "${CMAKE_BINARY_DIR}/stub_aarch64")

    compile_shim("${SHIM_ARM64}" "${AARCH64_GCC}" "${CMAKE_SOURCE_DIR}/stub/dlopen_shim.c")
    add_custom_target(dlopen_shim_aarch64 DEPENDS "${SHIM_ARM64}")

    make_blob_header("${SHIM_BLOB_ARM64_H}" "${SHIM_ARM64}" "dlopen_shim_blob" "${SHIM_ARM64}")
    add_custom_target(dlopen_shim_blob_aarch64_h DEPENDS "${SHIM_BLOB_ARM64_H}")

    build_stub("${STUB_ARM64}" "${AARCH64_GCC}" aarch64-linux-gnu-strip "${SHIM_BLOB_ARM64_H}")
    add_custom_target(stub_aarch64 ALL DEPENDS "${STUB_ARM64}")
endif()

# ═══════════════════════════════════════════════════════════════════════
#  Test binaries
# ═══════════════════════════════════════════════════════════════════════

add_executable(hello tests/hello/main.c)
target_compile_options(hello PRIVATE -O2)

if(AARCH64_GCC)
    add_custom_command(
        OUTPUT  "${CMAKE_BINARY_DIR}/hello_aarch64"
        COMMAND "${AARCH64_GCC}" -O2
                -o "${CMAKE_BINARY_DIR}/hello_aarch64"
                "${CMAKE_SOURCE_DIR}/tests/hello/main.c"
        DEPENDS "${CMAKE_SOURCE_DIR}/tests/hello/main.c"
        COMMENT "Building hello_aarch64 test binary"
    )
    add_custom_target(hello_aarch64 ALL DEPENDS "${CMAKE_BINARY_DIR}/hello_aarch64")
endif()

# ═══════════════════════════════════════════════════════════════════════
#  End-to-end tests
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(run_test
    COMMAND ${CMAKE_COMMAND} -E echo "=== x86-64 test ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py"
            --stub  "${CMAKE_BINARY_DIR}/stub"
            --main  "$<TARGET_FILE:hello>"
            --key   "${CMAKE_BINARY_DIR}/test.key"
            --output "${CMAKE_BINARY_DIR}/hello.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/hello.protected"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub hello
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "x86-64 end-to-end test"
    USES_TERMINAL
)

if(AARCH64_GCC)
    add_custom_target(run_test_aarch64
        COMMAND ${CMAKE_COMMAND} -E echo "=== ARM64 test via QEMU binfmt ==="
        COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py"
                --stub  "${CMAKE_BINARY_DIR}/stub_aarch64"
                --main  "${CMAKE_BINARY_DIR}/hello_aarch64"
                --key   "${CMAKE_BINARY_DIR}/test_aarch64.key"
                --output "${CMAKE_BINARY_DIR}/hello_aarch64.protected"
        COMMAND ${CMAKE_COMMAND}
                "-DBINARY=${CMAKE_BINARY_DIR}/hello_aarch64.protected"
                "-DQEMU_LD_PREFIX=/usr/aarch64-linux-gnu"
                -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
        DEPENDS stub_aarch64 hello_aarch64
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        COMMENT "ARM64 end-to-end test via QEMU binfmt"
        USES_TERMINAL
    )
endif()

# ═══════════════════════════════════════════════════════════════════════
#  Helper: compile a shared library with a given compiler
# ═══════════════════════════════════════════════════════════════════════
function(compile_lib OUTPUT COMPILER SOURCE)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2
                -I "${CMAKE_SOURCE_DIR}/tests"
                -o "${OUTPUT}" "${SOURCE}"
        DEPENDS "${SOURCE}"
        COMMENT "Building lib: ${OUTPUT}"
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  Helper: compile a test executable with a given compiler
# ═══════════════════════════════════════════════════════════════════════
function(compile_test_bin OUTPUT COMPILER SOURCE)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -O2
                -I "${CMAKE_SOURCE_DIR}/tests"
                -o "${OUTPUT}" "${SOURCE}" -ldl
        DEPENDS "${SOURCE}"
        COMMENT "Building test binary: ${OUTPUT}"
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen — main binary dlopen's a protected .so via the shim
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/mylib.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen/mylib.c")
add_custom_target(mylib DEPENDS "${CMAKE_BINARY_DIR}/mylib.so")

compile_test_bin("${CMAKE_BINARY_DIR}/dlopen_main"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen/main.c")
add_custom_target(dlopen_main DEPENDS "${CMAKE_BINARY_DIR}/dlopen_main")

add_custom_target(test_dlopen
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_dlopen ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py"
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/dlopen_main"
            --lib    "${CMAKE_BINARY_DIR}/mylib.so"
            --key    "${CMAKE_BINARY_DIR}/dlopen.key"
            --output "${CMAKE_BINARY_DIR}/dlopen_main.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/dlopen_main.protected"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub mylib dlopen_main
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "dlopen test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_multi_so — two protected shared libraries loaded via dlopen
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libmath.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/multi_so/libmath.c")
compile_lib("${CMAKE_BINARY_DIR}/libstr.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/multi_so/libstr.c")
add_custom_target(multi_libs
    DEPENDS "${CMAKE_BINARY_DIR}/libmath.so" "${CMAKE_BINARY_DIR}/libstr.so")

compile_test_bin("${CMAKE_BINARY_DIR}/multi_main"
    gcc "${CMAKE_SOURCE_DIR}/tests/multi_so/main.c")
add_custom_target(multi_main DEPENDS "${CMAKE_BINARY_DIR}/multi_main")

add_custom_target(test_multi_so
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_multi_so ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py"
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/multi_main"
            --lib    "${CMAKE_BINARY_DIR}/libmath.so"
                     "${CMAKE_BINARY_DIR}/libstr.so"
            --key    "${CMAKE_BINARY_DIR}/multi.key"
            --output "${CMAKE_BINARY_DIR}/multi_main.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/multi_main.protected"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub multi_libs multi_main
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "multi_so test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_wrong_key — protected binary must fail cleanly with wrong key
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_wrong_key
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_wrong_key ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py"
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "$<TARGET_FILE:hello>"
            --key    "${CMAKE_BINARY_DIR}/wrongkey.key"
            --output "${CMAKE_BINARY_DIR}/hello_wrongkey.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/hello_wrongkey.protected"
            -P "${CMAKE_SOURCE_DIR}/cmake/test_wrong_key.cmake"
    DEPENDS stub hello
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "wrong key negative test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_tamper — bit-flipped ciphertext must fail GCM tag verification
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_tamper
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_tamper ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py"
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "$<TARGET_FILE:hello>"
            --key    "${CMAKE_BINARY_DIR}/tamper.key"
            --output "${CMAKE_BINARY_DIR}/hello_tamper.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/hello_tamper.protected"
            -P "${CMAKE_SOURCE_DIR}/cmake/test_tamper.cmake"
    DEPENDS stub hello
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "tampered ciphertext negative test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  run_tests — runs all tests and prints a summary
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND}
            "-DBUILD_DIR=${CMAKE_BINARY_DIR}"
            "-DSRC_DIR=${CMAKE_SOURCE_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_all_tests.cmake"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Running all tests"
    USES_TERMINAL
)
