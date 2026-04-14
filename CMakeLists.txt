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

# ── Helper: compile the exe shim (readlink interceptor) ───────────────
# Usage: compile_exe_shim(<output.so> <compiler>)
function(compile_exe_shim OUTPUT COMPILER)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2 -fvisibility=hidden
                -o "${OUTPUT}"
                "${CMAKE_SOURCE_DIR}/stub/exe_shim.c"
                -ldl
        DEPENDS "${CMAKE_SOURCE_DIR}/stub/exe_shim.c"
        COMMENT "Building exe shim: ${OUTPUT}"
    )
endfunction()

# ── Helper: compile the dlopen shim (dlopen interceptor) ─────────────
# Usage: compile_dlopen_shim(<output.so> <compiler>)
function(compile_dlopen_shim OUTPUT COMPILER)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2 -fvisibility=hidden -pthread
                -o "${OUTPUT}"
                "${CMAKE_SOURCE_DIR}/stub/dlopen_shim.c"
                -ldl -lpthread
        DEPENDS "${CMAKE_SOURCE_DIR}/stub/dlopen_shim.c"
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
# Usage: build_stub(<output> <compiler> <stripper> <exe_blob_dep> <dlopen_blob_dep>)
function(build_stub OUTPUT COMPILER STRIPPER EXE_BLOB_DEP DLOPEN_BLOB_DEP)
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
        COMMAND "${COMPILER}" -O2 -Wall -Wextra -pthread ${EXTRA_FLAGS}
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
            "${EXE_BLOB_DEP}"
            "${DLOPEN_BLOB_DEP}"
        COMMENT "Building and stripping stub: ${OUTPUT}"
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  x86-64 targets
# ═══════════════════════════════════════════════════════════════════════

set(STUB_X86    "${CMAKE_BINARY_DIR}/stub")

set(EXE_SHIM_X86        "${CMAKE_BINARY_DIR}/exe_shim_x86_64.so")
set(EXE_SHIM_BLOB_X86_H "${CMAKE_BINARY_DIR}/exe_shim_blob.h")
set(DLOPEN_SHIM_X86        "${CMAKE_BINARY_DIR}/dlopen_shim_x86_64.so")
set(DLOPEN_SHIM_BLOB_X86_H "${CMAKE_BINARY_DIR}/dlopen_shim_blob.h")

compile_exe_shim("${EXE_SHIM_X86}" gcc)
add_custom_target(exe_shim_x86 DEPENDS "${EXE_SHIM_X86}")
compile_dlopen_shim("${DLOPEN_SHIM_X86}" gcc)
add_custom_target(dlopen_shim_x86 DEPENDS "${DLOPEN_SHIM_X86}")

make_blob_header("${EXE_SHIM_BLOB_X86_H}" "${EXE_SHIM_X86}" "exe_shim_blob" "${EXE_SHIM_X86}")
add_custom_target(exe_shim_blob_h DEPENDS "${EXE_SHIM_BLOB_X86_H}")
make_blob_header("${DLOPEN_SHIM_BLOB_X86_H}" "${DLOPEN_SHIM_X86}" "dlopen_shim_blob" "${DLOPEN_SHIM_X86}")
add_custom_target(dlopen_shim_blob_h DEPENDS "${DLOPEN_SHIM_BLOB_X86_H}")

build_stub("${STUB_X86}" gcc strip "${EXE_SHIM_BLOB_X86_H}" "${DLOPEN_SHIM_BLOB_X86_H}")
add_custom_target(stub ALL DEPENDS "${STUB_X86}")

# ═══════════════════════════════════════════════════════════════════════
#  ARM64 targets (only when cross-compiler is present)
# ═══════════════════════════════════════════════════════════════════════

if(AARCH64_GCC)
    set(STUB_ARM64       "${CMAKE_BINARY_DIR}/stub_aarch64")

    set(EXE_SHIM_ARM64        "${CMAKE_BINARY_DIR}/exe_shim_aarch64.so")
    set(EXE_SHIM_BLOB_ARM64_H "${CMAKE_BINARY_DIR}/exe_shim_blob_aarch64.h")
    set(DLOPEN_SHIM_ARM64        "${CMAKE_BINARY_DIR}/dlopen_shim_aarch64.so")
    set(DLOPEN_SHIM_BLOB_ARM64_H "${CMAKE_BINARY_DIR}/dlopen_shim_blob_aarch64.h")

    compile_exe_shim("${EXE_SHIM_ARM64}" "${AARCH64_GCC}")
    add_custom_target(exe_shim_aarch64 DEPENDS "${EXE_SHIM_ARM64}")
    compile_dlopen_shim("${DLOPEN_SHIM_ARM64}" "${AARCH64_GCC}")
    add_custom_target(dlopen_shim_aarch64 DEPENDS "${DLOPEN_SHIM_ARM64}")

    make_blob_header("${EXE_SHIM_BLOB_ARM64_H}" "${EXE_SHIM_ARM64}" "exe_shim_blob" "${EXE_SHIM_ARM64}")
    add_custom_target(exe_shim_blob_aarch64_h DEPENDS "${EXE_SHIM_BLOB_ARM64_H}")
    make_blob_header("${DLOPEN_SHIM_BLOB_ARM64_H}" "${DLOPEN_SHIM_ARM64}" "dlopen_shim_blob" "${DLOPEN_SHIM_ARM64}")
    add_custom_target(dlopen_shim_blob_aarch64_h DEPENDS "${DLOPEN_SHIM_BLOB_ARM64_H}")

    build_stub("${STUB_ARM64}" "${AARCH64_GCC}" aarch64-linux-gnu-strip "${EXE_SHIM_BLOB_ARM64_H}" "${DLOPEN_SHIM_BLOB_ARM64_H}")
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
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "$<TARGET_FILE:hello>"
            --key    "${CMAKE_BINARY_DIR}/test.key"
            --output "${CMAKE_BINARY_DIR}/hello.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/hello.protected"
            "-DEXPECTED_EXIT=42"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub hello
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "x86-64 end-to-end test"
    USES_TERMINAL
)

if(AARCH64_GCC)
    add_custom_target(run_test_aarch64
        COMMAND ${CMAKE_COMMAND} -E echo "=== ARM64 test via QEMU binfmt ==="
        COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
                --stub   "${CMAKE_BINARY_DIR}/stub_aarch64"
                --main   "${CMAKE_BINARY_DIR}/hello_aarch64"
                --key    "${CMAKE_BINARY_DIR}/test_aarch64.key"
                --output "${CMAKE_BINARY_DIR}/hello_aarch64.protected"
        COMMAND ${CMAKE_COMMAND}
                "-DBINARY=${CMAKE_BINARY_DIR}/hello_aarch64.protected"
                "-DQEMU_LD_PREFIX=/usr/aarch64-linux-gnu"
                "-DEXPECTED_EXIT=42"
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
    get_filename_component(_soname "${OUTPUT}" NAME)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2
                -I "${CMAKE_SOURCE_DIR}/tests"
                -Wl,-soname,${_soname}
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
#  Helper: daemon-mode test (protect-daemon + protect-exe --daemon-libs)
#  Usage: daemon_test(test_name client_bin "comment" lib1.so [lib2.so])
#         add_dependencies(test_name stub mylib client_target ...)
# ═══════════════════════════════════════════════════════════════════════
function(daemon_test TEST_NAME CLIENT_BIN COMMENT_STR)
    set(_TD "${CMAKE_BINARY_DIR}/daemon_${TEST_NAME}")
    add_custom_target(${TEST_NAME}
        COMMAND ${CMAKE_COMMAND} -E echo "=== ${TEST_NAME} ==="
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD}"
        COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-daemon
                --stub   "${CMAKE_BINARY_DIR}/stub"
                --key    "${_TD}/test.key"
                --libs   ${ARGN}
                --output "${_TD}/.antirev-libd"
        COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
                --stub   "${CMAKE_BINARY_DIR}/stub"
                --main   "${CLIENT_BIN}"
                --key    "${_TD}/test.key"
                --daemon-libs
                --output "${_TD}/test.protected"
        COMMAND ${CMAKE_COMMAND}
                "-DBINARY=${_TD}/test.protected"
                -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        COMMENT "${COMMENT_STR}"
        USES_TERMINAL
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  Shared test libraries and binaries
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/mylib.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen/mylib.c")
add_custom_target(mylib DEPENDS "${CMAKE_BINARY_DIR}/mylib.so")

compile_test_bin("${CMAKE_BINARY_DIR}/dlopen_main"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen/main.c")
add_custom_target(dlopen_main DEPENDS "${CMAKE_BINARY_DIR}/dlopen_main")

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen — main binary dlopen's a protected .so via the shim
# ═══════════════════════════════════════════════════════════════════════

daemon_test(test_dlopen "${CMAKE_BINARY_DIR}/dlopen_main"
    "dlopen test (.so via daemon)"
    "${CMAKE_BINARY_DIR}/mylib.so")
add_dependencies(test_dlopen stub mylib dlopen_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_edgecases — paths, flags, reopen, fallthrough
# ═══════════════════════════════════════════════════════════════════════

compile_test_bin("${CMAKE_BINARY_DIR}/dlopen_edgecases"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen_edgecases/main.c")
add_custom_target(dlopen_edgecases DEPENDS "${CMAKE_BINARY_DIR}/dlopen_edgecases")

daemon_test(test_dlopen_edgecases "${CMAKE_BINARY_DIR}/dlopen_edgecases"
    "dlopen edge-case tests (paths, flags, reopen, fallthrough)"
    "${CMAKE_BINARY_DIR}/mylib.so")
add_dependencies(test_dlopen_edgecases stub mylib dlopen_edgecases)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_nested — dlopen from within a protected shared library
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libcallee.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen_nested/libcallee.c")
add_custom_target(libcallee DEPENDS "${CMAKE_BINARY_DIR}/libcallee.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/libcaller.so"
    COMMAND gcc -shared -fPIC -O2
            -I "${CMAKE_SOURCE_DIR}/tests"
            -Wl,-soname,libcaller.so
            -o "${CMAKE_BINARY_DIR}/libcaller.so"
            "${CMAKE_SOURCE_DIR}/tests/dlopen_nested/libcaller.c"
            -ldl
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/dlopen_nested/libcaller.c"
    COMMENT "Building libcaller.so (nested dlopen test)"
)
add_custom_target(libcaller DEPENDS "${CMAKE_BINARY_DIR}/libcaller.so")

compile_test_bin("${CMAKE_BINARY_DIR}/dlopen_nested"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen_nested/main.c")
add_custom_target(dlopen_nested_bin DEPENDS "${CMAKE_BINARY_DIR}/dlopen_nested")

daemon_test(test_dlopen_nested "${CMAKE_BINARY_DIR}/dlopen_nested"
    "nested dlopen test (caller->callee chain via shim)"
    "${CMAKE_BINARY_DIR}/libcaller.so" "${CMAKE_BINARY_DIR}/libcallee.so")
add_dependencies(test_dlopen_nested stub libcallee libcaller dlopen_nested_bin)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_transitive — encrypted lib behind unencrypted intermediary
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libinner.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen_transitive/libinner.c")
add_custom_target(libinner DEPENDS "${CMAKE_BINARY_DIR}/libinner.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/libmiddle.so"
    COMMAND gcc -shared -fPIC -O2
            -I "${CMAKE_SOURCE_DIR}/tests"
            -Wl,-soname,libmiddle.so
            -o "${CMAKE_BINARY_DIR}/libmiddle.so"
            "${CMAKE_SOURCE_DIR}/tests/dlopen_transitive/libmiddle.c"
            -ldl
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/dlopen_transitive/libmiddle.c"
    COMMENT "Building libmiddle.so (transitive test)"
)
add_custom_target(libmiddle DEPENDS "${CMAKE_BINARY_DIR}/libmiddle.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/libbridge.so"
    COMMAND gcc -shared -fPIC -O2
            -I "${CMAKE_SOURCE_DIR}/tests"
            -Wl,-soname,libbridge.so
            -o "${CMAKE_BINARY_DIR}/libbridge.so"
            "${CMAKE_SOURCE_DIR}/tests/dlopen_transitive/libbridge.c"
            -L "${CMAKE_BINARY_DIR}" -lmiddle -Wl,--no-as-needed
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/dlopen_transitive/libbridge.c"
            "${CMAKE_BINARY_DIR}/libmiddle.so"
    COMMENT "Building libbridge.so (unencrypted intermediary)"
)
add_custom_target(libbridge DEPENDS "${CMAKE_BINARY_DIR}/libbridge.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/dlopen_transitive"
    COMMAND gcc -O2
            -I "${CMAKE_SOURCE_DIR}/tests"
            -o "${CMAKE_BINARY_DIR}/dlopen_transitive"
            "${CMAKE_SOURCE_DIR}/tests/dlopen_transitive/main.c"
            -L "${CMAKE_BINARY_DIR}" -lbridge -Wl,--no-as-needed
            -Wl,-rpath,${CMAKE_BINARY_DIR}
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/dlopen_transitive/main.c"
            "${CMAKE_BINARY_DIR}/libbridge.so"
    COMMENT "Building dlopen_transitive test binary"
)
add_custom_target(dlopen_transitive_bin DEPENDS "${CMAKE_BINARY_DIR}/dlopen_transitive")

set(_TD_TRANS "${CMAKE_BINARY_DIR}/daemon_test_dlopen_transitive")
add_custom_target(test_dlopen_transitive
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_dlopen_transitive ==="
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_TRANS}"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --key    "${_TD_TRANS}/test.key"
            --libs   "${CMAKE_BINARY_DIR}/libmiddle.so"
                     "${CMAKE_BINARY_DIR}/libinner.so"
            --output "${_TD_TRANS}/.antirev-libd"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/dlopen_transitive"
            --key    "${_TD_TRANS}/test.key"
            --daemon-libs
            --output "${_TD_TRANS}/test.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${_TD_TRANS}/test.protected"
            "-DLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub libinner libmiddle libbridge dlopen_transitive_bin
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "transitive DT_NEEDED through unencrypted intermediary"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_dt_needed — exe dlopen's libfoo, libfoo DT_NEEDs libbar,
#  ALL encrypted.  Tests LD_LIBRARY_PATH symlink resolution for
#  DT_NEEDED deps of dlopen'd libs.
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libbar.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen_dt_needed/libbar.c")
add_custom_target(libbar DEPENDS "${CMAKE_BINARY_DIR}/libbar.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/libfoo.so"
    COMMAND gcc -shared -fPIC -O2
            -Wl,-soname,libfoo.so
            -o "${CMAKE_BINARY_DIR}/libfoo.so"
            "${CMAKE_SOURCE_DIR}/tests/dlopen_dt_needed/libfoo.c"
            -L "${CMAKE_BINARY_DIR}" -lbar -Wl,--no-as-needed
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/dlopen_dt_needed/libfoo.c"
            "${CMAKE_BINARY_DIR}/libbar.so"
    COMMENT "Building libfoo.so (dlopen_dt_needed test)"
)
add_custom_target(libfoo DEPENDS "${CMAKE_BINARY_DIR}/libfoo.so")

compile_test_bin("${CMAKE_BINARY_DIR}/dlopen_dt_needed"
    gcc "${CMAKE_SOURCE_DIR}/tests/dlopen_dt_needed/main.c")
add_custom_target(dlopen_dt_needed_bin DEPENDS "${CMAKE_BINARY_DIR}/dlopen_dt_needed")

set(_TD_DTN "${CMAKE_BINARY_DIR}/daemon_test_dlopen_dt_needed")
add_custom_target(test_dlopen_dt_needed
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_dlopen_dt_needed ==="
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_DTN}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_DTN}/enc_disk"
    # Pack libs into daemon
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --key    "${_TD_DTN}/test.key"
            --libs   "${CMAKE_BINARY_DIR}/libfoo.so"
                     "${CMAKE_BINARY_DIR}/libbar.so"
            --output "${_TD_DTN}/.antirev-libd"
    # Put encrypted copies on disk so the linker finds them (and fails
    # with "invalid ELF header" rather than "not found")
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key    "${_TD_DTN}/test.key"
            --libs   "${CMAKE_BINARY_DIR}/libfoo.so"
                     "${CMAKE_BINARY_DIR}/libbar.so"
            --output-dir "${_TD_DTN}/enc_disk"
    # Protect exe
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/dlopen_dt_needed"
            --key    "${_TD_DTN}/test.key"
            --daemon-libs
            --output "${_TD_DTN}/test.protected"
    # Run with LD_LIBRARY_PATH pointing to encrypted copies on disk
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${_TD_DTN}/test.protected"
            "-DLD_LIBRARY_PATH=${_TD_DTN}/enc_disk"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub libbar libfoo dlopen_dt_needed_bin
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "dlopen DT_NEEDED: exe->dlopen(libfoo)->DT_NEEDED(libbar), all encrypted"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_preload_memfd — smoke test: DT_NEEDED satisfied via LD_PRELOAD
#  from a memfd (no .so on disk, no LD_AUDIT)
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libpretest.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/preload_memfd/libpretest.c")
add_custom_target(libpretest DEPENDS "${CMAKE_BINARY_DIR}/libpretest.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/preload_launcher"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/preload_launcher"
            "${CMAKE_SOURCE_DIR}/tests/preload_memfd/launcher.c"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/preload_memfd/launcher.c"
    COMMENT "Building preload_launcher"
)
add_custom_target(preload_launcher DEPENDS "${CMAKE_BINARY_DIR}/preload_launcher")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/preload_main"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/preload_main"
            "${CMAKE_SOURCE_DIR}/tests/preload_memfd/main.c"
            -L "${CMAKE_BINARY_DIR}" -lpretest -Wl,--no-as-needed
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/preload_memfd/main.c"
            "${CMAKE_BINARY_DIR}/libpretest.so"
    COMMENT "Building preload_main"
)
add_custom_target(preload_main DEPENDS "${CMAKE_BINARY_DIR}/preload_main")

add_custom_target(test_preload_memfd
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_preload_memfd ==="
    COMMAND "${CMAKE_BINARY_DIR}/preload_launcher"
            "${CMAKE_BINARY_DIR}/libpretest.so"
            "${CMAKE_BINARY_DIR}/preload_main"
    DEPENDS preload_launcher preload_main libpretest
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "LD_PRELOAD memfd DT_NEEDED satisfaction smoke test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_plain_so — encrypted exe dlopen's an unencrypted (plain) .so
# ═══════════════════════════════════════════════════════════════════════

compile_test_bin("${CMAKE_BINARY_DIR}/plain_so_main"
    gcc "${CMAKE_SOURCE_DIR}/tests/plain_so/main.c")
add_custom_target(plain_so_main DEPENDS "${CMAKE_BINARY_DIR}/plain_so_main")

add_custom_target(test_plain_so
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_plain_so ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/plain_so_main"
            --key    "${CMAKE_BINARY_DIR}/plain_so.key"
            --output "${CMAKE_BINARY_DIR}/plain_so_main.protected"
    COMMAND "${CMAKE_BINARY_DIR}/plain_so_main.protected"
            "${CMAKE_BINARY_DIR}/mylib.so"
    DEPENDS stub mylib plain_so_main
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "encrypted exe + plain (unencrypted) .so test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_plain_exe_enc_so — plain exe + encrypted .so via protect.py run
# ═══════════════════════════════════════════════════════════════════════

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
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_BINARY_DIR}/multi.key"
            --libs       "${CMAKE_BINARY_DIR}/libmath.so"
                         "${CMAKE_BINARY_DIR}/libstr.so"
            --output-dir "${CMAKE_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/multi_main"
            --key    "${CMAKE_BINARY_DIR}/multi.key"
            --output "${CMAKE_BINARY_DIR}/multi_main.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/multi_main.protected"
            "-DLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/encrypted"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub multi_libs multi_main
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "multi_so test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_linked — DT_NEEDED library loaded via LD_AUDIT audit shim
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/liblinkedmath.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/linked/liblinkedmath.c")
add_custom_target(liblinkedmath DEPENDS "${CMAKE_BINARY_DIR}/liblinkedmath.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/linked_main"
    COMMAND gcc -O2
            -I "${CMAKE_SOURCE_DIR}/tests"
            -o "${CMAKE_BINARY_DIR}/linked_main"
            "${CMAKE_SOURCE_DIR}/tests/linked/main.c"
            -L "${CMAKE_BINARY_DIR}" -llinkedmath
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/linked/main.c"
            "${CMAKE_BINARY_DIR}/liblinkedmath.so"
    COMMENT "Building test binary: linked_main"
)
add_custom_target(linked_main DEPENDS "${CMAKE_BINARY_DIR}/linked_main")

daemon_test(test_linked "${CMAKE_BINARY_DIR}/linked_main"
    "DT_NEEDED satisfied via daemon-served encrypted .so"
    "${CMAKE_BINARY_DIR}/liblinkedmath.so")
add_dependencies(test_linked stub liblinkedmath linked_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_fd_reduction — exe_shim must close DT_NEEDED memfds after ctor
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/fd_reduction_main"
    COMMAND gcc -O2
            -I "${CMAKE_SOURCE_DIR}/tests"
            -o "${CMAKE_BINARY_DIR}/fd_reduction_main"
            "${CMAKE_SOURCE_DIR}/tests/fd_reduction/main.c"
            -L "${CMAKE_BINARY_DIR}" -llinkedmath
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/fd_reduction/main.c"
            "${CMAKE_BINARY_DIR}/liblinkedmath.so"
    COMMENT "Building test binary: fd_reduction_main"
)
add_custom_target(fd_reduction_main DEPENDS "${CMAKE_BINARY_DIR}/fd_reduction_main")

daemon_test(test_fd_reduction "${CMAKE_BINARY_DIR}/fd_reduction_main"
    "DT_NEEDED memfds closed by exe_shim ctor (fd reduction)"
    "${CMAKE_BINARY_DIR}/liblinkedmath.so")
add_dependencies(test_fd_reduction stub liblinkedmath fd_reduction_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_fork_exec — child process spawned via fork()+exec() must be able
#  to dlopen an encrypted .so via the inherited LD_AUDIT shim
# ═══════════════════════════════════════════════════════════════════════

compile_test_bin("${CMAKE_BINARY_DIR}/fork_exec_parent"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_exec/parent.c")
add_custom_target(fork_exec_parent DEPENDS "${CMAKE_BINARY_DIR}/fork_exec_parent")

compile_test_bin("${CMAKE_BINARY_DIR}/fork_exec_child"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_exec/child.c")
add_custom_target(fork_exec_child DEPENDS "${CMAKE_BINARY_DIR}/fork_exec_child")

add_custom_target(test_fork_exec
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_fork_exec ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_BINARY_DIR}/fork_exec.key"
            --libs       "${CMAKE_BINARY_DIR}/mylib.so"
            --output-dir "${CMAKE_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/fork_exec_parent"
            --key    "${CMAKE_BINARY_DIR}/fork_exec.key"
            --output "${CMAKE_BINARY_DIR}/fork_exec_parent.protected"
    COMMAND ${CMAKE_COMMAND} -E env
            "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/encrypted"
            "${CMAKE_BINARY_DIR}/fork_exec_parent.protected"
            "${CMAKE_BINARY_DIR}/fork_exec_child"
            "${CMAKE_BINARY_DIR}/encrypted/mylib.so"
    DEPENDS stub mylib fork_exec_parent fork_exec_child
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "fork+exec child inherits audit shim test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_multi_process — full chain: PM → gRPC daemon → work process
#  (fork+exec, encrypted .so, /proc/self/exe, all in one test)
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libwork.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/multi_process/libwork.c")
add_custom_target(libwork DEPENDS "${CMAKE_BINARY_DIR}/libwork.so")

compile_test_bin("${CMAKE_BINARY_DIR}/work_process"
    gcc "${CMAKE_SOURCE_DIR}/tests/multi_process/work_process.c")
add_custom_target(work_process_bin DEPENDS "${CMAKE_BINARY_DIR}/work_process")

compile_test_bin("${CMAKE_BINARY_DIR}/grpc_daemon_sim"
    gcc "${CMAKE_SOURCE_DIR}/tests/multi_process/grpc_daemon.c")
add_custom_target(grpc_daemon_sim DEPENDS "${CMAKE_BINARY_DIR}/grpc_daemon_sim")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/pm_sim"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/pm_sim"
            "${CMAKE_SOURCE_DIR}/tests/multi_process/pm.c"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/multi_process/pm.c"
    COMMENT "Building test binary: pm_sim"
)
add_custom_target(pm_sim DEPENDS "${CMAKE_BINARY_DIR}/pm_sim")

add_custom_target(test_multi_process
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_multi_process ==="
    # Encrypt the shared library
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_BINARY_DIR}/multi_process.key"
            --libs       "${CMAKE_BINARY_DIR}/libwork.so"
            --output-dir "${CMAKE_BINARY_DIR}/encrypted"
    # Protect all three binaries with the same key
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/work_process"
            --key    "${CMAKE_BINARY_DIR}/multi_process.key"
            --output "${CMAKE_BINARY_DIR}/work_process.protected"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/grpc_daemon_sim"
            --key    "${CMAKE_BINARY_DIR}/multi_process.key"
            --output "${CMAKE_BINARY_DIR}/grpc_daemon_sim.protected"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/pm_sim"
            --key    "${CMAKE_BINARY_DIR}/multi_process.key"
            --output "${CMAKE_BINARY_DIR}/pm_sim.protected"
    # Run the orchestration script
    COMMAND bash "${CMAKE_SOURCE_DIR}/tests/multi_process/run_test.sh"
            "${CMAKE_BINARY_DIR}/grpc_daemon_sim.protected"
            "${CMAKE_BINARY_DIR}/pm_sim.protected"
            "${CMAKE_BINARY_DIR}/work_process.protected"
            "${CMAKE_BINARY_DIR}/encrypted/libwork.so"
    DEPENDS stub libwork work_process_bin grpc_daemon_sim pm_sim
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Multi-process chain test: PM -> gRPC daemon -> work process"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_proc_self_exe — readlink("/proc/self/exe") must return the real
#  on-disk path, not a memfd path, after fexecve
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/proc_self_exe_test"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/proc_self_exe_test"
            "${CMAKE_SOURCE_DIR}/tests/proc_self_exe/main.c"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/proc_self_exe/main.c"
    COMMENT "Building test binary: proc_self_exe_test"
)
add_custom_target(proc_self_exe_test DEPENDS "${CMAKE_BINARY_DIR}/proc_self_exe_test")

add_custom_target(test_proc_self_exe
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_proc_self_exe ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/proc_self_exe_test"
            --key    "${CMAKE_BINARY_DIR}/proc_self_exe.key"
            --output "${CMAKE_BINARY_DIR}/proc_self_exe_test.protected"
    COMMAND "${CMAKE_BINARY_DIR}/proc_self_exe_test.protected"
    DEPENDS stub proc_self_exe_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "/proc/self/exe readlink interception test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_ctor_readlink — readlink("/proc/self/exe") called from a C++
#  global static initializer in a DT_NEEDED library (before exe_shim's
#  constructor) must return the real path, not memfd.
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/libctor_readlink.so"
    COMMAND g++ -shared -fPIC -O2
            -Wl,-soname,libctor_readlink.so
            -o "${CMAKE_BINARY_DIR}/libctor_readlink.so"
            "${CMAKE_SOURCE_DIR}/tests/ctor_readlink/libctor_readlink.cpp"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/ctor_readlink/libctor_readlink.cpp"
    COMMENT "Building lib: libctor_readlink.so"
)
add_custom_target(libctor_readlink DEPENDS "${CMAKE_BINARY_DIR}/libctor_readlink.so")

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/ctor_readlink_main"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/ctor_readlink_main"
            "${CMAKE_SOURCE_DIR}/tests/ctor_readlink/main.c"
            -L "${CMAKE_BINARY_DIR}" -lctor_readlink
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/ctor_readlink/main.c"
            "${CMAKE_BINARY_DIR}/libctor_readlink.so"
    COMMENT "Building test binary: ctor_readlink_main"
)
add_custom_target(ctor_readlink_main DEPENDS "${CMAKE_BINARY_DIR}/ctor_readlink_main")

daemon_test(test_ctor_readlink "${CMAKE_BINARY_DIR}/ctor_readlink_main"
    "C++ ctor readlink before exe_shim constructor"
    "${CMAKE_BINARY_DIR}/libctor_readlink.so")
add_dependencies(test_ctor_readlink stub libctor_readlink ctor_readlink_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_realpath — realpath/canonicalize_file_name on /proc/self/exe
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/realpath_test"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/realpath_test"
            "${CMAKE_SOURCE_DIR}/tests/realpath/main.c"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/realpath/main.c"
    COMMENT "Building test binary: realpath_test"
)
add_custom_target(realpath_test DEPENDS "${CMAKE_BINARY_DIR}/realpath_test")

add_custom_target(test_realpath
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_realpath ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/realpath_test"
            --key    "${CMAKE_BINARY_DIR}/realpath.key"
            --output "${CMAKE_BINARY_DIR}/realpath_test.protected"
    COMMAND "${CMAKE_BINARY_DIR}/realpath_test.protected"
    DEPENDS stub realpath_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "realpath/canonicalize_file_name interception test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_path_stress — comprehensive path resolution stress test
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/path_stress_test"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/path_stress_test"
            "${CMAKE_SOURCE_DIR}/tests/path_stress/main.c"
            -ldl
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/path_stress/main.c"
    COMMENT "Building test binary: path_stress_test"
)
add_custom_target(path_stress_test DEPENDS "${CMAKE_BINARY_DIR}/path_stress_test")

# Without --has-libs (no LD_AUDIT)
add_custom_target(test_path_stress
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_path_stress no_audit ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/path_stress_test"
            --key    "${CMAKE_BINARY_DIR}/path_stress.key"
            --output "${CMAKE_BINARY_DIR}/path_stress_test.protected"
    COMMAND "${CMAKE_BINARY_DIR}/path_stress_test.protected"
    DEPENDS stub path_stress_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "path stress test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_getauxval — getauxval(AT_EXECFN) returns real path, not memfd
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/getauxval_test"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/getauxval_test"
            "${CMAKE_SOURCE_DIR}/tests/getauxval/main.c"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/getauxval/main.c"
    COMMENT "Building test binary: getauxval_test"
)
add_custom_target(getauxval_test DEPENDS "${CMAKE_BINARY_DIR}/getauxval_test")

add_custom_target(test_getauxval
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_getauxval ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/getauxval_test"
            --key    "${CMAKE_BINARY_DIR}/getauxval.key"
            --output "${CMAKE_BINARY_DIR}/getauxval_test.protected"
    COMMAND "${CMAKE_BINARY_DIR}/getauxval_test.protected"
    DEPENDS stub getauxval_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "getauxval(AT_EXECFN) interception test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_comm_name — /proc/self/comm restored to original binary name
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/comm_name_test"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/comm_name_test"
            "${CMAKE_SOURCE_DIR}/tests/comm_name/main.c"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/comm_name/main.c"
    COMMENT "Building test binary: comm_name_test"
)
add_custom_target(comm_name_test DEPENDS "${CMAKE_BINARY_DIR}/comm_name_test")

add_custom_target(test_comm_name
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_comm_name ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/comm_name_test"
            --key    "${CMAKE_BINARY_DIR}/comm_name.key"
            --output "${CMAKE_BINARY_DIR}/comm_name_test.protected"
    COMMAND "${CMAKE_BINARY_DIR}/comm_name_test.protected"
    DEPENDS stub comm_name_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "process comm name restoration test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_self_read — open() on protected binary redirects to decrypted memfd
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/self_read_test"
    COMMAND gcc -O2
            -o "${CMAKE_BINARY_DIR}/self_read_test"
            "${CMAKE_SOURCE_DIR}/tests/self_read/main.c"
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/self_read/main.c"
    COMMENT "Building test binary: self_read_test"
)
add_custom_target(self_read_test DEPENDS "${CMAKE_BINARY_DIR}/self_read_test")

add_custom_target(test_self_read
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_self_read ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/self_read_test"
            --key    "${CMAKE_BINARY_DIR}/self_read.key"
            --output "${CMAKE_BINARY_DIR}/self_read_test.protected"
    COMMAND "${CMAKE_BINARY_DIR}/self_read_test.protected"
    DEPENDS stub self_read_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "self-read redirect test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_daemon_fdclose — close all fds then dlopen via KEY_HEX fallback
# ═══════════════════════════════════════════════════════════════════════

compile_test_bin("${CMAKE_BINARY_DIR}/daemon_fdclose_test"
    gcc "${CMAKE_SOURCE_DIR}/tests/daemon_fdclose/main.c")
add_custom_target(daemon_fdclose_test DEPENDS "${CMAKE_BINARY_DIR}/daemon_fdclose_test")

add_custom_target(test_daemon_fdclose
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_daemon_fdclose ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_BINARY_DIR}/daemon_fdclose.key"
            --libs       "${CMAKE_BINARY_DIR}/mylib.so"
            --output-dir "${CMAKE_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/daemon_fdclose_test"
            --key    "${CMAKE_BINARY_DIR}/daemon_fdclose.key"
            --output "${CMAKE_BINARY_DIR}/daemon_fdclose_test.protected"
    COMMAND ${CMAKE_COMMAND} -E env
            "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/encrypted"
            "${CMAKE_BINARY_DIR}/daemon_fdclose_test.protected"
            "${CMAKE_BINARY_DIR}/encrypted/mylib.so"
    DEPENDS stub mylib daemon_fdclose_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "daemon fd-close KEY_HEX fallback test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_concurrent_dlopen — thread-safe cache (multiple threads dlopen)
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/concurrent_dlopen_test"
    COMMAND gcc -O2
            -I "${CMAKE_SOURCE_DIR}/tests"
            -o "${CMAKE_BINARY_DIR}/concurrent_dlopen_test"
            "${CMAKE_SOURCE_DIR}/tests/concurrent_dlopen/main.c"
            -ldl -pthread
    DEPENDS "${CMAKE_SOURCE_DIR}/tests/concurrent_dlopen/main.c"
    COMMENT "Building test binary: concurrent_dlopen_test"
)
add_custom_target(concurrent_dlopen_test DEPENDS "${CMAKE_BINARY_DIR}/concurrent_dlopen_test")

add_custom_target(test_concurrent_dlopen
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_concurrent_dlopen ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_BINARY_DIR}/concurrent.key"
            --libs       "${CMAKE_BINARY_DIR}/mylib.so"
            --output-dir "${CMAKE_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/concurrent_dlopen_test"
            --key    "${CMAKE_BINARY_DIR}/concurrent.key"
            --output "${CMAKE_BINARY_DIR}/concurrent_dlopen_test.protected"
    COMMAND ${CMAKE_COMMAND} -E env
            "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/encrypted"
            "${CMAKE_BINARY_DIR}/concurrent_dlopen_test.protected"
            "${CMAKE_BINARY_DIR}/encrypted/mylib.so"
    DEPENDS stub mylib concurrent_dlopen_test
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "concurrent dlopen thread-safe cache test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_wrong_key — protected binary must fail cleanly with wrong key
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_wrong_key
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_wrong_key ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
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
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
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
#  test_fork_same_lib — child inherits same bundled .so via LD_PRELOAD
# ═══════════════════════════════════════════════════════════════════════

compile_test_bin("${CMAKE_BINARY_DIR}/fork_same_parent"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_same_lib/parent.c")
add_custom_target(fork_same_parent DEPENDS "${CMAKE_BINARY_DIR}/fork_same_parent")

compile_test_bin("${CMAKE_BINARY_DIR}/fork_same_child"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_same_lib/child.c")
add_custom_target(fork_same_child DEPENDS "${CMAKE_BINARY_DIR}/fork_same_child")

set(_TD_FSL "${CMAKE_BINARY_DIR}/daemon_test_fork_same_lib")
add_custom_target(test_fork_same_lib
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_fork_same_lib ==="
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_FSL}"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --key    "${_TD_FSL}/test.key"
            --libs   "${CMAKE_BINARY_DIR}/mylib.so"
            --output "${_TD_FSL}/.antirev-libd"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/fork_same_parent"
            --key    "${_TD_FSL}/test.key"
            --daemon-libs
            --output "${_TD_FSL}/parent.protected"
    COMMAND "${_TD_FSL}/parent.protected"
            "${CMAKE_BINARY_DIR}/fork_same_child"
    DEPENDS stub mylib fork_same_parent fork_same_child
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "fork+exec child inherits same lib via daemon"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_fork_diff_lib — parent and child use different libs independently
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libparent.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_diff_lib/libparent.c")
add_custom_target(libparent DEPENDS "${CMAKE_BINARY_DIR}/libparent.so")

compile_lib("${CMAKE_BINARY_DIR}/libchild.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_diff_lib/libchild.c")
add_custom_target(libchild DEPENDS "${CMAKE_BINARY_DIR}/libchild.so")

compile_test_bin("${CMAKE_BINARY_DIR}/fork_diff_parent"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_diff_lib/parent.c")
add_custom_target(fork_diff_parent DEPENDS "${CMAKE_BINARY_DIR}/fork_diff_parent")

compile_test_bin("${CMAKE_BINARY_DIR}/fork_diff_child"
    gcc "${CMAKE_SOURCE_DIR}/tests/fork_diff_lib/child.c")
add_custom_target(fork_diff_child DEPENDS "${CMAKE_BINARY_DIR}/fork_diff_child")

set(_TD_FDL "${CMAKE_BINARY_DIR}/daemon_test_fork_diff_lib")
add_custom_target(test_fork_diff_lib
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_fork_diff_lib ==="
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_FDL}/parent" "${_TD_FDL}/child"
    # Daemon + client for parent (libparent.so)
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --key    "${_TD_FDL}/parent/test.key"
            --libs   "${CMAKE_BINARY_DIR}/libparent.so"
            --output "${_TD_FDL}/parent/.antirev-libd"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/fork_diff_parent"
            --key    "${_TD_FDL}/parent/test.key"
            --daemon-libs
            --output "${_TD_FDL}/parent/parent.protected"
    # Daemon + client for child (libchild.so, different key)
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --key    "${_TD_FDL}/child/test.key"
            --libs   "${CMAKE_BINARY_DIR}/libchild.so"
            --output "${_TD_FDL}/child/.antirev-libd"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/fork_diff_child"
            --key    "${_TD_FDL}/child/test.key"
            --daemon-libs
            --output "${_TD_FDL}/child/child.protected"
    # Run: parent execs child
    COMMAND "${_TD_FDL}/parent/parent.protected"
            "${_TD_FDL}/child/child.protected"
    DEPENDS stub libparent libchild fork_diff_parent fork_diff_child
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "parent(libparent.so) fork+exec child(libchild.so) via daemon"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_script_multi_bin — script invokes A and B with shared + unique libs
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_BINARY_DIR}/libcommon.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/script_multi_bin/libcommon.c")
compile_lib("${CMAKE_BINARY_DIR}/libA_only.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/script_multi_bin/libA_only.c")
compile_lib("${CMAKE_BINARY_DIR}/libB_only.so"
    gcc "${CMAKE_SOURCE_DIR}/tests/script_multi_bin/libB_only.c")
add_custom_target(script_multi_libs
    DEPENDS "${CMAKE_BINARY_DIR}/libcommon.so"
            "${CMAKE_BINARY_DIR}/libA_only.so"
            "${CMAKE_BINARY_DIR}/libB_only.so")

compile_test_bin("${CMAKE_BINARY_DIR}/proc_a"
    gcc "${CMAKE_SOURCE_DIR}/tests/script_multi_bin/proc_a.c")
add_custom_target(proc_a DEPENDS "${CMAKE_BINARY_DIR}/proc_a")

compile_test_bin("${CMAKE_BINARY_DIR}/proc_b"
    gcc "${CMAKE_SOURCE_DIR}/tests/script_multi_bin/proc_b.c")
add_custom_target(proc_b DEPENDS "${CMAKE_BINARY_DIR}/proc_b")

set(_TD_SMB "${CMAKE_BINARY_DIR}/daemon_test_script_multi_bin")
add_custom_target(test_script_multi_bin
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_script_multi_bin ==="
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_SMB}"
    # One daemon serves all libs (same key for both clients)
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --key    "${_TD_SMB}/test.key"
            --libs   "${CMAKE_BINARY_DIR}/libcommon.so"
                     "${CMAKE_BINARY_DIR}/libA_only.so"
                     "${CMAKE_BINARY_DIR}/libB_only.so"
            --output "${_TD_SMB}/.antirev-libd"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/proc_a"
            --key    "${_TD_SMB}/test.key"
            --daemon-libs
            --output "${_TD_SMB}/proc_a.protected"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/proc_b"
            --key    "${_TD_SMB}/test.key"
            --daemon-libs
            --output "${_TD_SMB}/proc_b.protected"
    COMMAND "${_TD_SMB}/proc_a.protected"
    COMMAND "${_TD_SMB}/proc_b.protected"
    DEPENDS stub script_multi_libs proc_a proc_b
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "A(common+A_only) and B(common+B_only) via daemon"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_lib_daemon — centralized lib daemon serves libs to client exes
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_lib_daemon
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_lib_daemon ==="
    COMMAND bash "${CMAKE_SOURCE_DIR}/tests/lib_daemon/run_test.sh"
            "${CMAKE_BINARY_DIR}/stub"
            "${CMAKE_BINARY_DIR}/dlopen_main"
            "${CMAKE_BINARY_DIR}/linked_main"
            "${CMAKE_BINARY_DIR}/mylib.so"
            "${CMAKE_BINARY_DIR}/liblinkedmath.so"
    DEPENDS stub mylib liblinkedmath dlopen_main linked_main
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "lib daemon mode test (dlopen + DT_NEEDED via daemon)"
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
