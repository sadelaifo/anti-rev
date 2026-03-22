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

# ── Helper: compile the audit shim (includes crypto.c) ────────────────
# Usage: compile_audit_shim(<output.so> <compiler>)
function(compile_audit_shim OUTPUT COMPILER)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2 -fvisibility=hidden
                -I "${CMAKE_SOURCE_DIR}/stub"
                -o "${OUTPUT}"
                "${CMAKE_SOURCE_DIR}/stub/audit_shim.c"
                "${CMAKE_SOURCE_DIR}/stub/crypto.c"
                -ldl
        DEPENDS "${CMAKE_SOURCE_DIR}/stub/audit_shim.c"
                "${CMAKE_SOURCE_DIR}/stub/crypto.c"
                "${CMAKE_SOURCE_DIR}/stub/crypto.h"
        COMMENT "Building audit shim: ${OUTPUT}"
    )
endfunction()

# ── Helper: compile the exe shim (readlink interceptor) ───────────────
# Usage: compile_exe_shim(<output.so> <compiler>)
function(compile_exe_shim OUTPUT COMPILER)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2 -fvisibility=hidden
                -o "${OUTPUT}"
                "${CMAKE_SOURCE_DIR}/stub/exe_shim.c"
        DEPENDS "${CMAKE_SOURCE_DIR}/stub/exe_shim.c"
        COMMENT "Building exe shim: ${OUTPUT}"
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
# Usage: build_stub(<output> <compiler> <stripper> <audit_blob_dep> <exe_blob_dep>)
function(build_stub OUTPUT COMPILER STRIPPER AUDIT_BLOB_DEP EXE_BLOB_DEP)
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
            "${AUDIT_BLOB_DEP}"
            "${EXE_BLOB_DEP}"
        COMMENT "Building and stripping stub: ${OUTPUT}"
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  x86-64 targets
# ═══════════════════════════════════════════════════════════════════════

set(STUB_X86    "${CMAKE_BINARY_DIR}/stub")

set(AUDIT_X86        "${CMAKE_BINARY_DIR}/audit_shim_x86_64.so")
set(AUDIT_BLOB_X86_H "${CMAKE_BINARY_DIR}/audit_shim_blob.h")

set(EXE_SHIM_X86        "${CMAKE_BINARY_DIR}/exe_shim_x86_64.so")
set(EXE_SHIM_BLOB_X86_H "${CMAKE_BINARY_DIR}/exe_shim_blob.h")

compile_audit_shim("${AUDIT_X86}" gcc)
add_custom_target(audit_shim_x86 DEPENDS "${AUDIT_X86}")

make_blob_header("${AUDIT_BLOB_X86_H}" "${AUDIT_X86}" "audit_shim_blob" "${AUDIT_X86}")
add_custom_target(audit_shim_blob_h DEPENDS "${AUDIT_BLOB_X86_H}")

compile_exe_shim("${EXE_SHIM_X86}" gcc)
add_custom_target(exe_shim_x86 DEPENDS "${EXE_SHIM_X86}")

make_blob_header("${EXE_SHIM_BLOB_X86_H}" "${EXE_SHIM_X86}" "exe_shim_blob" "${EXE_SHIM_X86}")
add_custom_target(exe_shim_blob_h DEPENDS "${EXE_SHIM_BLOB_X86_H}")

build_stub("${STUB_X86}" gcc strip "${AUDIT_BLOB_X86_H}" "${EXE_SHIM_BLOB_X86_H}")
add_custom_target(stub ALL DEPENDS "${STUB_X86}")

# ═══════════════════════════════════════════════════════════════════════
#  ARM64 targets (only when cross-compiler is present)
# ═══════════════════════════════════════════════════════════════════════

if(AARCH64_GCC)
    set(STUB_ARM64       "${CMAKE_BINARY_DIR}/stub_aarch64")

    set(AUDIT_ARM64        "${CMAKE_BINARY_DIR}/audit_shim_aarch64.so")
    set(AUDIT_BLOB_ARM64_H "${CMAKE_BINARY_DIR}/audit_shim_blob_aarch64.h")

    set(EXE_SHIM_ARM64        "${CMAKE_BINARY_DIR}/exe_shim_aarch64.so")
    set(EXE_SHIM_BLOB_ARM64_H "${CMAKE_BINARY_DIR}/exe_shim_blob_aarch64.h")

    compile_audit_shim("${AUDIT_ARM64}" "${AARCH64_GCC}")
    add_custom_target(audit_shim_aarch64 DEPENDS "${AUDIT_ARM64}")

    make_blob_header("${AUDIT_BLOB_ARM64_H}" "${AUDIT_ARM64}" "audit_shim_blob" "${AUDIT_ARM64}")
    add_custom_target(audit_shim_blob_aarch64_h DEPENDS "${AUDIT_BLOB_ARM64_H}")

    compile_exe_shim("${EXE_SHIM_ARM64}" "${AARCH64_GCC}")
    add_custom_target(exe_shim_aarch64 DEPENDS "${EXE_SHIM_ARM64}")

    make_blob_header("${EXE_SHIM_BLOB_ARM64_H}" "${EXE_SHIM_ARM64}" "exe_shim_blob" "${EXE_SHIM_ARM64}")
    add_custom_target(exe_shim_blob_aarch64_h DEPENDS "${EXE_SHIM_BLOB_ARM64_H}")

    build_stub("${STUB_ARM64}" "${AARCH64_GCC}" aarch64-linux-gnu-strip "${AUDIT_BLOB_ARM64_H}" "${EXE_SHIM_BLOB_ARM64_H}")
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
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_BINARY_DIR}/dlopen.key"
            --libs       "${CMAKE_BINARY_DIR}/mylib.so"
            --output-dir "${CMAKE_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/dlopen_main"
            --key    "${CMAKE_BINARY_DIR}/dlopen.key"
            --output "${CMAKE_BINARY_DIR}/dlopen_main.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/dlopen_main.protected"
            "-DLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/encrypted"
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

add_custom_target(test_linked
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_linked ==="
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_BINARY_DIR}/linked.key"
            --libs       "${CMAKE_BINARY_DIR}/liblinkedmath.so"
            --output-dir "${CMAKE_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_BINARY_DIR}/stub"
            --main   "${CMAKE_BINARY_DIR}/linked_main"
            --key    "${CMAKE_BINARY_DIR}/linked.key"
            --output "${CMAKE_BINARY_DIR}/linked_main.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_BINARY_DIR}/linked_main.protected"
            "-DLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/encrypted"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub liblinkedmath linked_main
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "DT_NEEDED LD_AUDIT test"
    USES_TERMINAL
)

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
