# Runs every test target via cmake --build and collects PASS/FAIL results.
# Usage: cmake -DBUILD_DIR=<path> -DSRC_DIR=<path> -P run_all_tests.cmake

if(NOT BUILD_DIR OR NOT SRC_DIR)
    message(FATAL_ERROR "Usage: cmake -DBUILD_DIR=<path> -DSRC_DIR=<path> -P run_all_tests.cmake")
endif()

set(TESTS
    run_test              # hello smoke test
    test_dlopen           # dlopen protected .so
    test_multi_so         # two protected .so files
    test_linked           # DT_NEEDED library via LD_AUDIT
    test_fork_exec        # fork+exec child inherits audit shim
    test_proc_self_exe    # /proc/self/exe returns real path (readlink)
    test_realpath         # realpath/canonicalize_file_name on /proc/self/exe
    test_multi_process    # full chain: PM -> gRPC daemon -> work process
    test_getauxval        # getauxval(AT_EXECFN) returns real path
    test_comm_name        # /proc/self/comm restored to original name
    test_self_read        # open() on protected binary -> decrypted memfd
    test_daemon_fdclose   # close all fds -> KEY_HEX fallback works
    test_concurrent_dlopen # thread-safe cache under concurrent dlopen
    test_wrong_key        # wrong key -> clean failure
    test_tamper           # bit-flipped ciphertext -> clean failure
)

set(PASS_COUNT 0)
set(FAIL_COUNT 0)
set(RESULTS "")

foreach(T ${TESTS})
    message(STATUS "")
    message(STATUS "────── ${T} ──────")
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build "${BUILD_DIR}" --target "${T}"
        RESULT_VARIABLE RET
        WORKING_DIRECTORY "${SRC_DIR}"
    )
    if(RET EQUAL 0)
        math(EXPR PASS_COUNT "${PASS_COUNT} + 1")
        list(APPEND RESULTS "  PASS  ${T}")
    else()
        math(EXPR FAIL_COUNT "${FAIL_COUNT} + 1")
        list(APPEND RESULTS "  FAIL  ${T}")
    endif()
endforeach()

message(STATUS "")
message(STATUS "══════════════════════════════════════")
message(STATUS "  Test Results")
message(STATUS "══════════════════════════════════════")
foreach(R ${RESULTS})
    message(STATUS "${R}")
endforeach()
message(STATUS "──────────────────────────────────────")
message(STATUS "  Passed: ${PASS_COUNT}   Failed: ${FAIL_COUNT}")
message(STATUS "══════════════════════════════════════")

if(FAIL_COUNT GREATER 0)
    message(FATAL_ERROR "${FAIL_COUNT} test(s) failed.")
endif()
