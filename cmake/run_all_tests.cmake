# Runs every test target via cmake --build and collects PASS/FAIL results.
# Usage: cmake -DBUILD_DIR=<path> -DSRC_DIR=<path> -P run_all_tests.cmake

if(NOT BUILD_DIR OR NOT SRC_DIR)
    message(FATAL_ERROR "Usage: cmake -DBUILD_DIR=<path> -DSRC_DIR=<path> -P run_all_tests.cmake")
endif()

# Tests that work with exe-only and bundled-lib protection
set(TESTS
    run_test              # hello smoke test
    test_preload_memfd    # LD_PRELOAD memfd DT_NEEDED smoke test
    test_plain_so         # encrypted exe + plain (unencrypted) .so
    test_linked           # DT_NEEDED .so via bundled LD_PRELOAD memfd
    test_proc_self_exe    # /proc/self/exe returns real path (readlink)
    test_realpath         # realpath/canonicalize_file_name on /proc/self/exe
    test_path_stress      # comprehensive path resolution test
    test_dlopen           # dlopen bundled .so by soname
    test_fork_same_lib    # fork+exec child inherits same lib via LD_PRELOAD
    test_fork_diff_lib    # parent and child use different libs independently
    test_script_multi_bin # script invokes A and B with shared + unique libs
    test_wrong_key        # wrong key -> clean failure
    test_tamper           # bit-flipped ciphertext -> clean failure
)

# Tests disabled — need further work:
#   test_multi_so, test_fork_exec,
#   test_multi_process, test_daemon_fdclose, test_concurrent_dlopen,
#   test_plain_exe_enc_so
# Tests disabled — source files not on this branch (exist on fix/deep-identity-shim):
#   test_getauxval, test_comm_name, test_self_read

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
