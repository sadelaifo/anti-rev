# Invoked by cmake test targets:
#   cmake -DBINARY=<path> [-DQEMU_LD_PREFIX=<path>] -P run_test.cmake
# Key is embedded in the binary — no ANTIREV_KEY env var needed.

if(NOT BINARY)
    message(FATAL_ERROR "Usage: cmake -DBINARY=<path> -P run_test.cmake")
endif()

if(DEFINED QEMU_LD_PREFIX)
    set(RUN_CMD ${CMAKE_COMMAND} -E env "QEMU_LD_PREFIX=${QEMU_LD_PREFIX}" "${BINARY}" test_arg)
else()
    set(RUN_CMD "${BINARY}" test_arg)
endif()

execute_process(
    COMMAND ${RUN_CMD}
    RESULT_VARIABLE RET
)
message(STATUS "Exit code: ${RET}")
