# Invoked by cmake test targets:
#   cmake -DBINARY=<path> [-DQEMU_LD_PREFIX=<path>] -P run_test.cmake
# Key is embedded in the binary — no ANTIREV_KEY env var needed.

if(NOT BINARY)
    message(FATAL_ERROR "Usage: cmake -DBINARY=<path> -P run_test.cmake")
endif()

set(ENV_ARGS "")
if(DEFINED QEMU_LD_PREFIX)
    list(APPEND ENV_ARGS "QEMU_LD_PREFIX=${QEMU_LD_PREFIX}")
endif()
if(DEFINED LD_LIBRARY_PATH)
    list(APPEND ENV_ARGS "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}")
endif()

if(ENV_ARGS)
    set(RUN_CMD ${CMAKE_COMMAND} -E env ${ENV_ARGS} "${BINARY}" test_arg)
else()
    set(RUN_CMD "${BINARY}" test_arg)
endif()

execute_process(
    COMMAND ${RUN_CMD}
    RESULT_VARIABLE RET
)
message(STATUS "Exit code: ${RET}")
