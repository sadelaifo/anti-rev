# Pre-test cleanup — SIGTERM any antirev daemon launched from a binary
# whose argv[0] contains TEST_DIR, then briefly wait so the daemon
# finishes its shutdown sequence and releases its binary file before
# the next protect-daemon step tries to overwrite it.
#
# Usage: cmake -DTEST_DIR=<path> -P cleanup_daemons.cmake
#
# Without this, test reruns hit:
#   OSError: [Errno 26] Text file busy: '.../.antirev-libd'

if(NOT TEST_DIR)
    return()
endif()

execute_process(
    COMMAND pkill -TERM -f "${TEST_DIR}.*antirev-libd"
    RESULT_VARIABLE _PKILL
    OUTPUT_QUIET ERROR_QUIET
)
# pkill: 0 = killed something, 1 = no matches.  Only sleep when we
# actually killed — saves the no-op cost on every pristine run.
if(_PKILL EQUAL 0)
    execute_process(COMMAND sleep 0.2)
endif()
