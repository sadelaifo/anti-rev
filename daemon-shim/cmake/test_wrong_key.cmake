# Copies a protected binary with its embedded key bytes bit-flipped,
# then runs it — expects AES-GCM decryption to fail.
# Usage: cmake -DBINARY=<path> -P test_wrong_key.cmake

if(NOT BINARY)
    message(FATAL_ERROR "Usage: cmake -DBINARY=<path> -P test_wrong_key.cmake")
endif()

set(WRONGKEY_BINARY "${BINARY}.wrongkey")

execute_process(
    COMMAND python3 -c "
import sys

with open('${BINARY}', 'rb') as f:
    data = bytearray(f.read())

# Trailer is 48 bytes: [bundle_offset:8LE][key:32][magic:8]
# Key occupies data[-40:-8]
if len(data) < 48:
    sys.exit('binary too small')

key_start = len(data) - 40
for i in range(32):
    data[key_start + i] ^= 0xff

with open('${WRONGKEY_BINARY}', 'wb') as f:
    f.write(data)
print('Flipped all 32 embedded key bytes')
"
    RESULT_VARIABLE PY_RET
    OUTPUT_VARIABLE PY_OUT
    ERROR_VARIABLE  PY_ERR
)
if(NOT PY_RET EQUAL 0)
    message(FATAL_ERROR "FAIL test_wrong_key: could not create wrong-key binary: ${PY_ERR}")
endif()
message(STATUS "${PY_OUT}")
execute_process(COMMAND chmod +x "${WRONGKEY_BINARY}")

execute_process(
    COMMAND "${WRONGKEY_BINARY}"
    RESULT_VARIABLE RET
    OUTPUT_VARIABLE OUT
    ERROR_VARIABLE  ERR
)
file(REMOVE "${WRONGKEY_BINARY}")

if(RET EQUAL 0)
    message(FATAL_ERROR "FAIL test_wrong_key: binary exited 0 with wrong key (expected non-zero)")
else()
    message(STATUS "PASS test_wrong_key: binary exited ${RET} with wrong key")
    message(STATUS "  stderr: ${ERR}")
endif()
