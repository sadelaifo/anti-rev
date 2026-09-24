# Copies a protected binary, flips a byte deep in the ciphertext,
# then runs it — expects GCM tag verification to fail.
# Key is embedded in the binary — no ANTIREV_KEY env var needed.
# Usage: cmake -DBINARY=<path> [-DQEMU_LD_PREFIX=<path>] -P test_tamper.cmake

if(NOT BINARY)
    message(FATAL_ERROR "Usage: cmake -DBINARY=<path> -P test_tamper.cmake")
endif()

set(TAMPERED "${BINARY}.tampered")

# Use Python to flip a byte 1 KB into the bundle (safely inside the ciphertext)
execute_process(
    COMMAND python3 -c "
import struct, sys

with open('${BINARY}', 'rb') as f:
    data = bytearray(f.read())

# Trailer is 48 bytes: [bundle_offset:8LE][key:32][magic:8]
bundle_off = struct.unpack_from('<Q', data, len(data) - 48)[0]

# Flip a byte 1024 bytes into the bundle (past the file-entry header, in ciphertext)
target = bundle_off + 1024
if target >= len(data) - 48:
    sys.exit('binary too small to tamper safely')

data[target] ^= 0xff
with open('${TAMPERED}', 'wb') as f:
    f.write(data)
print(f'Flipped byte at offset {target} (0x{data[target] ^ 0xff:02x} -> 0x{data[target]:02x})')
"
    RESULT_VARIABLE PY_RET
    OUTPUT_VARIABLE PY_OUT
    ERROR_VARIABLE  PY_ERR
)
if(NOT PY_RET EQUAL 0)
    message(FATAL_ERROR "FAIL test_tamper: could not create tampered binary: ${PY_ERR}")
endif()
message(STATUS "${PY_OUT}")
execute_process(COMMAND chmod +x "${TAMPERED}")

if(DEFINED QEMU_LD_PREFIX)
    set(RUN_CMD ${CMAKE_COMMAND} -E env "QEMU_LD_PREFIX=${QEMU_LD_PREFIX}" "${TAMPERED}")
else()
    set(RUN_CMD "${TAMPERED}")
endif()

# Run tampered binary with embedded (correct) key — GCM tag must reject it
execute_process(
    COMMAND ${RUN_CMD}
    RESULT_VARIABLE RET
    ERROR_VARIABLE  ERR
)
file(REMOVE "${TAMPERED}")

if(RET EQUAL 0)
    message(FATAL_ERROR "FAIL test_tamper: tampered binary exited 0 (expected non-zero)")
else()
    message(STATUS "PASS test_tamper: tampered binary rejected (exit ${RET})")
    message(STATUS "  stderr: ${ERR}")
endif()
