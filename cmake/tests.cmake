# ═══════════════════════════════════════════════════════════════════════
#  cmake/tests.cmake — test binaries and end-to-end test targets
# ═══════════════════════════════════════════════════════════════════════
# Included from the top-level CMakeLists.txt via include() (NOT
# add_subdirectory), so it runs in the top-level directory scope:
# CMAKE_CURRENT_SOURCE_DIR / CMAKE_CURRENT_BINARY_DIR, the X86_GCC /
# AARCH64_GCC compiler aliases, and the obfstr/blob helper functions are
# all visible here.
#
# ═══════════════════════════════════════════════════════════════════════
#  Test binaries
# ═══════════════════════════════════════════════════════════════════════

if(X86_GCC)
    add_executable(hello tests/hello/main.c)
    target_compile_options(hello PRIVATE -O2)
endif()

if(AARCH64_GCC)
    add_custom_command(
        OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/hello_aarch64"
        COMMAND "${AARCH64_GCC}" -O2
                -o "${CMAKE_CURRENT_BINARY_DIR}/hello_aarch64"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/hello/main.c"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/hello/main.c"
        COMMENT "Building hello_aarch64 test binary"
    )
    add_custom_target(hello_aarch64 ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/hello_aarch64")
endif()

# ── obfstr smoke test (codegen pipeline + runtime decoder) ─────────────
# Exercises tools/obfstr_gen.py end-to-end:
#   1. generate the rewritten main.c into ${BUILD}/obf/test_obfstr_main.c
#   2. compile that against stub/obfstr.h
#   3. run the binary; tests/obfstr/run_test.sh additionally `strings`-
#      scans the binary to confirm no cleartext marker survived.
# Picks any available native compiler — this test is arch-agnostic.
if(X86_GCC OR AARCH64_GCC)
    set(_OBFSTR_TEST_CC "${X86_GCC}")
    if(NOT _OBFSTR_TEST_CC)
        set(_OBFSTR_TEST_CC "${AARCH64_GCC}")
    endif()

    add_custom_command(
        OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/obf/test_obfstr_main.c"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/obf"
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tools/obfstr_gen.py"
                --out-dir "${CMAKE_CURRENT_BINARY_DIR}/obf"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/obfstr/main.c"
        # Rename the codegen output to a unique name so it doesn't
        # collide with other transformed main.c's down the line.
        COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_CURRENT_BINARY_DIR}/obf/main.c"
                "${CMAKE_CURRENT_BINARY_DIR}/obf/test_obfstr_main.c"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/obfstr/main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/obfstr_gen.py"
        COMMENT "Codegen-rewriting tests/obfstr/main.c"
    )

    add_custom_command(
        OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/test_obfstr_bin"
        COMMAND "${_OBFSTR_TEST_CC}" -O2 -Wall -Wextra
                -I "${CMAKE_CURRENT_SOURCE_DIR}/stub"
                -o "${CMAKE_CURRENT_BINARY_DIR}/test_obfstr_bin"
                "${CMAKE_CURRENT_BINARY_DIR}/obf/test_obfstr_main.c"
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/obf/test_obfstr_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/stub/obfstr.h"
        COMMENT "Building test_obfstr_bin (with codegen-obfuscated literals)"
    )
    add_custom_target(test_obfstr_bin ALL
                      DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/test_obfstr_bin")

    add_custom_target(test_obfstr
        COMMAND ${CMAKE_COMMAND} -E echo "=== obfstr codegen + runtime test ==="
        COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/obfstr/run_test.sh"
                     "${CMAKE_CURRENT_BINARY_DIR}"
        DEPENDS test_obfstr_bin
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "Running obfstr smoke test"
        USES_TERMINAL
    )
else()
    add_custom_target(test_obfstr
        COMMAND ${CMAKE_COMMAND} -E echo
                "[test_obfstr] no native compiler detected — skipped"
    )
endif()

# ── keysplit version-field parser test ────────────────────────────────
# Unit-tests ksv_parse (stub/keysplit_version.h) — the runtime extraction of
# the keysplit "version" key-component from the version script's stdout — plus
# the Python mirror (protect.parse_version_field).  Arch-agnostic, no daemon,
# no root: just compiles + runs a tiny C harness and a Python checker.
if(X86_GCC OR AARCH64_GCC)
    set(_KSV_TEST_CC "${X86_GCC}")
    if(NOT _KSV_TEST_CC)
        set(_KSV_TEST_CC "${AARCH64_GCC}")
    endif()

    add_custom_command(
        OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/test_keysplit_version_bin"
        COMMAND "${_KSV_TEST_CC}" -O2 -Wall -Wextra
                -I "${CMAKE_CURRENT_SOURCE_DIR}/stub"
                -o "${CMAKE_CURRENT_BINARY_DIR}/test_keysplit_version_bin"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/keysplit_version/test_parse.c"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/keysplit_version/test_parse.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/stub/keysplit_version.h"
        COMMENT "Building test_keysplit_version_bin"
    )
    add_custom_target(test_keysplit_version_bin ALL
                      DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/test_keysplit_version_bin")

    add_custom_target(test_keysplit_version
        COMMAND ${CMAKE_COMMAND} -E echo "=== keysplit version-field parser test ==="
        COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_keysplit_version_bin"
        DEPENDS test_keysplit_version_bin
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "Running keysplit version-field parser test (C ksv_parse)"
        USES_TERMINAL
    )
else()
    add_custom_target(test_keysplit_version
        COMMAND ${CMAKE_COMMAND} -E echo
                "[test_keysplit_version] no native compiler — skipped"
    )
endif()

# ── dependency-free python-lib replacements (miniyaml + libcrypto GCM) ─
# Verifies the two pip-dependency removals in the packer: miniyaml (replaces
# PyYAML) and the ctypes->libcrypto AES-256-GCM (replaces the `cryptography`
# package).  Pure Python; the GCM half checks NIST known-answer vectors against
# system libcrypto (OpenSSL), present on the build host.
add_custom_target(test_pythonlib
    COMMAND ${CMAKE_COMMAND} -E echo "=== python-lib replacements (miniyaml + GCM KAT) ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/pythonlib/test_miniyaml.py"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/pythonlib/test_gcm.py"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Running python-lib replacement tests (miniyaml + GCM)"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  End-to-end tests
# ═══════════════════════════════════════════════════════════════════════

if(X86_GCC)
    add_custom_target(run_test
        COMMAND ${CMAKE_COMMAND} -E echo "=== x86-64 test ==="
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
                --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
                --main   "$<TARGET_FILE:hello>"
                --key    "${CMAKE_CURRENT_BINARY_DIR}/test.key"
                --output "${CMAKE_CURRENT_BINARY_DIR}/hello.protected"
        COMMAND ${CMAKE_COMMAND}
                "-DBINARY=${CMAKE_CURRENT_BINARY_DIR}/hello.protected"
                "-DEXPECTED_EXIT=42"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test.cmake"
        DEPENDS stub hello
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "x86-64 end-to-end test"
        USES_TERMINAL
    )
endif()

if(AARCH64_GCC)
    add_custom_target(run_test_aarch64
        COMMAND ${CMAKE_COMMAND} -E echo "=== ARM64 test via QEMU binfmt ==="
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
                --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub_aarch64"
                --main   "${CMAKE_CURRENT_BINARY_DIR}/hello_aarch64"
                --key    "${CMAKE_CURRENT_BINARY_DIR}/test_aarch64.key"
                --output "${CMAKE_CURRENT_BINARY_DIR}/hello_aarch64.protected"
        COMMAND ${CMAKE_COMMAND}
                "-DBINARY=${CMAKE_CURRENT_BINARY_DIR}/hello_aarch64.protected"
                "-DQEMU_LD_PREFIX=/usr/aarch64-linux-gnu"
                "-DEXPECTED_EXIT=42"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test.cmake"
        DEPENDS stub_aarch64 hello_aarch64
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "ARM64 end-to-end test via QEMU binfmt"
        USES_TERMINAL
    )
endif()

# ═══════════════════════════════════════════════════════════════════════
#  Everything below is x86-64 specific: the tests hard-code `gcc` as
#  compiler and depend on the `stub` target (x86-64). Skip on hosts
#  without an x86-64 compiler.
# ═══════════════════════════════════════════════════════════════════════
if(X86_GCC)

# ═══════════════════════════════════════════════════════════════════════
#  Helper: compile a shared library with a given compiler
# ═══════════════════════════════════════════════════════════════════════
function(compile_lib OUTPUT COMPILER SOURCE)
    get_filename_component(_soname "${OUTPUT}" NAME)
    add_custom_command(
        OUTPUT  "${OUTPUT}"
        COMMAND "${COMPILER}" -shared -fPIC -O2
                -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
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
                -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
                -o "${OUTPUT}" "${SOURCE}" -ldl
        DEPENDS "${SOURCE}"
        COMMENT "Building test binary: ${OUTPUT}"
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  Helpers: build-artifact + phony-target in one call
# ═══════════════════════════════════════════════════════════════════════
# Each collapses the add_custom_command + add_custom_target pair that was
# repeated for nearly every test artifact.  TARGET is the phony build
# target other tests depend on; OUT is the produced filename under the
# build dir; SRC is a path relative to the source tree.  The generated
# build commands are identical to the old hand-written pairs.

# Shared lib (-shared -fPIC -O2, soname = OUT, -I tests on include path).
function(arev_lib TARGET OUT SRC)
    set(_o "${CMAKE_CURRENT_BINARY_DIR}/${OUT}")
    compile_lib("${_o}" gcc "${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
    add_custom_target(${TARGET} DEPENDS "${_o}")
endfunction()

# Test executable (-O2, -I tests, links -ldl).
function(arev_bin TARGET OUT SRC)
    set(_o "${CMAKE_CURRENT_BINARY_DIR}/${OUT}")
    compile_test_bin("${_o}" gcc "${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
    add_custom_target(${TARGET} DEPENDS "${_o}")
endfunction()

# Plain executable (-O2 only — no -I tests, no -ldl).  Used by the
# identity / path-interception test programs, which have no extra deps.
function(arev_plain_bin TARGET OUT SRC)
    set(_o "${CMAKE_CURRENT_BINARY_DIR}/${OUT}")
    add_custom_command(
        OUTPUT  "${_o}"
        COMMAND gcc -O2 -o "${_o}" "${CMAKE_CURRENT_SOURCE_DIR}/${SRC}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${SRC}"
        COMMENT "Building test binary: ${OUT}"
    )
    add_custom_target(${TARGET} DEPENDS "${_o}")
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  Helper: protect a single exe with its own key and run it
# ═══════════════════════════════════════════════════════════════════════
# The exe checks its own behaviour and returns an exit code.  Used by the
# identity / path-interception tests (no daemon, no libs).
#   arev_protect_run(test_name exe_basename key_basename "comment")
# Depends on `stub` and the exe build target (named == exe_basename).
function(arev_protect_run TEST EXE KEY COMMENT_STR)
    add_custom_target(${TEST}
        COMMAND ${CMAKE_COMMAND} -E echo "=== ${TEST} ==="
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
                --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
                --main   "${CMAKE_CURRENT_BINARY_DIR}/${EXE}"
                --key    "${CMAKE_CURRENT_BINARY_DIR}/${KEY}.key"
                --output "${CMAKE_CURRENT_BINARY_DIR}/${EXE}.protected"
        COMMAND "${CMAKE_CURRENT_BINARY_DIR}/${EXE}.protected"
        DEPENDS stub ${EXE}
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "${COMMENT_STR}"
        USES_TERMINAL
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  Helper: daemon-mode test (encrypt-lib + lightweight protect-daemon
#  + protect-exe --daemon-libs). Libs are encrypted as standalone files
#  in the test dir; the daemon scans that dir at startup.
#  Usage: daemon_test(test_name client_bin "comment" lib1.so [lib2.so])
#         add_dependencies(test_name stub mylib client_target ...)
# ═══════════════════════════════════════════════════════════════════════
function(daemon_test TEST_NAME CLIENT_BIN COMMENT_STR)
    set(_TD "${CMAKE_CURRENT_BINARY_DIR}/daemon_${TEST_NAME}")
    add_custom_target(${TEST_NAME}
        COMMAND ${CMAKE_COMMAND} -E echo "=== ${TEST_NAME} ==="
        # Pre-run cleanup: if a previous run left a daemon alive, SIGTERM
        # it before the protect-daemon step tries to overwrite the binary.
        COMMAND ${CMAKE_COMMAND} -DTEST_DIR=${_TD}
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cleanup_daemons.cmake"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD}"
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
                --key        "${_TD}/test.key"
                --libs       ${ARGN}
                --output-dir "${_TD}"
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
                --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
                --key    "${_TD}/test.key"
                --output "${_TD}/lrxd"
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
                --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
                --main   "${CLIENT_BIN}"
                --key    "${_TD}/test.key"
                --daemon-libs
                --output "${_TD}/test.protected"
        COMMAND ${CMAKE_COMMAND}
                "-DBINARY=${_TD}/test.protected"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test.cmake"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "${COMMENT_STR}"
        USES_TERMINAL
    )
endfunction()

# ═══════════════════════════════════════════════════════════════════════
#  Shared test libraries and binaries
# ═══════════════════════════════════════════════════════════════════════

arev_lib(mylib mylib.so tests/dlopen/mylib.c)

arev_bin(dlopen_main dlopen_main tests/dlopen/main.c)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen — main binary dlopen's a protected .so via the shim
# ═══════════════════════════════════════════════════════════════════════

daemon_test(test_dlopen "${CMAKE_CURRENT_BINARY_DIR}/dlopen_main"
    "dlopen test (.so via daemon)"
    "${CMAKE_CURRENT_BINARY_DIR}/mylib.so")
add_dependencies(test_dlopen stub mylib dlopen_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_edgecases — paths, flags, reopen, fallthrough
# ═══════════════════════════════════════════════════════════════════════

arev_bin(dlopen_edgecases dlopen_edgecases tests/dlopen_edgecases/main.c)

daemon_test(test_dlopen_edgecases "${CMAKE_CURRENT_BINARY_DIR}/dlopen_edgecases"
    "dlopen edge-case tests (paths, flags, reopen, fallthrough)"
    "${CMAKE_CURRENT_BINARY_DIR}/mylib.so")
add_dependencies(test_dlopen_edgecases stub mylib dlopen_edgecases)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_nested — dlopen from within a protected shared library
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libcallee libcallee.so tests/dlopen_nested/libcallee.c)

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libcaller.so"
    COMMAND gcc -shared -fPIC -O2
            -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            -Wl,-soname,libcaller.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libcaller.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_nested/libcaller.c"
            -ldl
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_nested/libcaller.c"
    COMMENT "Building libcaller.so (nested dlopen test)"
)
add_custom_target(libcaller DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libcaller.so")

arev_bin(dlopen_nested_bin dlopen_nested tests/dlopen_nested/main.c)

daemon_test(test_dlopen_nested "${CMAKE_CURRENT_BINARY_DIR}/dlopen_nested"
    "nested dlopen test (caller->callee chain via shim)"
    "${CMAKE_CURRENT_BINARY_DIR}/libcaller.so" "${CMAKE_CURRENT_BINARY_DIR}/libcallee.so")
add_dependencies(test_dlopen_nested stub libcallee libcaller dlopen_nested_bin)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_transitive — encrypted lib behind unencrypted intermediary
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libinner libinner.so tests/dlopen_transitive/libinner.c)

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libmiddle.so"
    COMMAND gcc -shared -fPIC -O2
            -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            -Wl,-soname,libmiddle.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libmiddle.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_transitive/libmiddle.c"
            -ldl
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_transitive/libmiddle.c"
    COMMENT "Building libmiddle.so (transitive test)"
)
add_custom_target(libmiddle DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libmiddle.so")

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libbridge.so"
    COMMAND gcc -shared -fPIC -O2
            -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            -Wl,-soname,libbridge.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libbridge.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_transitive/libbridge.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -lmiddle -Wl,--no-as-needed
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_transitive/libbridge.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libmiddle.so"
    COMMENT "Building libbridge.so (unencrypted intermediary)"
)
add_custom_target(libbridge DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libbridge.so")

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/dlopen_transitive"
    COMMAND gcc -O2
            -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            -o "${CMAKE_CURRENT_BINARY_DIR}/dlopen_transitive"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_transitive/main.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -lbridge -Wl,--no-as-needed
            -Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_transitive/main.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libbridge.so"
    COMMENT "Building dlopen_transitive test binary"
)
add_custom_target(dlopen_transitive_bin DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/dlopen_transitive")

set(_TD_TRANS "${CMAKE_CURRENT_BINARY_DIR}/daemon_test_dlopen_transitive")
add_custom_target(test_dlopen_transitive
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_dlopen_transitive ==="
    COMMAND ${CMAKE_COMMAND} -DTEST_DIR=${_TD_TRANS}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cleanup_daemons.cmake"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_TRANS}"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${_TD_TRANS}/test.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/libmiddle.so"
                         "${CMAKE_CURRENT_BINARY_DIR}/libinner.so"
            --output-dir "${_TD_TRANS}"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --key    "${_TD_TRANS}/test.key"
            --output "${_TD_TRANS}/lrxd"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/dlopen_transitive"
            --key    "${_TD_TRANS}/test.key"
            --daemon-libs
            --output "${_TD_TRANS}/test.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${_TD_TRANS}/test.protected"
            "-DLD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub libinner libmiddle libbridge dlopen_transitive_bin
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "transitive DT_NEEDED through unencrypted intermediary"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_dt_needed — exe dlopen's libfoo, libfoo DT_NEEDs libbar,
#  ALL encrypted.  Tests LD_LIBRARY_PATH symlink resolution for
#  DT_NEEDED deps of dlopen'd libs.
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libbar libbar.so tests/dlopen_dt_needed/libbar.c)

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libfoo.so"
    COMMAND gcc -shared -fPIC -O2
            -Wl,-soname,libfoo.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libfoo.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_dt_needed/libfoo.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -lbar -Wl,--no-as-needed
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_dt_needed/libfoo.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libbar.so"
    COMMENT "Building libfoo.so (dlopen_dt_needed test)"
)
add_custom_target(libfoo DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libfoo.so")

arev_bin(dlopen_dt_needed_bin dlopen_dt_needed tests/dlopen_dt_needed/main.c)

set(_TD_DTN "${CMAKE_CURRENT_BINARY_DIR}/daemon_test_dlopen_dt_needed")
add_custom_target(test_dlopen_dt_needed
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_dlopen_dt_needed ==="
    COMMAND ${CMAKE_COMMAND} -DTEST_DIR=${_TD_DTN}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cleanup_daemons.cmake"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_DTN}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_DTN}/enc_disk"
    # Encrypted copies on disk at enc_disk/; the daemon recursively scans
    # _TD_DTN and picks them up, and the runtime sets LD_LIBRARY_PATH to
    # enc_disk so the linker also finds them (and fails with "invalid ELF
    # header" rather than "not found" — which is what the test checks).
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key    "${_TD_DTN}/test.key"
            --libs   "${CMAKE_CURRENT_BINARY_DIR}/libfoo.so"
                     "${CMAKE_CURRENT_BINARY_DIR}/libbar.so"
            --output-dir "${_TD_DTN}/enc_disk"
    # Lightweight daemon
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --key    "${_TD_DTN}/test.key"
            --output "${_TD_DTN}/lrxd"
    # Protect exe
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/dlopen_dt_needed"
            --key    "${_TD_DTN}/test.key"
            --daemon-libs
            --output "${_TD_DTN}/test.protected"
    # Run with LD_LIBRARY_PATH pointing to encrypted copies on disk
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${_TD_DTN}/test.protected"
            "-DLD_LIBRARY_PATH=${_TD_DTN}/enc_disk"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub libbar libfoo dlopen_dt_needed_bin
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "dlopen DT_NEEDED: exe->dlopen(libfoo)->DT_NEEDED(libbar), all encrypted"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_reload — verify that plugin libs unload on dlclose and
#  re-run their constructors on the next dlopen.  Guards the lazy-fetch
#  "don't pin the root lib" rule — a regression would cause the
#  libprotobuf "File already exists in database" class of failures when
#  business software cycles plugins that share static state.
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libreload libreload.so tests/dlopen_reload/libreload.c)

arev_bin(dlopen_reload_bin dlopen_reload tests/dlopen_reload/main.c)

set(_TD_RELOAD "${CMAKE_CURRENT_BINARY_DIR}/daemon_test_dlopen_reload")
add_custom_target(test_dlopen_reload
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_dlopen_reload ==="
    COMMAND ${CMAKE_COMMAND} -DTEST_DIR=${_TD_RELOAD}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cleanup_daemons.cmake"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_RELOAD}"
    COMMAND ${CMAKE_COMMAND} -E remove -f /tmp/test_dlopen_reload.log
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${_TD_RELOAD}/test.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/libreload.so"
            --output-dir "${_TD_RELOAD}"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --key    "${_TD_RELOAD}/test.key"
            --output "${_TD_RELOAD}/lrxd"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/dlopen_reload"
            --key    "${_TD_RELOAD}/test.key"
            --daemon-libs
            --output "${_TD_RELOAD}/test.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${_TD_RELOAD}/test.protected"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub libreload dlopen_reload_bin
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "dlopen reload: dlopen/dlclose/dlopen must re-run ctor"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlopen_interpose — dlopen_shim must preload closure deps with
#  RTLD_GLOBAL so DSOs carrying overlapping static initializers (the
#  libprotobuf "File already exists in database" scenario) dedup via
#  symbol interposition the way the plaintext loader does.
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libregistrar libregistrar.so tests/dlopen_interpose/libregistrar.c)

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup1.so"
    COMMAND gcc -shared -fPIC -O2
            -Wl,-soname,libinterpose_dup1.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup1.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_interpose/libdup1.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -lregistrar -Wl,--no-as-needed
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_interpose/libdup1.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libregistrar.so"
    COMMENT "Building libinterpose_dup1.so"
)
add_custom_target(libinterpose_dup1
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup1.so")

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup2.so"
    COMMAND gcc -shared -fPIC -O2
            -Wl,-soname,libinterpose_dup2.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup2.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_interpose/libdup2.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -lregistrar -Wl,--no-as-needed
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_interpose/libdup2.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libregistrar.so"
    COMMENT "Building libinterpose_dup2.so"
)
add_custom_target(libinterpose_dup2
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup2.so")

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libroot.so"
    COMMAND gcc -shared -fPIC -O2
            -Wl,-soname,libroot.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libroot.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_interpose/libroot.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}"
            -linterpose_dup1 -linterpose_dup2
            -Wl,--no-as-needed
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dlopen_interpose/libroot.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup1.so"
            "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup2.so"
    COMMENT "Building libroot.so (dlopen_interpose test)"
)
add_custom_target(libroot_interpose DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libroot.so")

arev_bin(dlopen_interpose_bin dlopen_interpose tests/dlopen_interpose/main.c)

# Structurally a plain daemon_test (encrypt libs → daemon → protected exe,
# no LD_LIBRARY_PATH on run), so it uses the shared helper.
daemon_test(test_dlopen_interpose "${CMAKE_CURRENT_BINARY_DIR}/dlopen_interpose"
    "dlopen interpose: RTLD_GLOBAL preload dedups overlapping static state"
    "${CMAKE_CURRENT_BINARY_DIR}/libregistrar.so"
    "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup1.so"
    "${CMAKE_CURRENT_BINARY_DIR}/libinterpose_dup2.so"
    "${CMAKE_CURRENT_BINARY_DIR}/libroot.so")
add_dependencies(test_dlopen_interpose stub libregistrar libinterpose_dup1
    libinterpose_dup2 libroot_interpose dlopen_interpose_bin)

# ═══════════════════════════════════════════════════════════════════════
#  test_preload_memfd — smoke test: DT_NEEDED satisfied via LD_PRELOAD
#  from a memfd (no .so on disk, no LD_AUDIT)
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libpretest libpretest.so tests/preload_memfd/libpretest.c)

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/preload_launcher"
    COMMAND gcc -O2
            -o "${CMAKE_CURRENT_BINARY_DIR}/preload_launcher"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/preload_memfd/launcher.c"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/preload_memfd/launcher.c"
    COMMENT "Building preload_launcher"
)
add_custom_target(preload_launcher DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/preload_launcher")

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/preload_main"
    COMMAND gcc -O2
            -o "${CMAKE_CURRENT_BINARY_DIR}/preload_main"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/preload_memfd/main.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -lpretest -Wl,--no-as-needed
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/preload_memfd/main.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libpretest.so"
    COMMENT "Building preload_main"
)
add_custom_target(preload_main DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/preload_main")

add_custom_target(test_preload_memfd
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_preload_memfd ==="
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/preload_launcher"
            "${CMAKE_CURRENT_BINARY_DIR}/libpretest.so"
            "${CMAKE_CURRENT_BINARY_DIR}/preload_main"
    DEPENDS preload_launcher preload_main libpretest
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "LD_PRELOAD memfd DT_NEEDED satisfaction smoke test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_plain_so — encrypted exe dlopen's an unencrypted (plain) .so
# ═══════════════════════════════════════════════════════════════════════

arev_bin(plain_so_main plain_so_main tests/plain_so/main.c)

add_custom_target(test_plain_so
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_plain_so ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/plain_so_main"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/plain_so.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/plain_so_main.protected"
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/plain_so_main.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/mylib.so"
    DEPENDS stub mylib plain_so_main
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "encrypted exe + plain (unencrypted) .so test"
    USES_TERMINAL
)

# (test_plain_exe_enc_so was here — removed along with protect.py run/LD_AUDIT)

# ═══════════════════════════════════════════════════════════════════════
#  test_multi_so — two protected shared libraries loaded via dlopen
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_CURRENT_BINARY_DIR}/libmath.so"
    gcc "${CMAKE_CURRENT_SOURCE_DIR}/tests/multi_so/libmath.c")
compile_lib("${CMAKE_CURRENT_BINARY_DIR}/libstr.so"
    gcc "${CMAKE_CURRENT_SOURCE_DIR}/tests/multi_so/libstr.c")
add_custom_target(multi_libs
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libmath.so" "${CMAKE_CURRENT_BINARY_DIR}/libstr.so")

arev_bin(multi_main multi_main tests/multi_so/main.c)

add_custom_target(test_multi_so
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_multi_so ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_CURRENT_BINARY_DIR}/multi.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/libmath.so"
                         "${CMAKE_CURRENT_BINARY_DIR}/libstr.so"
            --output-dir "${CMAKE_CURRENT_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/multi_main"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/multi.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/multi_main.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_CURRENT_BINARY_DIR}/multi_main.protected"
            "-DLD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/encrypted"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test.cmake"
    DEPENDS stub multi_libs multi_main
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "multi_so test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_linked — DT_NEEDED library served by the daemon (symlink-dir path)
# ═══════════════════════════════════════════════════════════════════════

arev_lib(liblinkedmath liblinkedmath.so tests/linked/liblinkedmath.c)

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/linked_main"
    COMMAND gcc -O2
            -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            -o "${CMAKE_CURRENT_BINARY_DIR}/linked_main"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/linked/main.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -llinkedmath
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/linked/main.c"
            "${CMAKE_CURRENT_BINARY_DIR}/liblinkedmath.so"
    COMMENT "Building test binary: linked_main"
)
add_custom_target(linked_main DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/linked_main")

daemon_test(test_linked "${CMAKE_CURRENT_BINARY_DIR}/linked_main"
    "DT_NEEDED satisfied via daemon-served encrypted .so"
    "${CMAKE_CURRENT_BINARY_DIR}/liblinkedmath.so")
add_dependencies(test_linked stub liblinkedmath linked_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_fd_reduction — exe_shim must close DT_NEEDED memfds after ctor
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/fd_reduction_main"
    COMMAND gcc -O2
            -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            -o "${CMAKE_CURRENT_BINARY_DIR}/fd_reduction_main"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fd_reduction/main.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -llinkedmath
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fd_reduction/main.c"
            "${CMAKE_CURRENT_BINARY_DIR}/liblinkedmath.so"
    COMMENT "Building test binary: fd_reduction_main"
)
add_custom_target(fd_reduction_main DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/fd_reduction_main")

daemon_test(test_fd_reduction "${CMAKE_CURRENT_BINARY_DIR}/fd_reduction_main"
    "DT_NEEDED memfds closed by exe_shim ctor (fd reduction)"
    "${CMAKE_CURRENT_BINARY_DIR}/liblinkedmath.so")
add_dependencies(test_fd_reduction stub liblinkedmath fd_reduction_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_fork_exec — child process spawned via fork()+exec() must be able
#  to dlopen an encrypted .so via the inherited dlopen_shim
# ═══════════════════════════════════════════════════════════════════════

arev_bin(fork_exec_parent fork_exec_parent tests/fork_exec/parent.c)

arev_bin(fork_exec_child fork_exec_child tests/fork_exec/child.c)

add_custom_target(test_fork_exec
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_fork_exec ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_CURRENT_BINARY_DIR}/fork_exec.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/mylib.so"
            --output-dir "${CMAKE_CURRENT_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/fork_exec_parent"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/fork_exec.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/fork_exec_parent.protected"
    COMMAND ${CMAKE_COMMAND} -E env
            "LD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/encrypted"
            "${CMAKE_CURRENT_BINARY_DIR}/fork_exec_parent.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/fork_exec_child"
            "${CMAKE_CURRENT_BINARY_DIR}/encrypted/mylib.so"
    DEPENDS stub mylib fork_exec_parent fork_exec_child
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "fork+exec child inherits audit shim test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_multi_process — full chain: PM → gRPC daemon → work process
#  (fork+exec, encrypted .so, /proc/self/exe, all in one test)
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libwork libwork.so tests/multi_process/libwork.c)

arev_bin(work_process_bin work_process tests/multi_process/work_process.c)

arev_bin(grpc_daemon_sim grpc_daemon_sim tests/multi_process/grpc_daemon.c)

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/pm_sim"
    COMMAND gcc -O2
            -o "${CMAKE_CURRENT_BINARY_DIR}/pm_sim"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/multi_process/pm.c"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/multi_process/pm.c"
    COMMENT "Building test binary: pm_sim"
)
add_custom_target(pm_sim DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/pm_sim")

add_custom_target(test_multi_process
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_multi_process ==="
    # Encrypt the shared library
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_CURRENT_BINARY_DIR}/multi_process.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/libwork.so"
            --output-dir "${CMAKE_CURRENT_BINARY_DIR}/encrypted"
    # Protect all three binaries with the same key
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/work_process"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/multi_process.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/work_process.protected"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/grpc_daemon_sim"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/multi_process.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/grpc_daemon_sim.protected"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/pm_sim"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/multi_process.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/pm_sim.protected"
    # Run the orchestration script
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/multi_process/run_test.sh"
            "${CMAKE_CURRENT_BINARY_DIR}/grpc_daemon_sim.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/pm_sim.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/work_process.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/encrypted/libwork.so"
    DEPENDS stub libwork work_process_bin grpc_daemon_sim pm_sim
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Multi-process chain test: PM -> gRPC daemon -> work process"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_proc_self_exe — readlink("/proc/self/exe") must return the real
#  on-disk path, not a memfd path, after fexecve
# ═══════════════════════════════════════════════════════════════════════

arev_plain_bin(proc_self_exe_test proc_self_exe_test tests/proc_self_exe/main.c)
arev_protect_run(test_proc_self_exe proc_self_exe_test proc_self_exe
    "/proc/self/exe readlink interception test")

# ═══════════════════════════════════════════════════════════════════════
#  test_memfd_name — every decrypted memfd (exe, shim, daemon-served libs)
#  must appear in /proc/self/fd as "memfd:<random-hex> (deleted)" rather
#  than carrying the source artifact's basename.  Without the rename,
#  /proc/<pid>/fd readlinks would identify which encrypted blob each fd
#  holds; with a per-process random hex name they don't.
# ═══════════════════════════════════════════════════════════════════════

arev_plain_bin(memfd_name_test memfd_name_test tests/memfd_name/main.c)
arev_protect_run(test_memfd_name memfd_name_test memfd_name
    "memfd name obfuscation test (per-process random hex name)")

# ═══════════════════════════════════════════════════════════════════════
#  test_ctor_readlink — readlink("/proc/self/exe") called from a C++
#  global static initializer in a DT_NEEDED library (before exe_shim's
#  constructor) must return the real path, not memfd.
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/libctor_readlink.so"
    COMMAND g++ -shared -fPIC -O2
            -Wl,-soname,libctor_readlink.so
            -o "${CMAKE_CURRENT_BINARY_DIR}/libctor_readlink.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/ctor_readlink/libctor_readlink.cpp"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/ctor_readlink/libctor_readlink.cpp"
    COMMENT "Building lib: libctor_readlink.so"
)
add_custom_target(libctor_readlink DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libctor_readlink.so")

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/ctor_readlink_main"
    COMMAND gcc -O2
            -o "${CMAKE_CURRENT_BINARY_DIR}/ctor_readlink_main"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/ctor_readlink/main.c"
            -L "${CMAKE_CURRENT_BINARY_DIR}" -lctor_readlink
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/ctor_readlink/main.c"
            "${CMAKE_CURRENT_BINARY_DIR}/libctor_readlink.so"
    COMMENT "Building test binary: ctor_readlink_main"
)
add_custom_target(ctor_readlink_main DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/ctor_readlink_main")

daemon_test(test_ctor_readlink "${CMAKE_CURRENT_BINARY_DIR}/ctor_readlink_main"
    "C++ ctor readlink before exe_shim constructor"
    "${CMAKE_CURRENT_BINARY_DIR}/libctor_readlink.so")
add_dependencies(test_ctor_readlink stub libctor_readlink ctor_readlink_main)

# ═══════════════════════════════════════════════════════════════════════
#  test_realpath — realpath/canonicalize_file_name on /proc/self/exe
# ═══════════════════════════════════════════════════════════════════════

arev_plain_bin(realpath_test realpath_test tests/realpath/main.c)
arev_protect_run(test_realpath realpath_test realpath
    "realpath/canonicalize_file_name interception test")

# ═══════════════════════════════════════════════════════════════════════
#  test_path_stress — comprehensive path resolution stress test
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/path_stress_test"
    COMMAND gcc -O2
            -o "${CMAKE_CURRENT_BINARY_DIR}/path_stress_test"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/path_stress/main.c"
            -ldl
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/path_stress/main.c"
    COMMENT "Building test binary: path_stress_test"
)
add_custom_target(path_stress_test DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/path_stress_test")

# Without --has-libs (no LD_AUDIT)
add_custom_target(test_path_stress
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_path_stress no_audit ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/path_stress_test"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/path_stress.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/path_stress_test.protected"
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/path_stress_test.protected"
    DEPENDS stub path_stress_test
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "path stress test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_getauxval — getauxval(AT_EXECFN) returns real path, not memfd
# ═══════════════════════════════════════════════════════════════════════

arev_plain_bin(getauxval_test getauxval_test tests/getauxval/main.c)
arev_protect_run(test_getauxval getauxval_test getauxval
    "getauxval(AT_EXECFN) interception test")

# ═══════════════════════════════════════════════════════════════════════
#  test_comm_name — /proc/self/comm restored to original binary name
# ═══════════════════════════════════════════════════════════════════════

arev_plain_bin(comm_name_test comm_name_test tests/comm_name/main.c)
arev_protect_run(test_comm_name comm_name_test comm_name
    "process comm name restoration test")

# ═══════════════════════════════════════════════════════════════════════
#  test_self_read — open() on protected binary redirects to decrypted memfd
# ═══════════════════════════════════════════════════════════════════════

arev_plain_bin(self_read_test self_read_test tests/self_read/main.c)
arev_protect_run(test_self_read self_read_test self_read
    "self-read redirect test")

# ═══════════════════════════════════════════════════════════════════════
#  test_daemon_fdclose — close all fds then dlopen via KEY_HEX fallback
# ═══════════════════════════════════════════════════════════════════════

arev_bin(daemon_fdclose_test daemon_fdclose_test tests/daemon_fdclose/main.c)

add_custom_target(test_daemon_fdclose
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_daemon_fdclose ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_CURRENT_BINARY_DIR}/daemon_fdclose.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/mylib.so"
            --output-dir "${CMAKE_CURRENT_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/daemon_fdclose_test"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/daemon_fdclose.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/daemon_fdclose_test.protected"
    COMMAND ${CMAKE_COMMAND} -E env
            "LD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/encrypted"
            "${CMAKE_CURRENT_BINARY_DIR}/daemon_fdclose_test.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/encrypted/mylib.so"
    DEPENDS stub mylib daemon_fdclose_test
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "daemon fd-close KEY_HEX fallback test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_concurrent_dlopen — thread-safe cache (multiple threads dlopen)
# ═══════════════════════════════════════════════════════════════════════

add_custom_command(
    OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/concurrent_dlopen_test"
    COMMAND gcc -O2
            -I "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            -o "${CMAKE_CURRENT_BINARY_DIR}/concurrent_dlopen_test"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/concurrent_dlopen/main.c"
            -ldl -pthread
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/concurrent_dlopen/main.c"
    COMMENT "Building test binary: concurrent_dlopen_test"
)
add_custom_target(concurrent_dlopen_test DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/concurrent_dlopen_test")

add_custom_target(test_concurrent_dlopen
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_concurrent_dlopen ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${CMAKE_CURRENT_BINARY_DIR}/concurrent.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/mylib.so"
            --output-dir "${CMAKE_CURRENT_BINARY_DIR}/encrypted"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/concurrent_dlopen_test"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/concurrent.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/concurrent_dlopen_test.protected"
    COMMAND ${CMAKE_COMMAND} -E env
            "LD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/encrypted"
            "${CMAKE_CURRENT_BINARY_DIR}/concurrent_dlopen_test.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/encrypted/mylib.so"
    DEPENDS stub mylib concurrent_dlopen_test
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "concurrent dlopen thread-safe cache test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_wrong_key — protected binary must fail cleanly with wrong key
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_wrong_key
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_wrong_key ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "$<TARGET_FILE:hello>"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/wrongkey.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/hello_wrongkey.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_CURRENT_BINARY_DIR}/hello_wrongkey.protected"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_wrong_key.cmake"
    DEPENDS stub hello
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "wrong key negative test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_tamper — bit-flipped ciphertext must fail GCM tag verification
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_tamper
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_tamper ==="
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "$<TARGET_FILE:hello>"
            --key    "${CMAKE_CURRENT_BINARY_DIR}/tamper.key"
            --output "${CMAKE_CURRENT_BINARY_DIR}/hello_tamper.protected"
    COMMAND ${CMAKE_COMMAND}
            "-DBINARY=${CMAKE_CURRENT_BINARY_DIR}/hello_tamper.protected"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_tamper.cmake"
    DEPENDS stub hello
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "tampered ciphertext negative test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_fork_same_lib — child inherits same bundled .so via LD_PRELOAD
# ═══════════════════════════════════════════════════════════════════════

arev_bin(fork_same_parent fork_same_parent tests/fork_same_lib/parent.c)

arev_bin(fork_same_child fork_same_child tests/fork_same_lib/child.c)

set(_TD_FSL "${CMAKE_CURRENT_BINARY_DIR}/daemon_test_fork_same_lib")
add_custom_target(test_fork_same_lib
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_fork_same_lib ==="
    COMMAND ${CMAKE_COMMAND} -DTEST_DIR=${_TD_FSL}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cleanup_daemons.cmake"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_FSL}"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${_TD_FSL}/test.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/mylib.so"
            --output-dir "${_TD_FSL}"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --key    "${_TD_FSL}/test.key"
            --output "${_TD_FSL}/lrxd"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/fork_same_parent"
            --key    "${_TD_FSL}/test.key"
            --daemon-libs
            --output "${_TD_FSL}/parent.protected"
    COMMAND "${_TD_FSL}/parent.protected"
            "${CMAKE_CURRENT_BINARY_DIR}/fork_same_child"
    DEPENDS stub mylib fork_same_parent fork_same_child
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "fork+exec child inherits same lib via daemon"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_fork_diff_lib — parent and child use different libs independently
# ═══════════════════════════════════════════════════════════════════════

arev_lib(libparent libparent.so tests/fork_diff_lib/libparent.c)

arev_lib(libchild libchild.so tests/fork_diff_lib/libchild.c)

arev_bin(fork_diff_parent fork_diff_parent tests/fork_diff_lib/parent.c)

arev_bin(fork_diff_child fork_diff_child tests/fork_diff_lib/child.c)

set(_TD_FDL "${CMAKE_CURRENT_BINARY_DIR}/daemon_test_fork_diff_lib")
add_custom_target(test_fork_diff_lib
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_fork_diff_lib ==="
    COMMAND ${CMAKE_COMMAND} -DTEST_DIR=${_TD_FDL}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cleanup_daemons.cmake"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_FDL}/parent" "${_TD_FDL}/child"
    # Daemon + client for parent (libparent.so)
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${_TD_FDL}/parent/test.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/libparent.so"
            --output-dir "${_TD_FDL}/parent"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --key    "${_TD_FDL}/parent/test.key"
            --output "${_TD_FDL}/parent/lrxd"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/fork_diff_parent"
            --key    "${_TD_FDL}/parent/test.key"
            --daemon-libs
            --output "${_TD_FDL}/parent/parent.protected"
    # Daemon + client for child (libchild.so, different key)
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${_TD_FDL}/child/test.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/libchild.so"
            --output-dir "${_TD_FDL}/child"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --key    "${_TD_FDL}/child/test.key"
            --output "${_TD_FDL}/child/lrxd"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/fork_diff_child"
            --key    "${_TD_FDL}/child/test.key"
            --daemon-libs
            --output "${_TD_FDL}/child/child.protected"
    # Run: parent execs child
    COMMAND "${_TD_FDL}/parent/parent.protected"
            "${_TD_FDL}/child/child.protected"
    DEPENDS stub libparent libchild fork_diff_parent fork_diff_child
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "parent(libparent.so) fork+exec child(libchild.so) via daemon"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_script_multi_bin — script invokes A and B with shared + unique libs
# ═══════════════════════════════════════════════════════════════════════

compile_lib("${CMAKE_CURRENT_BINARY_DIR}/libcommon.so"
    gcc "${CMAKE_CURRENT_SOURCE_DIR}/tests/script_multi_bin/libcommon.c")
compile_lib("${CMAKE_CURRENT_BINARY_DIR}/libA_only.so"
    gcc "${CMAKE_CURRENT_SOURCE_DIR}/tests/script_multi_bin/libA_only.c")
compile_lib("${CMAKE_CURRENT_BINARY_DIR}/libB_only.so"
    gcc "${CMAKE_CURRENT_SOURCE_DIR}/tests/script_multi_bin/libB_only.c")
add_custom_target(script_multi_libs
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libcommon.so"
            "${CMAKE_CURRENT_BINARY_DIR}/libA_only.so"
            "${CMAKE_CURRENT_BINARY_DIR}/libB_only.so")

arev_bin(proc_a proc_a tests/script_multi_bin/proc_a.c)

arev_bin(proc_b proc_b tests/script_multi_bin/proc_b.c)

set(_TD_SMB "${CMAKE_CURRENT_BINARY_DIR}/daemon_test_script_multi_bin")
add_custom_target(test_script_multi_bin
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_script_multi_bin ==="
    COMMAND ${CMAKE_COMMAND} -DTEST_DIR=${_TD_SMB}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cleanup_daemons.cmake"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_TD_SMB}"
    # One daemon serves all libs (same key for both clients)
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" encrypt-lib
            --key        "${_TD_SMB}/test.key"
            --libs       "${CMAKE_CURRENT_BINARY_DIR}/libcommon.so"
                         "${CMAKE_CURRENT_BINARY_DIR}/libA_only.so"
                         "${CMAKE_CURRENT_BINARY_DIR}/libB_only.so"
            --output-dir "${_TD_SMB}"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-daemon
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --key    "${_TD_SMB}/test.key"
            --output "${_TD_SMB}/lrxd"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/proc_a"
            --key    "${_TD_SMB}/test.key"
            --daemon-libs
            --output "${_TD_SMB}/proc_a.protected"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/encryptor/protect.py" protect-exe
            --stub   "${CMAKE_CURRENT_BINARY_DIR}/stub"
            --main   "${CMAKE_CURRENT_BINARY_DIR}/proc_b"
            --key    "${_TD_SMB}/test.key"
            --daemon-libs
            --output "${_TD_SMB}/proc_b.protected"
    COMMAND "${_TD_SMB}/proc_a.protected"
    COMMAND "${_TD_SMB}/proc_b.protected"
    DEPENDS stub script_multi_libs proc_a proc_b
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "A(common+A_only) and B(common+B_only) via daemon"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_lib_daemon — centralized lib daemon serves libs to client exes
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_lib_daemon
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_lib_daemon ==="
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/lib_daemon/run_test.sh"
            "${CMAKE_CURRENT_BINARY_DIR}/stub"
            "${CMAKE_CURRENT_BINARY_DIR}/dlopen_main"
            "${CMAKE_CURRENT_BINARY_DIR}/linked_main"
            "${CMAKE_CURRENT_BINARY_DIR}/mylib.so"
            "${CMAKE_CURRENT_BINARY_DIR}/liblinkedmath.so"
    DEPENDS stub mylib liblinkedmath dlopen_main linked_main
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "lib daemon mode test (dlopen + DT_NEEDED via daemon)"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_python_client_daemon — antirev_client.py speaks daemon protocol v2
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_python_client_daemon
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_python_client_daemon ==="
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/python_client_daemon/run_test.sh"
            "${CMAKE_CURRENT_BINARY_DIR}/stub"
            "${CMAKE_CURRENT_BINARY_DIR}/mylib.so"
            "${CMAKE_CURRENT_BINARY_DIR}/liblinkedmath.so"
    DEPENDS stub mylib liblinkedmath
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Python antirev_client v2 protocol handshake test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_python_reload — antirev_client.py must not pin the root lib's
#  refcount on on-demand ctypes loads.  Loads libreload.so twice via
#  ctypes.CDLL with an explicit dlclose in between and counts ctor
#  runs; guards the libprotobuf "File already exists in database"
#  class of failures that triggered the fix.
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_python_reload
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_python_reload ==="
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/python_reload/run_test.sh"
            "${CMAKE_CURRENT_BINARY_DIR}/stub"
            "${CMAKE_CURRENT_BINARY_DIR}/libreload.so"
    DEPENDS stub libreload
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "antirev_client ctypes reload test (don't pin the root lib)"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_missing_syms — missing_syms.py finds missing DT_NEEDED edges
#  and circular dependencies in a synthetic lib graph
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_missing_syms
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_missing_syms ==="
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/missing_syms/run_test.sh"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "missing_syms.py: missing DT_NEEDED + circular deps test"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  test_dlsym_intercept — dlsym_intercept.so + symdiff.py detect a dlsym
#  ownership flip (produced by load-order change) and ignore a stable
#  specific-handle lookup.  Covers the blind spot LD_DEBUG=bindings has:
#  runtime dlsym() resolution is not a relocation, so only an interceptor
#  can surface an ownership change under memfd+daemon loading.
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(test_dlsym_intercept
    COMMAND ${CMAKE_COMMAND} -E echo "=== test_dlsym_intercept ==="
    COMMAND ${CMAKE_COMMAND} -E env "CC=${X86_GCC}"
            bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/symcheck/test_symcheck.sh"
            "${CMAKE_CURRENT_BINARY_DIR}/symcheck_work"
            "${CMAKE_CURRENT_SOURCE_DIR}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "dlsym interceptor + symdiff: detect a dlsym ownership flip"
    USES_TERMINAL
)

# ═══════════════════════════════════════════════════════════════════════
#  run_tests — runs all tests and prints a summary
# ═══════════════════════════════════════════════════════════════════════

add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND}
            "-DBUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DSRC_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_all_tests.cmake"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Running all tests"
    USES_TERMINAL
)

endif()  # X86_GCC (x86-64 specific tests)
