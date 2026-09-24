cmake_minimum_required(VERSION 3.13)
# NONE: fusefs builds with a plain Makefile (libfuse3 + openssl via pkg-config);
# CMake wraps it rather than reimplementing the build.
project(fusefs NONE)

# -DFUSEFS_STATIC=ON builds a static vcachefsd for shipping inside an image.
# -DFUSEFS_KEYFILE=/path/key.hex bakes that AES-256 key into the binary (see below).
option(FUSEFS_STATIC "build a static vcachefsd (make static)" OFF)
set(FUSEFS_KEYFILE "" CACHE STRING "hex keyfile whose AES-256 key is baked into vcachefsd (blank = keep the checked-in placeholder src/key_blob.c)")
set(_tgt all)
if(FUSEFS_STATIC)
    set(_tgt static)
endif()

# key-in-binary: with -DFUSEFS_KEYFILE set, regenerate src/key_blob.c (the
# obfuscated master key) from that keyfile before building.  Blank keeps the
# checked-in placeholder (daemon builds but decrypt returns -ENOKEY: fail-safe).
if(FUSEFS_KEYFILE)
    add_custom_target(fusefs_key
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/../shared/gen_key_blob.py"
                "${FUSEFS_KEYFILE}" "${CMAKE_CURRENT_SOURCE_DIR}/src/key_blob.c"
        COMMENT "Embedding master key from ${FUSEFS_KEYFILE} into src/key_blob.c"
        VERBATIM)
endif()

add_custom_target(fusefs_daemon ALL
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}" ${_tgt}
    COMMENT "Building vcachefsd (FUSE decrypt daemon)"
    VERBATIM USES_TERMINAL)
if(FUSEFS_KEYFILE)
    add_dependencies(fusefs_daemon fusefs_key)
endif()

add_custom_target(fusefs_clean
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}" clean
    COMMENT "Cleaning fusefs build outputs"
    VERBATIM)
