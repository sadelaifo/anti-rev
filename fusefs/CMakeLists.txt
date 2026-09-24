cmake_minimum_required(VERSION 3.13)
# NONE: fusefs builds with a plain Makefile (libfuse3 + openssl via pkg-config);
# CMake wraps it rather than reimplementing the build.
project(fusefs NONE)

# -DFUSEFS_STATIC=ON builds a static vcachefsd for shipping inside an image.
option(FUSEFS_STATIC "build a static vcachefsd (make static)" OFF)
set(_tgt all)
if(FUSEFS_STATIC)
    set(_tgt static)
endif()

add_custom_target(fusefs_daemon ALL
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}" ${_tgt}
    COMMENT "Building vcachefsd (FUSE decrypt daemon)"
    VERBATIM USES_TERMINAL)

add_custom_target(fusefs_clean
    COMMAND make -C "${CMAKE_CURRENT_SOURCE_DIR}" clean
    COMMENT "Cleaning fusefs build outputs"
    VERBATIM)
