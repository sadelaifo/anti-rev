cmake_minimum_required(VERSION 3.16)
# Umbrella for the three sibling designs, each self-contained in its own folder
# with its own CMakeLists.txt:
#   daemon-shim/  stub + LD_PRELOAD shim + daemon + python client   (native C build)
#   kmod2/        vcachefs kernel module + tools                    (wraps kbuild make)
#   fusefs/       userspace FUSE decrypt daemon                     (wraps make)
# shared/ holds cross-design code (protect.py crypto container, obfstr_gen.py) and
# has no build of its own.
#
# Each design can also be built standalone (cmake from inside its folder).  Here
# only daemon-shim builds by default — kmod2 needs kernel headers and fusefs needs
# libfuse3/openssl, so they are opt-in.
project(antirev_suite NONE)

option(BUILD_DAEMON_SHIM "build the stub/shim/daemon design" ON)
option(BUILD_KMOD2       "build the kmod2 kernel module + tools (needs kernel-devel)" OFF)
option(BUILD_FUSEFS      "build the fusefs userspace daemon (needs libfuse3/openssl)" OFF)

if(BUILD_DAEMON_SHIM)
    add_subdirectory(daemon-shim)
endif()
if(BUILD_KMOD2)
    add_subdirectory(kmod2)
endif()
if(BUILD_FUSEFS)
    add_subdirectory(fusefs)
endif()
