# CMake toolchain file for cross-compiling to x86_64-linux-musl using zig cc
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=path/to/x86_64-linux-musl.cmake ...

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Get the directory of this toolchain file
get_filename_component(_CROSS_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)

# Compiler wrappers
set(CMAKE_C_COMPILER "${_CROSS_DIR}/zig-cc-x86_64-linux")
set(CMAKE_CXX_COMPILER "${_CROSS_DIR}/zig-cxx-x86_64-linux")
set(CMAKE_AR "${_CROSS_DIR}/zig-ar-x86_64-linux")
set(CMAKE_RANLIB "${_CROSS_DIR}/zig-ranlib-x86_64-linux")

# Static linking flags
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-static")

# Cross-compilation sysroot for finding our pre-built dependencies
set(CROSS_SYSROOT "${_CROSS_DIR}/../../_cross_sysroot")
get_filename_component(CROSS_SYSROOT "${CROSS_SYSROOT}" ABSOLUTE)

set(CMAKE_FIND_ROOT_PATH "${CROSS_SYSROOT}")
set(CMAKE_PREFIX_PATH "${CROSS_SYSROOT}")

# Search for programs on the host, libraries/headers in the sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Tell pkg-config to look in sysroot
set(ENV{PKG_CONFIG_PATH} "${CROSS_SYSROOT}/lib/pkgconfig")
set(ENV{PKG_CONFIG_LIBDIR} "${CROSS_SYSROOT}/lib/pkgconfig")
set(ENV{PKG_CONFIG_SYSROOT_DIR} "${CROSS_SYSROOT}")
