# Unified toolchain for cross-compiling shellcode to Windows
# Usage: cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain.cmake -DSCFW_TARGET=x64

set(CMAKE_SYSTEM_NAME Generic)

# Target architecture (x64 or x86)
if(NOT DEFINED SCFW_TARGET)
    set(SCFW_TARGET "x64" CACHE STRING "Target: x64 or x86")
endif()

if(SCFW_TARGET STREQUAL "x64")
    set(CMAKE_SYSTEM_PROCESSOR AMD64)
    set(SCFW_TRIPLE x86_64-pc-windows-msvc)
elseif(SCFW_TARGET STREQUAL "x86")
    set(CMAKE_SYSTEM_PROCESSOR X86)
    set(SCFW_TRIPLE i686-pc-windows-msvc)
else()
    message(FATAL_ERROR "SCFW_TARGET must be x64 or x86, got: ${SCFW_TARGET}")
endif()

# Load shared LLVM search paths
include(${CMAKE_CURRENT_LIST_DIR}/llvm_paths.cmake)

# Find clang - check common locations
if(NOT CMAKE_C_COMPILER)
    find_program(CLANG_C clang
        PATHS ${SCFW_LLVM_SEARCH_PATHS}
        NO_DEFAULT_PATH
    )
    if(NOT CLANG_C)
        find_program(CLANG_C clang)
    endif()
    if(CLANG_C)
        set(CMAKE_C_COMPILER "${CLANG_C}")
    endif()
endif()

if(NOT CMAKE_CXX_COMPILER)
    find_program(CLANG_CXX clang++
        PATHS ${SCFW_LLVM_SEARCH_PATHS}
        NO_DEFAULT_PATH
    )
    if(NOT CLANG_CXX)
        find_program(CLANG_CXX clang++)
    endif()
    if(CLANG_CXX)
        set(CMAKE_CXX_COMPILER "${CLANG_CXX}")
    endif()
endif()

# ASM uses C compiler
if(NOT CMAKE_ASM_COMPILER AND CMAKE_C_COMPILER)
    set(CMAKE_ASM_COMPILER "${CMAKE_C_COMPILER}")
endif()

# Set target triples
set(CMAKE_C_COMPILER_TARGET ${SCFW_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${SCFW_TRIPLE})
set(CMAKE_ASM_COMPILER_TARGET ${SCFW_TRIPLE})

# Disable macOS-specific settings (only on macOS)
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
    set(CMAKE_OSX_ARCHITECTURES "")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "")
    set(CMAKE_OSX_SYSROOT "")
endif()

# Skip compiler checks for cross-compilation
set(CMAKE_C_COMPILER_WORKS TRUE)
set(CMAKE_CXX_COMPILER_WORKS TRUE)
set(CMAKE_ASM_COMPILER_WORKS TRUE)
