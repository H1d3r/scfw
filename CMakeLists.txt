cmake_minimum_required(VERSION 3.22)
project(scfw C CXX ASM)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "This project requires Clang or AppleClang")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(cmake/scfw.cmake)
add_subdirectory(lib)
add_subdirectory(examples)
add_subdirectory(tools)
