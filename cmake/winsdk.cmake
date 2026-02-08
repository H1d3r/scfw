# Windows SDK and phnt paths
#
# Options:
#   SCFW_FETCH_WINSDK           - download Windows SDK + CRT via xwin if not found (default: OFF)
#
# Sets:
#   SCFW_WINSDK_INCLUDE_DIRS    - include directories for Windows SDK headers + phnt
#   SCFW_WINSDK_LIB_DIRS        - library directories for CRT and SDK libs (xwin only)
#   SCFW_WINSDK_COMPILE_OPTIONS - warning suppressions for SDK/phnt headers

# Fetch phnt (Windows native API headers)
include(FetchContent)
FetchContent_Declare(
    phnt
    GIT_REPOSITORY https://github.com/winsiderss/phnt.git
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(phnt)

set(SCFW_WINSDK_INCLUDE_DIRS
    ${phnt_SOURCE_DIR}
)

set(SCFW_WINSDK_LIB_DIRS)

cmake_path(SET _winsdk_dir NORMALIZE "${CMAKE_CURRENT_LIST_DIR}/../winsdk")

option(SCFW_FETCH_WINSDK "Automatically fetch Windows SDK via xwin" OFF)

# On Windows, check if the compiler can find SDK headers natively (e.g., MSVC installed).
# On other hosts there is never a system Windows SDK, so skip the check entirely.
set(_SCFW_HAVE_SYSTEM_WINSDK FALSE)
if(CMAKE_HOST_WIN32)
    include(CheckIncludeFile)
    set(CMAKE_REQUIRED_QUIET TRUE)
    check_include_file(windows.h _SCFW_HAVE_SYSTEM_WINSDK)
endif()

if(NOT _SCFW_HAVE_SYSTEM_WINSDK AND NOT EXISTS "${_winsdk_dir}/sdk")
    if(SCFW_FETCH_WINSDK)
        set(_fetch_scripts_dir "${CMAKE_CURRENT_LIST_DIR}/../scripts")
        if(CMAKE_HOST_WIN32)
            message(STATUS "Windows SDK not found, running fetch-winsdk.ps1...")
            execute_process(
                COMMAND powershell -ExecutionPolicy Bypass -File
                    "${_fetch_scripts_dir}/fetch-winsdk.ps1"
                    -Output "${_winsdk_dir}"
                RESULT_VARIABLE _fetch_result
            )
        else()
            message(STATUS "Windows SDK not found, running fetch-winsdk.sh...")
            execute_process(
                COMMAND bash "${_fetch_scripts_dir}/fetch-winsdk.sh"
                    --output "${_winsdk_dir}"
                RESULT_VARIABLE _fetch_result
            )
        endif()
        if(NOT _fetch_result EQUAL 0)
            message(FATAL_ERROR "Failed to fetch Windows SDK")
        endif()
    else()
        message(STATUS "Windows SDK not found. To fetch automatically, re-run with -DSCFW_FETCH_WINSDK=ON")
        message(STATUS "  This uses xwin to download the SDK headers and libraries into ${_winsdk_dir}/.")
        message(STATUS "  If cargo is not installed, a temporary Rust toolchain is downloaded and removed after use.")
    endif()
endif()

if(EXISTS "${_winsdk_dir}")
    list(APPEND SCFW_WINSDK_INCLUDE_DIRS
        ${_winsdk_dir}/crt/include
        ${_winsdk_dir}/sdk/include/ucrt
        ${_winsdk_dir}/sdk/include/shared
        ${_winsdk_dir}/sdk/include/um
    )

    # Map architecture to xwin lib subdirectory
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
        set(_winsdk_arch "x86_64")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "X86")
        set(_winsdk_arch "x86")
    endif()

    if(_winsdk_arch AND EXISTS "${_winsdk_dir}/crt/lib/${_winsdk_arch}")
        set(SCFW_WINSDK_LIB_DIRS
            ${_winsdk_dir}/crt/lib/${_winsdk_arch}
            ${_winsdk_dir}/sdk/lib/um/${_winsdk_arch}
            ${_winsdk_dir}/sdk/lib/ucrt/${_winsdk_arch}
        )
    endif()
endif()

# Suppress harmless SDK/phnt header warnings when cross-compiling with Clang:
#   pragma-pack:                  SDK uses pshpack/poppack for struct packing (MSVC convention)
#   nonportable-include-path:     Case mismatch (Windows SDK built on case-insensitive FS)
#   ignored-pragma-intrinsic:     MSVC intrinsics Clang doesn't recognize
#   microsoft-enum-forward-reference: Forward enum decls (MS extension, supported)
#   microsoft-anon-tag:           Anonymous structs (MS extension, supported)
#   ignored-attributes:           stdcall on variadic function in phnt (compiler ignores it)
set(SCFW_WINSDK_COMPILE_OPTIONS
    -Wno-pragma-pack
    -Wno-nonportable-include-path
    -Wno-ignored-pragma-intrinsic
    -Wno-microsoft-enum-forward-reference
    -Wno-microsoft-anon-tag
    -Wno-ignored-attributes
)
