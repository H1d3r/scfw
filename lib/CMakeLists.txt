# Select assembly sources based on target architecture
get_property(_cleanup GLOBAL PROPERTY SCFW_OPT_CLEANUP)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "X86")
    set(ASM_SOURCES src/arch/x86/init.S)
    if(_cleanup)
        list(APPEND ASM_SOURCES src/arch/x86/start.S)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    set(ASM_SOURCES src/arch/x64/init.S)
    if(_cleanup)
        list(APPEND ASM_SOURCES src/arch/x64/start.S)
    endif()
else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

add_library(scfw STATIC
    ${ASM_SOURCES}
    src/crt0.c
)

# Include paths: our headers, then phnt, then SDK
target_include_directories(scfw PUBLIC
    include
    ${SCFW_WINSDK_INCLUDE_DIRS}
)
target_compile_options(scfw PUBLIC ${SCFW_COMPILE_FLAGS})

if(_cleanup)
    target_compile_definitions(scfw PUBLIC SCFW_ENABLE_CLEANUP)
endif()

# Link options propagate to consumers
# Note: /MERGE appends sections to the end, preserving .text$* ordering
target_link_options(scfw INTERFACE
    ${SCFW_LINK_FLAGS}
    -Wl,/ENTRY:_init
    -Wl,/SUBSYSTEM:CONSOLE
    -Wl,/NODEFAULTLIB
    -Wl,/OPT:REF
    -Wl,/MERGE:.data=.text
    -Wl,/MERGE:.rdata=.text
    -Xlinker /SECTION:.text,RWE
)

# x86-specific linker options
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "X86")
    target_link_options(scfw INTERFACE
        -Wl,/SAFESEH:NO     # Assembly files lack SEH metadata
        -Wl,/FIXED          # No base relocations - safe because PIC code only uses
                            # address DIFFERENCES which are base-independent
    )

    # Setting /BASE:0 makes shellcode offsets match raw file offsets, which is
    # nice for analysis. However, it makes the .exe non-executable and doesn't
    # actually reduce shellcode size (x86 imm32 is always 4 bytes regardless
    # of the value).
    if(SCFW_OPT_ZERO_BASE)
        target_link_options(scfw INTERFACE -Wl,/BASE:0)
    endif()
endif()

# Assembly compile flags
set(_asm_flags "-masm=intel")

if(_cleanup)
    string(APPEND _asm_flags " -DSCFW_ENABLE_CLEANUP")
endif()

# Function alignment for assembly (convert bytes to p2align power)
get_property(_fn_align GLOBAL PROPERTY SCFW_FUNCTION_ALIGNMENT)
if(_fn_align GREATER 0)
    # Compute log2 of alignment value for .p2align directive
    math(EXPR _p2align "0")
    set(_temp ${_fn_align})
    while(_temp GREATER 1)
        math(EXPR _temp "${_temp} / 2")
        math(EXPR _p2align "${_p2align} + 1")
    endwhile()
    string(APPEND _asm_flags " -DSCFW_P2ALIGN=${_p2align}")
endif()

set_source_files_properties(${ASM_SOURCES} PROPERTIES
    COMPILE_FLAGS "${_asm_flags}"
)
