# verify_pe.cmake
# Build-time verification of PE section layout.
# Accepts .text only, or .text + .rdata (debug/export info kept out of shellcode).

if(NOT LLVM_READOBJ)
    message(FATAL_ERROR "LLVM_READOBJ not specified")
endif()

if(NOT PE_FILE)
    message(FATAL_ERROR "PE_FILE not specified")
endif()

if(NOT EXISTS "${PE_FILE}")
    message(FATAL_ERROR "PE file not found: ${PE_FILE}")
endif()

# Run llvm-readobj to get file headers
execute_process(
    COMMAND ${LLVM_READOBJ} --file-headers ${PE_FILE}
    OUTPUT_VARIABLE HEADERS_OUTPUT
    ERROR_VARIABLE READOBJ_ERROR
    RESULT_VARIABLE READOBJ_RESULT
)

if(NOT READOBJ_RESULT EQUAL 0)
    message(FATAL_ERROR "llvm-readobj failed: ${READOBJ_ERROR}")
endif()

# Extract SectionCount from output
string(REGEX MATCH "SectionCount: ([0-9]+)" MATCH_RESULT "${HEADERS_OUTPUT}")
if(NOT MATCH_RESULT)
    message(FATAL_ERROR "Could not find SectionCount in llvm-readobj output")
endif()

set(SECTION_COUNT "${CMAKE_MATCH_1}")

if(SECTION_COUNT EQUAL 1)
    message(STATUS "PE verification PASSED: 1 section (.text)")
elseif(SECTION_COUNT EQUAL 2)
    # Get section details to verify .rdata is the second section
    execute_process(
        COMMAND ${LLVM_READOBJ} --sections ${PE_FILE}
        OUTPUT_VARIABLE SECTIONS_OUTPUT
    )
    # Check that we have .text and .rdata (debug/export info stays in .rdata, not in .bin)
    string(FIND "${SECTIONS_OUTPUT}" "Name: .text" HAS_TEXT)
    string(FIND "${SECTIONS_OUTPUT}" "Name: .rdata" HAS_RDATA)
    if(HAS_TEXT EQUAL -1 OR HAS_RDATA EQUAL -1)
        string(REGEX MATCHALL "Name: ([^\n]+)" SECTION_NAMES "${SECTIONS_OUTPUT}")
        message(FATAL_ERROR
            "PE verification FAILED!\n"
            "Expected .text and .rdata sections, found: ${SECTION_NAMES}\n"
            "File: ${PE_FILE}"
        )
    endif()
    message(STATUS "PE verification PASSED: 2 sections (.text + .rdata)")
else()
    # Get section details for error message
    execute_process(
        COMMAND ${LLVM_READOBJ} --sections ${PE_FILE}
        OUTPUT_VARIABLE SECTIONS_OUTPUT
    )
    # Extract section names
    string(REGEX MATCHALL "Name: ([^\n]+)" SECTION_NAMES "${SECTIONS_OUTPUT}")
    message(FATAL_ERROR
        "PE verification FAILED!\n"
        "Expected 1-2 sections, found ${SECTION_COUNT}.\n"
        "Sections found: ${SECTION_NAMES}\n"
        "This indicates data sections were not properly merged into .text.\n"
        "Check linker flags: /MERGE:...\n"
        "File: ${PE_FILE}"
    )
endif()
