# pad_bin.cmake
# Pads an extracted shellcode blob from SizeOfRawData up to VirtualSize,
# so it also covers the uninitialized data that the payload uses at runtime.

if(NOT LLVM_READOBJ)
    message(FATAL_ERROR "LLVM_READOBJ not specified")
endif()

if(NOT LLVM_OBJCOPY)
    message(FATAL_ERROR "LLVM_OBJCOPY not specified")
endif()

if(NOT PE_FILE)
    message(FATAL_ERROR "PE_FILE not specified")
endif()

if(NOT BIN_FILE)
    message(FATAL_ERROR "BIN_FILE not specified")
endif()

execute_process(
    COMMAND "${LLVM_READOBJ}" --sections "${PE_FILE}"
    OUTPUT_VARIABLE SECTIONS_OUTPUT
    ERROR_VARIABLE SECTIONS_ERROR
    RESULT_VARIABLE SECTIONS_RESULT
)

if(NOT SECTIONS_RESULT EQUAL 0)
    message(FATAL_ERROR "llvm-readobj --sections failed: ${SECTIONS_ERROR}")
endif()

if(NOT SECTIONS_OUTPUT MATCHES "Name: \\.text \\([^\n]*\n[ \t]*VirtualSize: (0x[0-9a-fA-F]+)")
    message(FATAL_ERROR "Could not find .text VirtualSize in llvm-readobj output")
endif()

math(EXPR IMAGE_SIZE "${CMAKE_MATCH_1}")

# `--pad-to` only works on binary output, so the dumped blob is re-read as
# binary input. It never truncates, so the size check below still catches a
# blob larger than the image.
execute_process(
    COMMAND "${LLVM_OBJCOPY}" -I binary -O binary --pad-to=${IMAGE_SIZE}
            "${BIN_FILE}" "${BIN_FILE}.padded"
    ERROR_VARIABLE OBJCOPY_ERROR
    RESULT_VARIABLE OBJCOPY_RESULT
)

if(NOT OBJCOPY_RESULT EQUAL 0)
    message(FATAL_ERROR "llvm-objcopy --pad-to failed: ${OBJCOPY_ERROR}")
endif()

file(RENAME "${BIN_FILE}.padded" "${BIN_FILE}")
file(SIZE "${BIN_FILE}" BIN_SIZE)

if(NOT BIN_SIZE EQUAL IMAGE_SIZE)
    message(FATAL_ERROR
        "Extracted shellcode does not cover the runtime image:\n"
        "  ${BIN_FILE}: ${BIN_SIZE} bytes\n"
        "  .text VirtualSize: ${IMAGE_SIZE} bytes\n")
endif()

message(STATUS "Shellcode covers runtime image: ${BIN_SIZE} bytes")
