if(NOT DEFINED BIN_FILE)
    message(FATAL_ERROR "BIN_FILE not specified")
endif()

if(NOT EXISTS "${BIN_FILE}")
    message(FATAL_ERROR "Binary file not found: ${BIN_FILE}")
endif()

file(SIZE "${BIN_FILE}" SIZE_BYTES)
message(STATUS "Shellcode size: ${SIZE_BYTES} bytes")
