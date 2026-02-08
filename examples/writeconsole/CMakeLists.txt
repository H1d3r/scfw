add_executable(writeconsole main.cpp)
target_link_libraries(writeconsole PRIVATE scfw)
scfw_extract_shellcode(writeconsole)
